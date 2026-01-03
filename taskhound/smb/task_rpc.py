"""
Task Scheduler RPC client for credential validation.

Uses MS-TSCH protocol to query task execution history and determine
if stored credentials are valid based on return codes.

Requires RPC_C_AUTHN_LEVEL_PKT_PRIVACY authentication level.

CREDENTIAL CONFIDENCE HEURISTICS
================================
Since Windows Task Scheduler does NOT record authentication failures in
LastRunInfo, we use multiple data sources to estimate credential validity:

1. DEFINITELY_STALE: pwdLastSet > LastRunTime
   - Password was changed AFTER the last successful run
   - The stored credentials are guaranteed to be wrong

2. HIGH_CONFIDENCE_VALID: pwdLastSet < task_creation_date
   - Password has not changed since the task was created
   - If task ever ran successfully, credentials are still valid

3. CONFIRMED_VALID: pwdLastSet > task_creation_date AND LastRunTime is recent
   - Password was changed after task creation, BUT task ran successfully
     within its expected schedule - someone updated the task credentials

4. LIKELY_VALID: Valid return code + recent LastRunTime (within 2x trigger interval)
   - Task ran successfully recently, probably still valid

5. POSSIBLY_STALE: Valid return code + old LastRunTime (outside expected schedule)
   - Task shows success but hasn't run when it should have
   - May indicate silent auth failures (credentials became stale)

6. UNKNOWN: Task has never run successfully
   - Could be new task, disabled, or wrong credentials from the start
"""

import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from impacket.dcerpc.v5 import transport, tsch
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from taskhound.utils.logging import debug as log_debug
from taskhound.utils.logging import warn


class CredentialStatus(Enum):
    """
    Credential validation status based on task return codes.

    IMPORTANT: Due to Windows Task Scheduler behavior, authentication failures
    (wrong password, user not found) are NOT recorded as task runs. This means
    INVALID status may never appear in practice - failed auth attempts result
    in UNKNOWN status (indistinguishable from "task never ran").

    Only VALID and VALID_RESTRICTED statuses reliably indicate password correctness.
    """

    VALID = "valid"  # Password correct, task ran successfully
    VALID_RESTRICTED = "valid_restricted"  # Password correct, but account restricted
    INVALID = "invalid"  # Wrong password or user not found (rarely seen in practice)
    BLOCKED = "blocked"  # Account disabled/locked/expired (may appear if blocked after a run)
    UNKNOWN = "unknown"  # Task never ran OR auth failed - cannot distinguish


class CredentialConfidence(Enum):
    """
    Confidence level for credential validity assessment.

    Combines return code analysis with AD metadata (pwdLastSet) and
    schedule analysis to provide a more accurate assessment.

    Ordered from most certain to least certain.
    """

    # Definitive states (high certainty)
    DEFINITELY_STALE = "definitely_stale"      # pwdLastSet > LastRunTime - password changed after last run
    HIGH_CONFIDENCE_VALID = "high_confidence"  # pwdLastSet < task_creation_date - password unchanged
    CONFIRMED_VALID = "confirmed_valid"        # pwdLastSet > task_creation but task ran recently

    # Probable states (medium certainty)
    LIKELY_VALID = "likely_valid"              # Task ran recently within schedule
    POSSIBLY_STALE = "possibly_stale"          # Task should have run but LastRunTime is old

    # Indeterminate states
    UNKNOWN = "unknown"                        # Cannot determine (never ran, blocked, etc.)


@dataclass
class CredentialContext:
    """
    Additional context for credential confidence calculation.

    These values come from AD/LDAP and task XML parsing, and are used
    to improve confidence assessment beyond just the return code.
    """

    # From AD/LDAP - when the user's password was last changed
    pwd_last_set: Optional[datetime] = None

    # From task XML - when the task was created/registered
    task_creation_date: Optional[datetime] = None

    # From task XML - expected run interval in days (e.g., 1 for daily, 7 for weekly)
    trigger_interval_days: Optional[int] = None

    # Current time for staleness calculation (injectable for testing)
    current_time: Optional[datetime] = field(default_factory=datetime.now)


@dataclass
class TaskRunInfo:
    """Information about a task's last execution and credential validation."""

    task_path: str
    last_run: Optional[datetime]
    return_code: int
    credential_status: CredentialStatus
    status_detail: str
    password_valid: bool  # Key field for DPAPI feasibility
    task_hijackable: bool  # Can we use this for execution?

    # Confidence assessment (populated by calculate_confidence())
    confidence: CredentialConfidence = CredentialConfidence.UNKNOWN
    confidence_reason: str = ""


def calculate_confidence(
    run_info: TaskRunInfo,
    context: Optional[CredentialContext] = None,
) -> tuple[CredentialConfidence, str]:
    """
    Calculate credential confidence based on multiple heuristics.

    Combines the basic return code status with AD metadata and schedule
    analysis to provide a more accurate confidence level.

    Args:
        run_info: Task run information from RPC query
        context: Additional context (pwdLastSet, task creation date, trigger interval)

    Returns:
        Tuple of (confidence_level, human_readable_reason)

    Heuristics applied in order:
    1. If task never ran or is blocked -> UNKNOWN
    2. If pwdLastSet > LastRunTime -> DEFINITELY_STALE
    3. If pwdLastSet < task_creation_date -> HIGH_CONFIDENCE_VALID
    4. If pwdLastSet > task_creation_date AND LastRunTime is recent -> CONFIRMED_VALID
    5. If LastRunTime is within expected schedule -> LIKELY_VALID
    6. If LastRunTime is older than expected -> POSSIBLY_STALE
    """
    # No run info or task never ran - can't determine
    if run_info.last_run is None:
        return (CredentialConfidence.UNKNOWN, "Task has never run successfully")

    # Blocked accounts - password status unknown
    if run_info.credential_status == CredentialStatus.BLOCKED:
        return (CredentialConfidence.UNKNOWN, f"Account blocked: {run_info.status_detail}")

    # Invalid credentials (rare - usually not recorded)
    if run_info.credential_status == CredentialStatus.INVALID:
        return (CredentialConfidence.DEFINITELY_STALE, f"Invalid credentials: {run_info.status_detail}")

    # From here on, we have a successful run (VALID or VALID_RESTRICTED)
    # Apply heuristics based on available context

    if context is None:
        # No additional context - basic assessment only
        return (CredentialConfidence.LIKELY_VALID, "Task ran successfully (no AD context available)")

    now = context.current_time or datetime.now()

    # HEURISTIC 1: pwdLastSet > LastRunTime -> DEFINITELY_STALE
    # Password was changed AFTER the last successful run
    if context.pwd_last_set and context.pwd_last_set > run_info.last_run:
        days_since_pwd_change = (now - context.pwd_last_set).days
        return (
            CredentialConfidence.DEFINITELY_STALE,
            f"Password changed {days_since_pwd_change}d ago (after last successful run on {run_info.last_run.strftime('%Y-%m-%d')})"
        )

    # HEURISTIC 2: pwdLastSet < task_creation_date -> HIGH_CONFIDENCE_VALID
    # Password has not changed since the task was created
    if context.pwd_last_set and context.task_creation_date:
        if context.pwd_last_set < context.task_creation_date:
            return (
                CredentialConfidence.HIGH_CONFIDENCE_VALID,
                f"Password unchanged since task creation (pwdLastSet: {context.pwd_last_set.strftime('%Y-%m-%d')}, task created: {context.task_creation_date.strftime('%Y-%m-%d')})"
            )

    # HEURISTIC 3: pwdLastSet > task_creation_date BUT task ran successfully within schedule
    # This means someone updated the task credentials after the password change!
    if context.pwd_last_set and context.task_creation_date and context.trigger_interval_days:
        if context.pwd_last_set > context.task_creation_date:
            # Password was changed after task creation - check if task still runs
            expected_interval = timedelta(days=context.trigger_interval_days)
            # Allow 2x the interval as grace period (task may not run exactly on schedule)
            grace_period = expected_interval * 2
            time_since_last_run = now - run_info.last_run

            if time_since_last_run <= grace_period:
                return (
                    CredentialConfidence.CONFIRMED_VALID,
                    f"Password changed after task creation, but task ran successfully within schedule ({run_info.last_run.strftime('%Y-%m-%d %H:%M')})"
                )

    # HEURISTIC 4 & 5: Schedule-based staleness detection
    if context.trigger_interval_days:
        expected_interval = timedelta(days=context.trigger_interval_days)
        grace_period = expected_interval * 2  # Allow 2x interval before flagging
        time_since_last_run = now - run_info.last_run

        if time_since_last_run <= grace_period:
            return (
                CredentialConfidence.LIKELY_VALID,
                f"Task ran {time_since_last_run.days}d ago (within {context.trigger_interval_days}d schedule)"
            )
        else:
            missed_runs = int(time_since_last_run / expected_interval)
            return (
                CredentialConfidence.POSSIBLY_STALE,
                f"Task should run every {context.trigger_interval_days}d but last ran {time_since_last_run.days}d ago (~{missed_runs} missed runs)"
            )

    # Fallback: We have pwdLastSet but no schedule info
    if context.pwd_last_set:
        # pwdLastSet <= LastRunTime means password hasn't changed since last run
        if context.pwd_last_set <= run_info.last_run:
            return (
                CredentialConfidence.LIKELY_VALID,
                f"Password unchanged since last successful run ({run_info.last_run.strftime('%Y-%m-%d')})"
            )

    # No useful context available
    days_since_run = (now - run_info.last_run).days
    return (
        CredentialConfidence.LIKELY_VALID if days_since_run < 30 else CredentialConfidence.POSSIBLY_STALE,
        f"Task last ran {days_since_run}d ago (limited context available)"
    )


def enrich_with_confidence(
    run_info: TaskRunInfo,
    context: Optional[CredentialContext] = None,
) -> TaskRunInfo:
    """
    Calculate and set confidence on a TaskRunInfo object.

    Convenience function that calculates confidence and updates the
    TaskRunInfo in place, also returning it for method chaining.

    Args:
        run_info: Task run information to enrich
        context: Additional context for confidence calculation

    Returns:
        The same TaskRunInfo with confidence and confidence_reason set
    """
    confidence, reason = calculate_confidence(run_info, context)
    run_info.confidence = confidence
    run_info.confidence_reason = reason
    return run_info


# fmt: off
# =============================================================================
# CREDENTIAL VALIDATION RETURN CODES
# =============================================================================
#
# IMPORTANT WINDOWS LIMITATION (verified by testing):
# When Task Scheduler authentication fails (wrong password, user not found),
# Windows does NOT spawn a process and does NOT update LastRunInfo at all.
#
# The SchRpcGetLastRunInfo RPC call behavior:
# - If task has NEVER run successfully: returns 0x00041303 (SCHED_S_TASK_HAS_NOT_RUN)
# - If task HAS run successfully before: returns the LAST SUCCESSFUL run's info
#   (even after multiple auth failures, it keeps showing the old success!)
#
# Auth failures ARE logged in the Event Log (Event IDs 101, 104) with error
# 0x8007052E (ERROR_LOGON_FAILURE), but this is not accessible via MS-TSCH RPC.
#
# This means:
# - PASSWORD_VALID_CODES: Reliable - task ran, so credentials worked at that time
# - PASSWORD_INVALID_CODES: Will NEVER appear via SchRpcGetLastRunInfo
# - ACCOUNT_BLOCKED_CODES: May appear if account was blocked AFTER a successful run
# - UNKNOWN status: Could mean "never ran" OR "creds became stale after creation"
#
# Key insight: A task showing a successful LastRunInfo (e.g., 0x0) with an old
# LastRunTime may have stale credentials - we can only confirm validity by
# checking if the LastRunTime is recent enough.
# =============================================================================

# Return codes indicating PASSWORD IS CORRECT (DPAPI feasible)
PASSWORD_VALID_CODES: set[int] = {
    # Task executed successfully - credentials definitely work
    0x00000000,  # SUCCESS
    0x00000001,  # ERROR_INVALID_FUNCTION
    0x00000002,  # ERROR_FILE_NOT_FOUND
    0x00000005,  # ERROR_ACCESS_DENIED (command-level, NOT auth)
    0x0000007B,  # ERROR_INVALID_NAME
    0x000000C1,  # ERROR_BAD_EXE_FORMAT
    0x800700C1,  # ERROR_BAD_EXE_FORMAT (HRESULT)
    0x80070002,  # ERROR_FILE_NOT_FOUND (HRESULT)
    0x80070005,  # E_ACCESSDENIED (HRESULT, command-level)

    # Account restrictions - password IS correct, just can't batch logon
    # These prove the password because Windows validates it before checking rights
    0x80070569,  # ERROR_LOGON_TYPE_NOT_GRANTED (no "batch logon" right)
    0xC000015B,  # STATUS_LOGON_TYPE_NOT_GRANTED (NTSTATUS)
    0x800704C3,  # ERROR_LOGON_NOT_GRANTED
    0xC000006E,  # STATUS_ACCOUNT_RESTRICTION
    0x8007052F,  # ERROR_ACCOUNT_RESTRICTION (Win32 0x052F = 1327)
}

# Subset of PASSWORD_VALID_CODES: Task can actually run (hijackable)
TASK_RUNNABLE_CODES: set[int] = {
    0x00000000,  # SUCCESS
    0x00000001,  # ERROR_INVALID_FUNCTION
    0x00000002,  # ERROR_FILE_NOT_FOUND
    0x00000005,  # ERROR_ACCESS_DENIED
    0x0000007B,  # ERROR_INVALID_NAME
    0x000000C1,  # ERROR_BAD_EXE_FORMAT
    0x800700C1,  # ERROR_BAD_EXE_FORMAT (HRESULT)
    0x80070002,  # ERROR_FILE_NOT_FOUND (HRESULT)
    0x80070005,  # E_ACCESSDENIED (HRESULT)
}

# Password is WRONG or user doesn't exist
# NOTE: These codes are kept for completeness but may NEVER appear in practice.
# When authentication fails, Windows Task Scheduler does not record the attempt
# as a "run" - it simply returns 0x00041303 (task has not run).
PASSWORD_INVALID_CODES: set[int] = {
    0x8007052E,  # ERROR_LOGON_FAILURE - wrong password (Win32 0x052E = 1326)
    0xC000006D,  # STATUS_LOGON_FAILURE (NTSTATUS)
    0x80070525,  # ERROR_NO_SUCH_USER (Win32 0x0525 = 1317)
    0xC0000064,  # STATUS_NO_SUCH_USER (NTSTATUS)
    0x8004130F,  # SCHED_E_ACCOUNT_INFORMATION_NOT_SET
    0x80041310,  # SCHED_E_ACCOUNT_NAME_NOT_FOUND
}

# Account blocked - password status unknown (may have been correct)
ACCOUNT_BLOCKED_CODES: set[int] = {
    # Password expired
    0x8007056A,  # ERROR_PASSWORD_EXPIRED (Win32 0x056A = 1386)
    0xC0000071,  # STATUS_PASSWORD_EXPIRED (NTSTATUS)
    0x80070774,  # ERROR_PASSWORD_MUST_CHANGE (Win32 0x0774 = 1908)
    0xC0000224,  # STATUS_PASSWORD_MUST_CHANGE (NTSTATUS)
    # Account disabled/locked/expired
    0x80070533,  # ERROR_ACCOUNT_DISABLED (Win32 0x0533 = 1331)
    0xC0000072,  # STATUS_ACCOUNT_DISABLED (NTSTATUS)
    0x80070775,  # ERROR_ACCOUNT_LOCKED_OUT (Win32 0x0775 = 1909)
    0xC0000234,  # STATUS_ACCOUNT_LOCKED_OUT (NTSTATUS)
    0xC0000193,  # STATUS_ACCOUNT_EXPIRED (NTSTATUS)
    # Logon time/workstation restrictions
    0x80070530,  # ERROR_INVALID_LOGON_HOURS (Win32 0x0530 = 1328)
    0xC000006F,  # STATUS_INVALID_LOGON_HOURS (NTSTATUS)
    0x80070531,  # ERROR_INVALID_WORKSTATION (Win32 0x0531 = 1329)
    0xC0000070,  # STATUS_INVALID_WORKSTATION (NTSTATUS)
}

# Task Scheduler specific codes (SCHED_S_* and SCHED_E_*) not in impacket
# For Windows/NTSTATUS/HRESULT codes, we use impacket's built-in mappings
TASK_SCHEDULER_CODES: dict[int, str] = {
    0x00041300: "Task is ready to run",
    0x00041301: "Task is currently running",
    0x00041302: "Task is disabled",
    0x00041303: "Task not yet run",
    0x00041304: "No more runs scheduled",
    0x00041305: "Account info not set",
    0x00041306: "Task terminated",
    0x00041307: "No valid triggers",
    0x00041308: "Event triggers don't have set run times",
    0x00041309: "Trigger not found",
    0x0004130A: "Properties invalid",
    0x0004130B: "No account specified",
    0x0004130C: "Security context could not be set",
    0x0004130D: "Task registered, some triggers may fail",
    0x0004130E: "Task registered, may fail to start",
    0x0004130F: "Task is disabled",
    0x00041310: "Properties not compatible with earlier versions",
    0x00041311: "Cannot start on demand",
    0x8004130A: "Account name not found in store",
    0x8004130B: "XML values out of range",
    0x8004130C: "XML unexpected node",
    0x8004130D: "XML unexpected namespace",
    0x8004130E: "XML malformed",
    0x8004130F: "Account info not set",
    0x80041310: "Account name not found",
    0x80041311: "Account info not set (XML)",
    0x80041312: "Orphaned task (no security services)",
    0x80041313: "Cannot connect to security services",
    0x80041314: "Cannot get security descriptor",
    0x80041315: "Cannot query/set account info",
    0x80041316: "Cannot query/set password",
    0x80041317: "Not supported on platform",
    0x80041318: "Access denied (remote)",
    0x80041319: "Version mismatch",
    0x8004131A: "Task already running",
    0x8004131B: "Task not running",
    0x8004131C: "Task service not running",
    0x8004131D: "S4U + Interactive not supported",
    0x8004131E: "Network unavailable",
    0x8004131F: "S4U requires password",
    0x800710E0: "Operation refused",  # ERROR_REQUEST_REFUSED - common for protected users
}


def get_return_code_description(code: int) -> str:
    """
    Get human-readable description for a return code.

    Uses impacket's built-in error mappings for Windows/NTSTATUS/HRESULT codes,
    with Task Scheduler-specific codes handled separately.
    """
    from impacket import hresult_errors, nt_errors, system_errors

    # Check Task Scheduler specific codes first
    if code in TASK_SCHEDULER_CODES:
        return TASK_SCHEDULER_CODES[code]

    # Try NT errors (NTSTATUS - 0xC0xxxxxx)
    if code in nt_errors.ERROR_MESSAGES:
        name, _desc = nt_errors.ERROR_MESSAGES[code]
        return name

    # Try HRESULT errors
    if code in hresult_errors.ERROR_MESSAGES:
        name, _desc = hresult_errors.ERROR_MESSAGES[code]
        return name

    # Try system errors (Win32 - low codes)
    if code in system_errors.ERROR_MESSAGES:
        name, _desc = system_errors.ERROR_MESSAGES[code]
        return name

    # For HRESULT wrapping Win32 (0x8007xxxx), extract and lookup Win32 code
    if (code & 0xFFFF0000) == 0x80070000:
        win32_code = code & 0xFFFF
        if win32_code in system_errors.ERROR_MESSAGES:
            name, _desc = system_errors.ERROR_MESSAGES[win32_code]
            return name

    return f"Unknown (0x{code:08X})"


class TaskSchedulerRPC:
    """
    Task Scheduler RPC client for querying task execution history.

    Uses MS-TSCH protocol over named pipe \\pipe\\atsvc.
    Requires PKT_PRIVACY authentication level for access.
    """

    def __init__(
        self,
        target: str,
        domain: str,
        username: str,
        password: str,
        lm_hash: str = "",
        nt_hash: str = "",
        aes_key: str = "",
        kerberos: bool = False,
        dc_ip: str = "",
    ):
        """
        Initialize Task Scheduler RPC client.

        Args:
            target: Target hostname or IP
            domain: Domain name
            username: Username for authentication
            password: Password (or empty if using hash/aesKey)
            lm_hash: LM hash (optional)
            nt_hash: NT hash (optional)
            aes_key: Kerberos AES key (optional, 128 or 256-bit)
            kerberos: Use Kerberos authentication
            dc_ip: Domain Controller IP for KDC (optional)
        """
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aes_key = aes_key
        self.kerberos = kerberos
        self.dc_ip = dc_ip
        self._dce = None
        self._connection_lost = False

    def connect(self) -> bool:
        """
        Establish RPC connection to Task Scheduler service.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            binding = f"ncacn_np:{self.target}[\\pipe\\atsvc]"
            rpc_transport = transport.DCERPCTransportFactory(binding)
            rpc_transport.set_credentials(
                self.username,
                self.password,
                self.domain,
                self.lm_hash,
                self.nt_hash,
                self.aes_key,
            )

            # Enable Kerberos if requested (needed for AES key auth)
            if self.kerberos or self.aes_key:
                kdc_host = self.dc_ip or self.target
                rpc_transport.set_kerberos(True, kdcHost=kdc_host)
                log_debug(f"Using Kerberos authentication for RPC (KDC: {kdc_host})")

            self._dce = rpc_transport.get_dce_rpc()
            # PKT_PRIVACY is REQUIRED - lower auth levels get access denied
            self._dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            # For Kerberos, must set GSS_NEGOTIATE auth type BEFORE connect()
            if self.kerberos or self.aes_key:
                self._dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            self._dce.connect()
            self._dce.bind(tsch.MSRPC_UUID_TSCHS)
            self._connection_lost = False

            log_debug(f"Connected to Task Scheduler RPC on {self.target}")
            return True

        except Exception as e:
            log_debug(f"Failed to connect to Task Scheduler RPC: {e}")
            return False

    def disconnect(self) -> None:
        """Close RPC connection."""
        if self._dce:
            with contextlib.suppress(Exception):
                self._dce.disconnect()
            self._dce = None

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
        return False

    def get_task_run_info(self, task_path: str) -> Optional[TaskRunInfo]:
        """
        Query last run information for a specific task.

        Args:
            task_path: Full path to task (e.g., "\\MyTask" or
                      "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag")

        Returns:
            TaskRunInfo with credential validation results, or None on error
        """
        if not self._dce:
            warn("Not connected to Task Scheduler RPC")
            return None

        try:
            resp = tsch.hSchRpcGetLastRunInfo(self._dce, task_path)
            last_run_time = resp["pLastRuntime"]
            return_code = resp["pLastReturnCode"]

            # Parse last run time
            if last_run_time["wYear"] == 0:
                last_run = None
            else:
                last_run = datetime(
                    year=last_run_time["wYear"],
                    month=last_run_time["wMonth"],
                    day=last_run_time["wDay"],
                    hour=last_run_time["wHour"],
                    minute=last_run_time["wMinute"],
                    second=last_run_time["wSecond"],
                )

            # Determine credential status
            cred_status, password_valid, hijackable, detail = (
                self._interpret_return_code(return_code, last_run)
            )

            return TaskRunInfo(
                task_path=task_path,
                last_run=last_run,
                return_code=return_code,
                credential_status=cred_status,
                status_detail=detail,
                password_valid=password_valid,
                task_hijackable=hijackable,
            )

        except Exception as e:
            error_str = str(e)
            if "SCHED_S_TASK_HAS_NOT_RUN" in error_str:
                return TaskRunInfo(
                    task_path=task_path,
                    last_run=None,
                    return_code=0x00041303,
                    credential_status=CredentialStatus.UNKNOWN,
                    status_detail="Task has never run",
                    password_valid=False,  # Can't determine
                    task_hijackable=False,  # Can't determine
                )
            log_debug(f"Failed to get run info for {task_path}: {e}")
            # Check if connection was lost (need to reconnect)
            if "PIPE_DISCONNECTED" in error_str or "rpc_s_access_denied" in error_str:
                self._connection_lost = True
            return None

    def _interpret_return_code(
        self, code: int, last_run: Optional[datetime]
    ) -> tuple[CredentialStatus, bool, bool, str]:
        """
        Interpret return code for credential validation.

        Args:
            code: Task return code
            last_run: Last run datetime (None if never ran)

        Returns:
            Tuple of (status, password_valid, task_hijackable, detail_message)
        """
        detail = get_return_code_description(code)

        if last_run is None:
            return (CredentialStatus.UNKNOWN, False, False, "Task never executed")

        if code in PASSWORD_VALID_CODES:
            hijackable = code in TASK_RUNNABLE_CODES
            if hijackable:
                return (CredentialStatus.VALID, True, True, detail)
            else:
                return (
                    CredentialStatus.VALID_RESTRICTED,
                    True,
                    False,
                    f"{detail} (password valid, account restricted)",
                )

        elif code in PASSWORD_INVALID_CODES:
            return (CredentialStatus.INVALID, False, False, detail)

        elif code in ACCOUNT_BLOCKED_CODES:
            return (CredentialStatus.BLOCKED, False, False, detail)

        else:
            # Unknown code but task ran - likely valid
            return (
                CredentialStatus.VALID,
                True,
                True,
                f"{detail} (task executed, assuming valid)",
            )

    def validate_specific_tasks(
        self, task_paths: list[str]
    ) -> dict[str, TaskRunInfo]:
        """
        Validate credentials for specific task paths.

        Use this when you already have the list of password-authenticated
        tasks from SMB crawling - avoids redundant RPC enumeration.

        Args:
            task_paths: List of task paths to validate.
                        Accepts SMB paths like "Windows\\System32\\Tasks\\MyTask"
                        or RPC paths like "\\MyTask"

        Returns:
            Dictionary mapping ORIGINAL task path to TaskRunInfo
            (preserves the SMB path format for correlation)
        """
        results = {}

        # Task root prefix from SMB crawling
        SMB_TASK_PREFIX = "Windows\\System32\\Tasks\\"
        SMB_TASK_PREFIX_ALT = "Windows/System32/Tasks/"

        # Track if we need to reconnect (Kerberos connections can drop after errors)
        for original_path in task_paths:
            # Reconnect if connection was lost (common with Kerberos after RPC errors)
            if self._connection_lost:
                log_debug("Reconnecting to Task Scheduler RPC (connection lost)...")
                self.disconnect()
                if not self.connect():
                    log_debug("Failed to reconnect to Task Scheduler RPC")
                    break

            # Convert SMB path to RPC path
            # SMB: "Windows\System32\Tasks\HIGH_PRIV_CREDS"
            # RPC: "\HIGH_PRIV_CREDS"
            rpc_path = original_path

            # Strip SMB task root prefix
            if rpc_path.startswith(SMB_TASK_PREFIX):
                rpc_path = rpc_path[len(SMB_TASK_PREFIX):]
            elif rpc_path.startswith(SMB_TASK_PREFIX_ALT):
                rpc_path = rpc_path[len(SMB_TASK_PREFIX_ALT):]

            # Ensure path starts with backslash for RPC
            if not rpc_path.startswith("\\"):
                rpc_path = "\\" + rpc_path

            # Normalize path separators (SMB uses \, RPC uses \)
            rpc_path = rpc_path.replace("/", "\\")

            log_debug(f"Validating credentials for task: {rpc_path} (SMB: {original_path})")
            run_info = self.get_task_run_info(rpc_path)
            if run_info:
                # Store with original SMB path for correlation with crawled tasks
                results[original_path] = run_info
                # Detailed validation result logging
                log_debug(
                    f"  -> {rpc_path}: status={run_info.credential_status.name}, "
                    f"return_code=0x{run_info.return_code:08X}, "
                    f"password_valid={run_info.password_valid}, "
                    f"hijackable={run_info.task_hijackable}, "
                    f"detail='{run_info.status_detail}'"
                )
            else:
                log_debug(f"  -> {rpc_path}: Could not get run info (RPC error or access denied)")

        return results
