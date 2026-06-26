# Task data model for structured task representation.
#
# This module provides the TaskRow dataclass which replaces the previous
# Dict[str, Any] approach, giving type safety and IDE autocomplete support.

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class TaskType(str, Enum):
    """Classification type for a scheduled task."""

    TIER0 = "TIER-0"
    PRIV = "PRIV"
    TASK = "TASK"
    FAILURE = "FAILURE"
    SKIPPED = "SKIPPED"  # Dual-homed duplicate, not processed


@dataclass
class TaskRow:
    """
    Structured representation of a scheduled task for export and processing.

    This dataclass replaces the previous Dict[str, Any] approach, providing:
    - Type safety and IDE autocomplete
    - Clear documentation of all fields
    - Easy conversion to dict for JSON/CSV export
    - Default values for optional fields

    Attributes:
        host: The FQDN of the target host (resolved from SMB)
        path: Relative path to the task (e.g., "Windows\\System32\\Tasks\\MyTask")
        target_ip: Original target IP/hostname used for connection
        computer_sid: Computer account SID from SMB (for BloodHound lookups)
        type: Task classification (TIER-0, PRIV, TASK, FAILURE)
        runas: Account the task runs as
        command: Command/executable to run
        arguments: Command arguments
        author: Task author from XML
        date: Task creation/registration date
        logon_type: Windows logon type (Password, InteractiveToken, S4U, etc.)
        enabled: Whether the task is enabled
        trigger_type: Type of trigger (TimeTrigger, CalendarTrigger, etc.)
        start_boundary: Trigger start time
        interval: Repetition interval
        duration: Repetition duration
        days_interval: Days between runs (for daily triggers)
        reason: Classification reason (for TIER-0/PRIV tasks)
        credentials_hint: Credential storage hint (stored_credentials, no_saved_credentials)
        credential_guard: Whether Credential Guard is detected on the host
        password_analysis: Password age analysis result
        cred_status: Credential validation status (valid, invalid, blocked, unknown)
        cred_password_valid: Whether stored password is valid (key for DPAPI feasibility)
        cred_hijackable: Whether the task can be hijacked
        cred_last_run: ISO timestamp of last task run
        cred_return_code: Hex return code from last execution
        cred_detail: Human-readable credential validation detail
        resolved_runas: Resolved username if runas was a SID (for credential matching)
    """

    # Required fields (set during construction)
    host: str
    path: str

    # Connection info
    target_ip: str | None = None
    computer_sid: str | None = None

    # Classification
    type: str = field(default=TaskType.TASK.value)
    reason: str | None = None
    password_analysis: str | None = None

    # Task identity
    runas: str | None = None
    resolved_runas: str | None = None  # Resolved username if runas was a SID
    resolved_runas_sid: str | None = None  # Domain SID resolved from a bare-name runas
    command: str | None = None
    arguments: str | None = None
    author: str | None = None
    date: str | None = None

    # Task configuration
    logon_type: str | None = None
    enabled: str | None = None
    trigger_type: str | None = None
    start_boundary: str | None = None
    interval: str | None = None
    duration: str | None = None
    days_interval: str | None = None

    # Credential hints
    credentials_hint: str | None = None
    credential_guard: bool | None = None

    # Credential validation (--validate-creds)
    cred_status: str | None = None
    cred_password_valid: bool | None = None
    cred_hijackable: bool | None = None
    cred_last_run: str | None = None
    cred_return_code: str | None = None
    cred_detail: str | None = None

    # DPAPI looted credentials
    decrypted_password: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON/CSV export."""
        return asdict(self)

    @classmethod
    def from_meta(
        cls,
        host: str,
        rel_path: str,
        meta: dict[str, Any],
        target_ip: str | None = None,
        computer_sid: str | None = None,
    ) -> "TaskRow":
        """
        Create a TaskRow from parsed task XML metadata.

        Args:
            host: FQDN of the target host
            rel_path: Relative path to the task
            meta: Parsed task XML metadata dict
            target_ip: Original target IP/hostname
            computer_sid: Computer account SID

        Returns:
            TaskRow instance with fields populated from metadata
        """
        # Determine credentials hint based on logon type
        logon_type_raw = meta.get("logon_type")
        logon_type = logon_type_raw.strip().lower() if logon_type_raw else ""

        if logon_type == "password":
            credentials_hint = "stored_credentials"
        elif logon_type in ("interactive", "interactivetoken", "s4u"):
            credentials_hint = "no_saved_credentials"
        else:
            credentials_hint = None

        return cls(
            host=host,
            path=rel_path,
            target_ip=target_ip,
            computer_sid=computer_sid,
            runas=meta.get("runas"),
            command=meta.get("command"),
            arguments=meta.get("arguments"),
            author=meta.get("author"),
            date=meta.get("date"),
            logon_type=meta.get("logon_type"),
            enabled=meta.get("enabled"),
            trigger_type=meta.get("trigger_type"),
            start_boundary=meta.get("start_boundary"),
            interval=meta.get("interval"),
            duration=meta.get("duration"),
            days_interval=meta.get("days_interval"),
            credentials_hint=credentials_hint,
        )

    @classmethod
    def failure(
        cls,
        host: str,
        reason: str,
        target_ip: str | None = None,
    ) -> "TaskRow":
        """
        Create a FAILURE row for hosts that couldn't be processed.

        Args:
            host: Hostname or IP of the failed target
            reason: Failure reason message
            target_ip: Original target IP/hostname

        Returns:
            TaskRow with type=FAILURE
        """
        return cls(
            host=host,
            path="",
            target_ip=target_ip,
            type=TaskType.FAILURE.value,
            reason=reason,
        )

    @classmethod
    def skipped(
        cls,
        host: str,
        reason: str,
        target_ip: str | None = None,
    ) -> "TaskRow":
        """
        Create a SKIPPED row for dual-homed hosts already processed.

        Args:
            host: Hostname or IP of the skipped target
            reason: Skip reason message (e.g., "duplicate of 192.168.1.1")
            target_ip: Original target IP/hostname

        Returns:
            TaskRow with type=SKIPPED
        """
        return cls(
            host=host,
            path="",
            target_ip=target_ip,
            type=TaskType.SKIPPED.value,
            reason=reason,
        )
