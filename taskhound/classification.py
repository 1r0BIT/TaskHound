# Task classification logic for determining privilege levels.
#
# This module provides shared classification logic used by both online
# and offline processing modes. It determines whether a task is TIER-0,
# PRIV (high-value), or TASK (normal) based on the runas account.

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from .utils.logging import warn
from .resolver import looks_like_domain_user

if TYPE_CHECKING:
    from .models.task import TaskRow

from .models.task import TaskType


@dataclass
class ClassificationResult:
    """Result of task classification."""

    task_type: str  # "TIER-0", "PRIV", or "TASK"
    reason: Optional[str] = None
    password_analysis: Optional[str] = None
    should_include: bool = True  # Whether to include in output


# Type alias for pre-fetched password data: username -> pwdLastSet datetime
PwdLastSetCache = Dict[str, datetime]

# Type alias for pre-fetched Tier-0 membership data: username -> (is_tier0, group_list)
Tier0Cache = Dict[str, Tuple[bool, List[str]]]


def _get_task_date_for_analysis(meta: Dict) -> Tuple[Optional[str], bool]:
    """
    Get the best available date for password freshness analysis.
    Prefers RegistrationInfo/Date, falls back to StartBoundary from trigger.

    Args:
        meta: Task metadata dict containing date and start_boundary fields

    Returns:
        Tuple of (date_string, is_fallback) where:
        - date_string: ISO format date string or None if no date available
        - is_fallback: True if using StartBoundary fallback, False if using explicit date
    """
    # Prefer explicit registration date
    if meta.get("date"):
        return meta.get("date"), False

    # Fall back to start boundary (trigger time) as proxy for task creation
    # This is less accurate but better than no analysis at all
    if meta.get("start_boundary"):
        return meta.get("start_boundary"), True

    return None, False


def _analyze_password_age(
    hv: Any,
    runas: str,
    meta: Dict,
    rel_path: str,
    pwd_cache: Optional[PwdLastSetCache] = None,
) -> Optional[str]:
    """
    Analyze password age for DPAPI dump viability.

    Uses BloodHound data if available, otherwise uses pre-fetched LDAP data
    from pwd_cache (if provided).

    Args:
        hv: HighValueLoader instance (can be None)
        runas: The account the task runs as
        meta: Task metadata dict
        rel_path: Task path for warning messages
        pwd_cache: Pre-fetched dict of username -> pwdLastSet datetime (optional)

    Returns:
        Password analysis string or None if not applicable
    """
    task_date, is_fallback = _get_task_date_for_analysis(meta)
    if is_fallback and task_date:
        warn(
            f"Task {rel_path} has no explicit creation date - "
            "using trigger StartBoundary for password analysis (may be inaccurate)"
        )

    # Try BloodHound data first
    if hv and hv.loaded:
        risk_level, pwd_analysis = hv.analyze_password_age(runas, task_date)
        if risk_level != "UNKNOWN":
            return f"{risk_level}: {pwd_analysis}"

    # Fall back to pre-fetched LDAP data if BloodHound not available
    if pwd_cache and task_date:
        try:
            from .parsers.highvalue import _analyze_password_freshness

            # Normalize username for lookup
            norm_user = runas.split("\\")[-1].lower() if "\\" in runas else runas.lower()

            pwd_last_set = pwd_cache.get(norm_user)

            if pwd_last_set:
                risk_level, pwd_analysis = _analyze_password_freshness(task_date, pwd_last_set)
                if risk_level != "UNKNOWN":
                    return f"{risk_level}: {pwd_analysis}"
        except Exception as e:
            from .utils.logging import debug
            debug(f"Password analysis failed for {runas}: {e}")

    return None


def classify_task(
    row: "TaskRow",
    meta: Dict[str, Any],
    runas: str,
    rel_path: str,
    hv: Optional[Any],
    show_unsaved_creds: bool,
    include_local: bool,
    pwd_cache: Optional[PwdLastSetCache] = None,
    tier0_cache: Optional[Tier0Cache] = None,
    resolved_runas: Optional[str] = None,
) -> ClassificationResult:
    """
    Classify a task as TIER-0, PRIV, or TASK based on the runas account.

    This is the single source of truth for task classification logic,
    used by both online and offline processing modes.

    Args:
        row: TaskRow instance (modified in place with type/reason/password_analysis)
        meta: Parsed task XML metadata
        runas: The account the task runs as
        rel_path: Task path for display/warnings
        hv: HighValueLoader instance (can be None)
        show_unsaved_creds: Whether to include tasks without saved credentials
        include_local: Whether to include local system accounts
        pwd_cache: Pre-fetched dict of username -> pwdLastSet datetime
        tier0_cache: Pre-fetched dict of username -> (is_tier0, group_list) from LDAP
        resolved_runas: Pre-resolved username if runas was a SID (for tier0_cache lookup)

    Returns:
        ClassificationResult with task_type, reason, password_analysis, should_include
    """
    has_no_saved_creds = row.credentials_hint == "no_saved_credentials"
    has_stored_creds = row.credentials_hint == "stored_credentials"

    # Skip tasks without saved credentials unless user explicitly requested them
    if has_no_saved_creds and not show_unsaved_creds:
        return ClassificationResult(
            task_type="TASK",
            should_include=False,
        )

    # Helper to add account status indicator
    def _add_account_status(reason: str) -> str:
        """Add [ACCOUNT DISABLED] indicator if account is disabled in AD."""
        if hv and hv.loaded:
            enabled = hv.is_account_enabled(runas)
            if enabled is False:  # Explicitly False, not None
                return f"[ACCOUNT DISABLED] {reason}"
        return reason

    # Check for Tier 0 first, then high-value
    # Priority: BloodHound data > LDAP tier0_cache
    if hv and hv.loaded:
        # Check Tier 0 classification via BloodHound
        is_tier0, tier0_reasons = hv.check_tier0(runas)
        if is_tier0:
            reason = "; ".join(tier0_reasons)
            password_analysis = None

            if has_no_saved_creds:
                reason = f"{reason} (no saved credentials — DPAPI dump not applicable; manipulation requires an interactive session)"
            else:
                password_analysis = _analyze_password_age(hv, runas, meta, rel_path, pwd_cache)

            # Add account status indicator
            reason = _add_account_status(reason)

            # Update row in place
            row.type = TaskType.TIER0.value
            row.reason = reason
            row.password_analysis = password_analysis

            return ClassificationResult(
                task_type="TIER-0",
                reason=reason,
                password_analysis=password_analysis,
                should_include=True,
            )

        # Check high-value (PRIV)
        if hv.check_highvalue(runas):
            reason = "High Value match found (Check BloodHound Outbound Object Control for Details)"
            password_analysis = None

            if has_no_saved_creds:
                reason = f"{reason} (no saved credentials — DPAPI dump not applicable; manipulation requires an interactive session)"
            else:
                password_analysis = _analyze_password_age(hv, runas, meta, rel_path, pwd_cache)

            # Add account status indicator
            reason = _add_account_status(reason)

            # Update row in place
            row.type = TaskType.PRIV.value
            row.reason = reason
            row.password_analysis = password_analysis

            return ClassificationResult(
                task_type="PRIV",
                reason=reason,
                password_analysis=password_analysis,
                should_include=True,
            )

    # Check LDAP-based Tier-0 detection (when BloodHound not available)
    elif tier0_cache:
        # Normalize username for lookup
        # If runas is a SID and we have a resolved username, use that instead
        from .resolver import is_sid
        lookup_user = runas
        if is_sid(runas) and resolved_runas:
            lookup_user = resolved_runas
        norm_user = lookup_user.split("\\")[-1].lower() if "\\" in lookup_user else lookup_user.lower()
        tier0_result = tier0_cache.get(norm_user)

        if tier0_result:
            is_tier0, groups = tier0_result
            if is_tier0:
                reason = f"Tier-0 via LDAP: member of {', '.join(groups)}"
                password_analysis = None

                if has_no_saved_creds:
                    reason = f"{reason} (no saved credentials — DPAPI dump not applicable; manipulation requires an interactive session)"
                else:
                    password_analysis = _analyze_password_age(hv, runas, meta, rel_path, pwd_cache)

                # Update row in place
                row.type = TaskType.TIER0.value
                row.reason = reason
                row.password_analysis = password_analysis

                return ClassificationResult(
                    task_type="TIER-0",
                    reason=reason,
                    password_analysis=password_analysis,
                    should_include=True,
                )

    # Regular task - still analyze password age if credentials are stored
    password_analysis = None
    if has_stored_creds:
        # Try BloodHound first, then pre-fetched LDAP data
        password_analysis = _analyze_password_age(hv, runas, meta, rel_path, pwd_cache)

    # Determine if we should include this regular task
    should_include = (
        looks_like_domain_user(runas)
        or has_stored_creds
        or (include_local and not looks_like_domain_user(runas))
    )

    if should_include:
        row.password_analysis = password_analysis

    return ClassificationResult(
        task_type="TASK",
        reason=None,
        password_analysis=password_analysis,
        should_include=should_include,
    )
