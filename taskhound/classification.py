# Classification logic for determining privilege levels.
#
# This module provides shared classification logic used by both online
# and offline processing modes. It determines whether a task or service
# is TIER-0, PRIV (high-value), or TASK/SERVICE (normal) based on the
# runas/start_name account.

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .resolver import looks_like_domain_user
from .utils.logging import warn

if TYPE_CHECKING:
    from .models.service import ServiceRow
    from .models.task import TaskRow

from .models.task import TaskType


@dataclass
class ClassificationResult:
    """Result of task or service classification."""

    task_type: str  # "TIER-0", "PRIV", "TASK", or "SERVICE"
    reason: str | None = None
    password_analysis: str | None = None
    should_include: bool = True  # Whether to include in output


# Type alias for pre-fetched password data: username -> pwdLastSet datetime
PwdLastSetCache = dict[str, datetime]

# Type alias for pre-fetched Tier-0 membership data: username -> (is_tier0, group_list)
Tier0Cache = dict[str, tuple[bool, list[str]]]


def _get_task_date_for_analysis(meta: dict) -> tuple[str | None, bool]:
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
    meta: dict,
    rel_path: str,
    pwd_cache: PwdLastSetCache | None = None,
) -> str | None:
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


# Reason fragments (kept as module constants so task/service paths stay identical).
_HIGHVALUE_REASON = "High Value match found (Check BloodHound Outbound Object Control for Details)"
_BARE_MATCH_NOTE = " (matched by bare username — verify not a local account)"


def _bloodhound_privilege(
    hv: Any,
    account: str,
    resolved_account_sid: str | None,
    match_bare_runas: bool,
) -> tuple[str, str] | None:
    r"""Detect TIER-0/PRIV for an account using BloodHound data.

    Returns (classification, reason) or None. Handles a bare-name RunAs (no ``DOMAIN\``
    prefix, no UPN ``@``): when it was resolved to a domain SID upstream, that SID is matched
    directly against BloodHound's SID-keyed data (a domain-LDAP-resolved SID proves the bare
    name is a real domain account, neutralizing the local-account false-positive concern).
    When ``match_bare_runas`` is set and no SID was resolved, fall back to matching the bare
    name against domain data with a verification annotation.
    """
    from .resolver import is_bare_name, is_probably_local_bare_name

    bare = is_bare_name(account)
    lookup = resolved_account_sid if (resolved_account_sid and bare) else account

    is_tier0, reasons = hv.check_tier0(lookup)
    if is_tier0:
        return "TIER-0", "; ".join(reasons)
    if hv.check_highvalue(lookup):
        return "PRIV", _HIGHVALUE_REASON

    if match_bare_runas and bare and not resolved_account_sid and not is_probably_local_bare_name(account):
        is_tier0, reasons = hv.check_tier0_bare(account)
        if is_tier0:
            return "TIER-0", "; ".join(reasons) + _BARE_MATCH_NOTE
        if hv.check_highvalue_bare(account):
            return "PRIV", _HIGHVALUE_REASON + _BARE_MATCH_NOTE
    return None


def _ldap_tier0(
    account: str,
    tier0_cache: Tier0Cache,
    resolved_account: str | None,
    resolved_account_sid: str | None,
    match_bare_runas: bool,
) -> tuple[str, str] | None:
    r"""Detect TIER-0 via the pre-fetched LDAP tier0_cache (used when BloodHound is absent).

    The cache is keyed by sAMAccountName and contains only domain accounts. A bare name is
    matched when it was resolved to a domain SID upstream (proven domain account) or, opt-in
    via ``match_bare_runas``, when it is not a known local account.
    """
    from .resolver import is_bare_name, is_probably_local_bare_name, is_sid

    lookup_user = account
    if is_sid(account) and resolved_account:
        lookup_user = resolved_account

    if "\\" in lookup_user:
        norm_user = lookup_user.split("\\")[-1].lower()
    elif "@" in lookup_user:
        norm_user = lookup_user.split("@")[0].lower()
    else:
        norm_user = lookup_user.lower()

    bare = is_bare_name(account)
    allow = (
        "\\" in lookup_user
        or "@" in lookup_user
        or is_sid(account)
        or (bare and resolved_account_sid is not None)
        or (bare and match_bare_runas and not is_probably_local_bare_name(account))
    )
    if not allow:
        return None

    tier0_result = tier0_cache.get(norm_user)
    if tier0_result:
        is_tier0, groups = tier0_result
        if is_tier0:
            reason = f"Tier-0 via LDAP: member of {', '.join(groups)}"
            if bare and not resolved_account_sid:
                reason += _BARE_MATCH_NOTE
            return "TIER-0", reason
    return None


def classify_task(
    row: "TaskRow",
    meta: dict[str, Any],
    runas: str,
    rel_path: str,
    hv: Any | None,
    show_unsaved_creds: bool,
    include_local: bool,
    pwd_cache: PwdLastSetCache | None = None,
    tier0_cache: Tier0Cache | None = None,
    resolved_runas: str | None = None,
    resolved_runas_sid: str | None = None,
    match_bare_runas: bool = False,
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
        resolved_runas_sid: Domain SID resolved from a bare-name runas (for BloodHound SID match)
        match_bare_runas: Opt-in fallback matching unresolved bare names against domain data

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

    # Check for Tier 0 / high-value. Priority: BloodHound data > LDAP tier0_cache.
    # A bare-name RunAs (e.g. "svc_admin" with no domain) is matched via its resolved
    # domain SID when available; see _bloodhound_privilege / _ldap_tier0.
    priv: tuple[str, str] | None = None
    if hv and hv.loaded:
        priv = _bloodhound_privilege(hv, runas, resolved_runas_sid, match_bare_runas)
    elif tier0_cache:
        priv = _ldap_tier0(runas, tier0_cache, resolved_runas, resolved_runas_sid, match_bare_runas)

    if priv:
        classification, reason = priv
        password_analysis = None

        if has_no_saved_creds:
            reason = f"{reason} (no saved credentials — DPAPI dump not applicable; manipulation requires an interactive session)"
        else:
            password_analysis = _analyze_password_age(hv, runas, meta, rel_path, pwd_cache)

        # Account-disabled indicator is only available from BloodHound data (the LDAP
        # tier0_cache carries no enabled/disabled state) — matches prior behavior.
        if hv and hv.loaded:
            reason = _add_account_status(reason)

        # Update row in place
        row.type = TaskType.TIER0.value if classification == "TIER-0" else TaskType.PRIV.value
        row.reason = reason
        row.password_analysis = password_analysis

        return ClassificationResult(
            task_type=classification,
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


# ---------------------------------------------------------------------------
# Shared privilege detection helpers
# ---------------------------------------------------------------------------


def _check_account_disabled(hv: Any, account: str) -> bool:
    """Check if an account is disabled in AD via BloodHound data."""
    if hv and hv.loaded:
        enabled = hv.is_account_enabled(account)
        if enabled is False:
            return True
    return False


def _classify_by_privilege(
    account: str,
    hv: Any | None,
    tier0_cache: Tier0Cache | None = None,
    resolved_account: str | None = None,
    resolved_account_sid: str | None = None,
    match_bare_runas: bool = False,
) -> tuple[str, str] | None:
    """
    Check if an account is TIER-0 or PRIV via BloodHound or LDAP cache.

    This is the shared privilege detection used by both classify_task()
    and classify_service().

    Args:
        account: The account name (domain\\user, UPN, SID, or bare name)
        hv: HighValueLoader instance (can be None)
        tier0_cache: Pre-fetched LDAP Tier-0 membership data
        resolved_account: Resolved username if account was a SID
        resolved_account_sid: Domain SID resolved from a bare-name account
        match_bare_runas: Opt-in fallback matching unresolved bare names against domain data

    Returns:
        Tuple of (classification, reason) if TIER-0 or PRIV detected,
        None if the account is not privileged.
    """
    # Priority 1: BloodHound data; Priority 2: LDAP tier0_cache (when BloodHound absent).
    if hv and hv.loaded:
        return _bloodhound_privilege(hv, account, resolved_account_sid, match_bare_runas)
    if tier0_cache:
        return _ldap_tier0(account, tier0_cache, resolved_account, resolved_account_sid, match_bare_runas)
    return None


def _get_password_analysis_from_cache(
    account: str,
    pwd_cache: PwdLastSetCache | None,
    hv: Any | None = None,
) -> str | None:
    """
    Get password age analysis for an account from cache or BloodHound.

    Unlike _analyze_password_age() which needs task metadata dates,
    this version works with accounts directly (for services).
    """
    # Try BloodHound first
    if hv and hv.loaded:
        risk_level, pwd_analysis = hv.analyze_password_age(account, None)
        if risk_level != "UNKNOWN":
            return f"{risk_level}: {pwd_analysis}"

    # Fall back to LDAP pwd_cache
    if pwd_cache:
        try:
            from .parsers.highvalue import _analyze_password_freshness

            norm_user = account.split("\\")[-1].lower() if "\\" in account else account.lower()
            pwd_last_set = pwd_cache.get(norm_user)

            if pwd_last_set:
                risk_level, pwd_analysis = _analyze_password_freshness(None, pwd_last_set)
                if risk_level != "UNKNOWN":
                    return f"{risk_level}: {pwd_analysis}"
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# Service classification
# ---------------------------------------------------------------------------


def classify_service(
    row: "ServiceRow",
    account: str,
    hv: Any | None,
    pwd_cache: PwdLastSetCache | None = None,
    tier0_cache: Tier0Cache | None = None,
    resolved_account: str | None = None,
    resolved_account_sid: str | None = None,
    match_bare_runas: bool = False,
) -> ClassificationResult:
    """
    Classify a service as TIER-0, PRIV, or SERVICE based on the start_name account.

    Unlike tasks, ALL domain-account services inherently store credentials
    in LSA secrets — there is no "no saved credentials" state. Classification
    focuses on privilege level and account status.

    Args:
        row: ServiceRow instance (modified in place with type/reason/password_analysis)
        account: The account the service runs as (start_name)
        hv: HighValueLoader instance (can be None)
        pwd_cache: Pre-fetched dict of username -> pwdLastSet datetime
        tier0_cache: Pre-fetched dict of username -> (is_tier0, group_list) from LDAP
        resolved_account: Pre-resolved username if account was a SID

    Returns:
        ClassificationResult with task_type, reason, password_analysis, should_include
    """
    from .models.service import ServiceType

    # Check privilege level
    priv_result = _classify_by_privilege(
        account, hv, tier0_cache, resolved_account,
        resolved_account_sid=resolved_account_sid,
        match_bare_runas=match_bare_runas,
    )

    if priv_result:
        classification, reason = priv_result

        # Check if account is disabled
        if _check_account_disabled(hv, account):
            reason = f"[ACCOUNT DISABLED] {reason}"
            row.is_disabled_account = True

        # gMSA annotation
        if row.is_gmsa:
            reason = f"[gMSA] {reason}"

        # Password age analysis
        password_analysis = _get_password_analysis_from_cache(account, pwd_cache, hv)

        # Update row in place
        row.type = ServiceType.TIER0.value if classification == "TIER-0" else ServiceType.PRIV.value
        row.reason = reason
        row.password_analysis = password_analysis

        return ClassificationResult(
            task_type=classification,
            reason=reason,
            password_analysis=password_analysis,
            should_include=True,
        )

    # Regular SERVICE — still check disabled status and password age
    reason = None
    if _check_account_disabled(hv, account):
        reason = "[ACCOUNT DISABLED]"
        row.is_disabled_account = True

    if row.is_gmsa:
        gmsa_note = "[gMSA] Managed password — NTLM hash extracted from LSA if available"
        reason = f"{reason} {gmsa_note}" if reason else gmsa_note

    password_analysis = _get_password_analysis_from_cache(account, pwd_cache, hv)

    row.type = ServiceType.SERVICE.value
    row.reason = reason
    row.password_analysis = password_analysis

    return ClassificationResult(
        task_type="SERVICE",
        reason=reason,
        password_analysis=password_analysis,
        should_include=True,
    )
