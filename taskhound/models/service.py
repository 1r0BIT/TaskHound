# Service data model for structured Windows service representation.
#
# This module provides the ServiceRow dataclass for services discovered
# via SVCCTL RPC enumeration. Parallel to TaskRow but with service-specific
# fields (service_name, binary_path, start_type, etc. instead of task path,
# triggers, logon types).

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class ServiceType(str, Enum):
    """Classification type for a Windows service."""

    TIER0 = "TIER-0"
    PRIV = "PRIV"
    SERVICE = "SERVICE"
    FAILURE = "FAILURE"
    SKIPPED = "SKIPPED"


# Human-readable start type names
START_TYPE_MAP = {
    0x00: "Boot",
    0x01: "System",
    0x02: "Auto",
    0x03: "Manual",
    0x04: "Disabled",
}

# Human-readable service type names (Win32 only — drivers are pre-filtered)
SERVICE_TYPE_MAP = {
    0x10: "Win32OwnProcess",
    0x20: "Win32ShareProcess",
    0x30: "Win32OwnOrShare",
    0x50: "UserOwnProcess",
    0x60: "UserShareProcess",
    # With interactive bit set
    0x110: "Win32OwnProcess (Interactive)",
    0x120: "Win32ShareProcess (Interactive)",
}

# Human-readable state names
STATE_MAP = {
    0x01: "Stopped",
    0x02: "StartPending",
    0x03: "StopPending",
    0x04: "Running",
    0x05: "ContinuePending",
    0x06: "PausePending",
    0x07: "Paused",
}


@dataclass
class ServiceRow:
    """
    Structured representation of a Windows service for export and processing.

    Attributes:
        host: The FQDN of the target host (resolved from SMB)
        service_name: Internal service name (registry key)
        target_ip: Original target IP/hostname used for connection
        computer_sid: Computer account SID from SMB
        type: Classification (TIER-0, PRIV, SERVICE, FAILURE, SKIPPED)
        reason: Classification reason
        password_analysis: Password age analysis result
        start_name: Account the service runs as (lpServiceStartName)
        resolved_runas: Resolved username if start_name was a SID
        display_name: Human-readable service name
        binary_path: Executable path (lpBinaryPathName)
        start_type: Boot/System/Auto/Manual/Disabled
        service_type: Win32OwnProcess/Win32ShareProcess/etc.
        state: Running/Stopped/Paused/etc.
        is_gmsa: Whether this is a Group Managed Service Account
        is_disabled_account: Whether the AD account is disabled
        credential_guard: Whether Credential Guard is detected on the host
        decrypted_password: Plaintext password from LSA secret extraction
        lsa_secret_name: The _SC_<ServiceName> registry key
    """

    # Required fields
    host: str
    service_name: str

    # Connection info
    target_ip: Optional[str] = None
    computer_sid: Optional[str] = None

    # Classification
    type: str = field(default=ServiceType.SERVICE.value)
    reason: Optional[str] = None
    password_analysis: Optional[str] = None

    # Service identity
    start_name: Optional[str] = None
    resolved_runas: Optional[str] = None
    display_name: Optional[str] = None
    binary_path: Optional[str] = None
    start_type: Optional[str] = None
    service_type: Optional[str] = None
    state: Optional[str] = None

    # Account flags
    is_gmsa: bool = False
    is_disabled_account: bool = False

    # Credential state
    credential_guard: Optional[bool] = None
    decrypted_password: Optional[str] = None
    lsa_secret_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON/CSV export."""
        return asdict(self)

    @classmethod
    def from_svcctl(
        cls,
        host: str,
        svc: Dict[str, Any],
        target_ip: Optional[str] = None,
        computer_sid: Optional[str] = None,
    ) -> "ServiceRow":
        """
        Create a ServiceRow from SVCCTL RPC enumeration data.

        Args:
            host: FQDN of the target host
            svc: Dict from enumerate_services() with keys:
                 name, display_name, account, binary_path,
                 start_type, service_type, state
            target_ip: Original target IP/hostname
            computer_sid: Computer account SID
        """
        account = (svc.get("account") or "").strip()
        is_gmsa = account.endswith("$") and "\\" in account

        return cls(
            host=host,
            service_name=svc.get("name", ""),
            target_ip=target_ip,
            computer_sid=computer_sid,
            start_name=account or None,
            display_name=svc.get("display_name"),
            binary_path=svc.get("binary_path"),
            start_type=START_TYPE_MAP.get(svc.get("start_type", -1), str(svc.get("start_type", ""))),
            service_type=SERVICE_TYPE_MAP.get(svc.get("service_type", -1), str(svc.get("service_type", ""))),
            state=STATE_MAP.get(svc.get("state", -1), str(svc.get("state", ""))),
            is_gmsa=is_gmsa,
            lsa_secret_name=f"_SC_{svc.get('name', '')}",
        )

    @classmethod
    def failure(
        cls,
        host: str,
        reason: str,
        target_ip: Optional[str] = None,
    ) -> "ServiceRow":
        """Create a FAILURE row for hosts that couldn't be processed."""
        return cls(
            host=host,
            service_name="",
            target_ip=target_ip,
            type=ServiceType.FAILURE.value,
            reason=reason,
        )

    @classmethod
    def skipped(
        cls,
        host: str,
        reason: str,
        target_ip: Optional[str] = None,
    ) -> "ServiceRow":
        """Create a SKIPPED row for dual-homed hosts already processed."""
        return cls(
            host=host,
            service_name="",
            target_ip=target_ip,
            type=ServiceType.SKIPPED.value,
            reason=reason,
        )
