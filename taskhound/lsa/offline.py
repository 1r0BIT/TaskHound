# Offline service enumeration from exported registry hives.
#
# Parses SYSTEM hive to enumerate service configurations
# (CurrentControlSet\Services\*) and optionally SECURITY hive
# to extract LSA secrets (_SC_* entries) for credential recovery.
#
# Expected directory structure:
#   offline_dir/
#   └── hostname/
#       ├── SYSTEM       # Required: service configurations
#       └── SECURITY     # Optional: LSA secrets (for --loot)

from typing import Any, Dict, List, Tuple

from ..utils.logging import debug as log_debug
from ..utils.logging import good, info, warn

# Start type constants from registry
_START_TYPE_MAP = {
    0: "Boot",
    1: "System",
    2: "Auto",
    3: "Manual",
    4: "Disabled",
}

# Service type bitmask — only Win32 services are interesting
_WIN32_SERVICE_TYPES = {0x10, 0x20, 0x30, 0x50, 0x60, 0x110, 0x120}


def enumerate_services_from_hive(
    system_hive_path: str,
    hostname: str = "OFFLINE",
) -> List[Dict[str, Any]]:
    """
    Parse a SYSTEM registry hive to enumerate service configurations.

    Reads CurrentControlSet\\Services\\* subkeys and extracts service
    configurations. Filters to Win32 services only (skips drivers).

    Args:
        system_hive_path: Path to exported SYSTEM hive file
        hostname: Hostname to associate with services (for display)

    Returns:
        List of service dicts compatible with ServiceRow.from_svcctl()
    """
    try:
        from impacket.winregistry import Registry
    except ImportError:
        warn("impacket.winregistry not available — cannot parse offline hives")
        return []

    services: List[Dict[str, Any]] = []

    try:
        reg = Registry(system_hive_path, isRemote=False)

        # Find the CurrentControlSet (usually ControlSet001)
        # The "Select" key tells us which control set is current
        select_key = reg.findKey("Select")
        if select_key:
            current_value = reg.getValue("Current", select_key)
            if current_value:
                control_set_num = current_value[1]
                control_set = f"ControlSet{control_set_num:03d}"
            else:
                control_set = "ControlSet001"
        else:
            control_set = "ControlSet001"

        log_debug(f"{hostname}: Using {control_set} from SYSTEM hive")

        # Enumerate services under CurrentControlSet\Services
        services_key_path = f"{control_set}\\Services"
        services_key = reg.findKey(services_key_path)
        if not services_key:
            warn(f"{hostname}: Cannot find {services_key_path} in SYSTEM hive")
            reg.close()
            return []

        # Iterate over all service subkeys
        for subkey_name in reg.enumKey(services_key):
            try:
                svc_key = reg.findKey(f"{services_key_path}\\{subkey_name}")
                if not svc_key:
                    continue

                # Read service type
                type_val = reg.getValue("Type", svc_key)
                svc_type = type_val[1] if type_val else 0

                # Skip non-Win32 services (drivers, etc.)
                if svc_type not in _WIN32_SERVICE_TYPES:
                    continue

                # Read ObjectName (the account the service runs as)
                obj_val = reg.getValue("ObjectName", svc_key)
                account = obj_val[1].rstrip("\x00") if obj_val and obj_val[1] else ""

                # Read ImagePath (binary path)
                img_val = reg.getValue("ImagePath", svc_key)
                binary_path = img_val[1].rstrip("\x00") if img_val and img_val[1] else ""

                # Read Start type
                start_val = reg.getValue("Start", svc_key)
                start_type = start_val[1] if start_val else 3

                # Read DisplayName
                display_val = reg.getValue("DisplayName", svc_key)
                display_name = display_val[1].rstrip("\x00") if display_val and display_val[1] else subkey_name

                services.append({
                    "name": subkey_name,
                    "display_name": display_name,
                    "account": account,
                    "binary_path": binary_path,
                    "start_type": start_type,
                    "service_type": svc_type,
                    "state": 0,  # Unknown from offline hive
                })

            except Exception as e:
                log_debug(f"{hostname}: Error reading service '{subkey_name}': {e}")
                continue

        reg.close()
        info(f"{hostname}: Enumerated {len(services)} Win32 services from SYSTEM hive")
        return services

    except Exception as e:
        warn(f"{hostname}: Failed to parse SYSTEM hive: {e}")
        return []


def extract_offline_lsa_secrets(
    system_hive_path: str,
    security_hive_path: str,
    hostname: str = "OFFLINE",
    service_names: set | None = None,
) -> Dict[str, str]:
    """
    Extract _SC_* LSA secrets from offline SYSTEM + SECURITY hives.

    Args:
        system_hive_path: Path to SYSTEM hive
        security_hive_path: Path to SECURITY hive
        hostname: Hostname for logging
        service_names: Optional set of service names to filter

    Returns:
        Dict mapping service_name -> plaintext_password
    """
    from impacket.examples.secretsdump import LocalOperations, LSASecrets

    credentials: Dict[str, str] = {}
    captured: List[Tuple[Any, str]] = []

    def _callback(secret_type, secret: str) -> None:
        captured.append((secret_type, secret))

    try:
        local_ops = LocalOperations(system_hive_path)
        boot_key = local_ops.getBootKey()
        log_debug(f"{hostname}: Boot key extracted from offline SYSTEM hive")

        lsa = LSASecrets(
            security_hive_path,
            boot_key,
            isRemote=False,
            perSecretCallback=_callback,
        )
        lsa.dumpSecrets()
        log_debug(f"{hostname}: Dumped {len(captured)} LSA secrets from offline hive")

        # Parse _SC_* secrets
        for _stype, secret_str in captured:
            if not secret_str or ":" not in secret_str:
                continue

            account, password = secret_str.split(":", 1)
            if not password:
                continue

            # We can't easily map back to service names in offline mode
            # without the SCM, but we store the credential for matching
            credentials[account] = password

        if credentials:
            good(f"{hostname}: Extracted {len(credentials)} credential(s) from offline LSA secrets")

        lsa.finish()
        return credentials

    except Exception as e:
        warn(f"{hostname}: Offline LSA extraction failed: {e}")
        return {}
