# Disk loader for mounted Windows filesystems (VHDX, forensic images).
#
# This module extracts scheduled tasks and DPAPI data from a mounted Windows
# filesystem and creates a TaskHound-compatible backup structure for analysis.
#
# Usage:
#     taskhound --offline-disk /mnt/vhdx
#
# Automatically extracts DPAPI key from registry hives if --dpapi-key not provided.
# Creates backup in ./dpapi_loot/<hostname>/ by default.

import io
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from ..utils.logging import good, info, status, warn

# Windows paths relative to system root
TASKS_PATH = "Windows/System32/Tasks"
DPAPI_SYSTEM_PATH = "Windows/System32/Microsoft/Protect/S-1-5-18/User"
SYSTEM_CREDS_PATH = "Windows/System32/config/systemprofile/AppData/Local/Microsoft/Credentials"
REGISTRY_PATH = "Windows/System32/config"

# GUID pattern for masterkey files
GUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def find_windows_root(mount_path: str) -> Optional[Path]:
    """
    Find the Windows root directory in a mounted filesystem.

    Handles various mount structures:
    - Direct mount: /mnt/vhdx/Windows/...
    - Partition mount: /mnt/vhdx/C/Windows/...
    - Volume mount: /mnt/vhdx/Volume1/Windows/...

    Args:
        mount_path: Path to the mount point

    Returns:
        Path to the Windows root directory, or None if not found
    """
    mount: Path = Path(mount_path)

    # Check if Windows folder exists directly
    if (mount / "Windows").exists():
        return mount

    # Check one level down (partition/volume mounts)
    try:
        for subdir in mount.iterdir():
            if subdir.is_dir() and (subdir / "Windows").exists():
                info(f"Found Windows root at: {subdir}")
                return subdir
    except PermissionError:
        pass

    # Check two levels down (rare but possible)
    try:
        for subdir in mount.iterdir():
            if subdir.is_dir():
                for subsubdir in subdir.iterdir():
                    if subsubdir.is_dir() and (subsubdir / "Windows").exists():
                        info(f"Found Windows root at: {subsubdir}")
                        return subsubdir
    except PermissionError:
        pass

    return None


def get_hostname_from_registry(windows_root: Path, debug: bool = False) -> Optional[str]:
    """
    Attempt to extract hostname from SYSTEM registry hive.

    This is a best-effort attempt - requires python-registry if available.

    Args:
        windows_root: Path to the Windows root directory
        debug: Enable debug output

    Returns:
        Hostname string or None if extraction fails
    """
    system_path = windows_root / "Windows" / "System32" / "config" / "SYSTEM"
    if not system_path.exists():
        return None

    try:
        from Registry import Registry

        reg = Registry.Registry(str(system_path))

        # Find the current control set
        select_key = reg.open("Select")
        current = select_key.value("Current").value()

        # Get the hostname from ControlSet00X\Control\ComputerName\ComputerName
        computer_name_key = reg.open(f"ControlSet00{current}\\Control\\ComputerName\\ComputerName")
        hostname = computer_name_key.value("ComputerName").value()
        return hostname

    except ImportError:
        if debug:
            info("python-registry not installed - cannot extract hostname from registry")
        return None
    except Exception as e:
        if debug:
            info(f"Failed to extract hostname from registry: {e}")
        return None


def extract_dpapi_key_from_registry(windows_root: Path, debug: bool = False) -> Optional[str]:
    """
    Extract DPAPI SYSTEM user key from offline registry hives.

    Uses impacket's secretsdump functionality to extract DPAPI keys from
    the SAM, SYSTEM, and SECURITY registry hives.

    Note: Registry hives are copied to a temp directory because impacket
    requires read-write access, but mounted filesystems are often read-only.

    Args:
        windows_root: Path to the Windows root directory
        debug: Enable debug output

    Returns:
        DPAPI user key as hex string (e.g., "0x1234...") or None if extraction fails
    """
    registry_path = windows_root / REGISTRY_PATH
    system_path = registry_path / "SYSTEM"
    security_path = registry_path / "SECURITY"

    if not system_path.exists():
        if debug:
            info(f"SYSTEM hive not found: {system_path}")
        return None

    if not security_path.exists():
        if debug:
            info(f"SECURITY hive not found: {security_path}")
        return None

    # Copy hives to temp directory (impacket requires read-write access)
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp(prefix="taskhound_registry_")
        temp_system = Path(temp_dir) / "SYSTEM"
        temp_security = Path(temp_dir) / "SECURITY"

        if debug:
            info(f"Copying registry hives to temp directory: {temp_dir}")

        shutil.copy2(system_path, temp_system)
        shutil.copy2(security_path, temp_security)

        from impacket.examples.secretsdump import LocalOperations, LSASecrets

        # Get boot key from SYSTEM hive
        local_ops = LocalOperations(str(temp_system))
        boot_key = local_ops.getBootKey()

        if debug:
            info("Extracted boot key from SYSTEM hive")

        # Capture stdout - LSASecrets.dumpSecrets() prints the keys
        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()

        try:
            lsa_secrets = LSASecrets(str(temp_security), boot_key, isRemote=False)
            lsa_secrets.dumpSecrets()
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()

        # Parse output for DPAPI user key
        dpapi_key = None
        for line in output.split('\n'):
            if 'dpapi_userkey:' in line.lower():
                # Format: dpapi_userkey:0x...
                parts = line.split('dpapi_userkey:', 1)
                if len(parts) >= 2:
                    dpapi_key = parts[1].strip()
                    break

        if dpapi_key:
            good("Extracted DPAPI user key from registry hives")
            return dpapi_key

        if debug:
            info("DPAPI_SYSTEM secret not found in SECURITY hive")
            if output:
                info(f"LSA secrets output: {output[:500]}")
        return None

    except ImportError as e:
        if debug:
            info(f"impacket not available for DPAPI extraction: {e}")
        return None
    except Exception as e:
        if debug:
            info(f"Failed to extract DPAPI key from registry: {e}")
            import traceback
            traceback.print_exc()
        return None
    finally:
        # Clean up temp directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                if debug:
                    info(f"Cleaned up temp directory: {temp_dir}")
            except Exception:
                pass  # Best effort cleanup


def extract_tasks(windows_root: Path, output_dir: Path, verbose: bool = False, debug: bool = False) -> int:
    """
    Extract scheduled task XML files from Windows Tasks directory.

    Creates the expected structure:
        output_dir/Windows/System32/Tasks/...

    Args:
        windows_root: Path to the Windows root directory
        output_dir: Output directory for the backup
        verbose: Enable verbose output
        debug: Enable debug output

    Returns:
        Number of task files extracted
    """
    tasks_source = windows_root / TASKS_PATH
    tasks_dest = output_dir / TASKS_PATH

    if not tasks_source.exists():
        warn(f"Tasks directory not found: {tasks_source}")
        return 0

    count = 0
    skipped = 0

    for root, dirs, files in os.walk(tasks_source):
        # Skip the Microsoft folder by default (system tasks)
        if "Microsoft" in dirs:
            dirs.remove("Microsoft")
            if verbose:
                info("Skipping \\Microsoft folder (system tasks)")

        for file in files:
            src_file = Path(root) / file
            rel_path = src_file.relative_to(tasks_source)
            dst_file = tasks_dest / rel_path

            # Check if it's an XML file (various encodings)
            try:
                with open(src_file, "rb") as f:
                    header = f.read(100)

                    # Check for various XML signatures
                    is_xml = False

                    if b"<?xml" in header or b"<Task" in header:
                        is_xml = True
                    elif header.startswith(b"\xff\xfe") and (
                        b"<\x00T\x00a\x00s\x00k" in header or b"<\x00?\x00x\x00m\x00l" in header
                    ):
                        # UTF-16 LE with <Task or <?xml
                        is_xml = True
                    elif b"\x00<\x00T\x00a\x00s\x00k" in header:
                        # UTF-16 (either endian) with <Task
                        is_xml = True

                    if not is_xml:
                        skipped += 1
                        if debug:
                            info(f"Skipping non-XML: {rel_path}")
                        continue

            except (PermissionError, OSError) as e:
                warn(f"Cannot read {src_file}: {e}")
                continue

            # Copy the task XML
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(src_file, dst_file)
                count += 1
                if verbose:
                    info(f"Extracted: {rel_path}")
            except (PermissionError, OSError) as e:
                warn(f"Failed to copy {src_file}: {e}")

    if debug and skipped > 0:
        info(f"Skipped {skipped} non-XML files in Tasks folder")

    return count


def extract_masterkeys(windows_root: Path, output_dir: Path, verbose: bool = False, debug: bool = False) -> int:
    """
    Extract SYSTEM DPAPI master keys for decrypting task credentials.

    TaskHound expects masterkey files as GUID-named files in:
        output_dir/masterkeys/

    Windows stores SYSTEM masterkeys in:
        Windows/System32/Microsoft/Protect/S-1-5-18/User/<GUID>

    Args:
        windows_root: Path to the Windows root directory
        output_dir: Output directory for the backup
        verbose: Enable verbose output
        debug: Enable debug output

    Returns:
        Number of masterkey files extracted
    """
    dpapi_source = windows_root / DPAPI_SYSTEM_PATH
    masterkeys_dest = output_dir / "masterkeys"
    masterkeys_dest.mkdir(parents=True, exist_ok=True)

    if not dpapi_source.exists():
        # Also check the parent (S-1-5-18) in case User doesn't exist
        alt_path = windows_root / "Windows/System32/Microsoft/Protect/S-1-5-18"
        if alt_path.exists():
            dpapi_source = alt_path
            if verbose:
                info(f"Using alternate DPAPI path: {alt_path}")
        else:
            warn(f"SYSTEM DPAPI directory not found: {dpapi_source}")
            return 0

    if debug:
        info(f"DPAPI source: {dpapi_source}")

    count = 0
    for item in dpapi_source.iterdir():
        if debug:
            info(f"DPAPI item: {item.name} (dir={item.is_dir()}, file={item.is_file()})")

        # Only extract GUID-named files (actual masterkey blobs)
        if item.is_file() and GUID_PATTERN.match(item.name):
            try:
                shutil.copy2(item, masterkeys_dest / item.name)
                count += 1
                if verbose:
                    info(f"Extracted SYSTEM masterkey: {item.name}")
            except (PermissionError, OSError) as e:
                warn(f"Failed to copy {item}: {e}")
        elif item.is_file() and item.name.lower() == "preferred":
            # Also copy the Preferred file (points to current masterkey)
            try:
                shutil.copy2(item, masterkeys_dest / item.name)
                if verbose:
                    info("Extracted Preferred file")
            except (PermissionError, OSError):
                pass  # Not critical

    return count


def extract_credentials(windows_root: Path, output_dir: Path, verbose: bool = False, debug: bool = False) -> int:
    """
    Extract SYSTEM credential files for Task Scheduler stored passwords.

    Task Scheduler credentials are stored in SYSTEM's credential store:
        Windows/System32/config/systemprofile/AppData/Local/Microsoft/Credentials/

    TaskHound expects these in:
        output_dir/credentials/

    Args:
        windows_root: Path to the Windows root directory
        output_dir: Output directory for the backup
        verbose: Enable verbose output
        debug: Enable debug output

    Returns:
        Number of credential files extracted
    """
    system_creds_path = windows_root / SYSTEM_CREDS_PATH
    creds_dest = output_dir / "credentials"
    creds_dest.mkdir(parents=True, exist_ok=True)

    count = 0

    if system_creds_path.exists():
        try:
            for item in system_creds_path.iterdir():
                if item.is_file():
                    shutil.copy2(item, creds_dest / item.name)
                    count += 1
                    if verbose:
                        info(f"Extracted SYSTEM credential: {item.name}")
        except (PermissionError, OSError) as e:
            warn(f"Failed to copy SYSTEM credentials: {e}")
    else:
        if verbose:
            info(f"SYSTEM credentials path not found: {system_creds_path}")

    return count


def load_from_disk(
    mount_path: str,
    backup_dir: Optional[str] = None,
    hostname: Optional[str] = None,
    no_backup: bool = False,
    verbose: bool = False,
    debug: bool = False,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Load tasks and DPAPI data from a mounted Windows filesystem.

    This is the main entry point for --offline-disk mode. It:
    1. Locates the Windows root in the mount
    2. Extracts scheduled tasks, masterkeys, and credentials
    3. Creates a TaskHound-compatible backup structure (unless --no-backup)

    Args:
        mount_path: Path to the mount point (e.g., /mnt/vhdx)
        backup_dir: Output directory for backup (default: ./dpapi_loot)
        hostname: Override hostname detection (default: from registry or mount name)
        no_backup: If True, skip creating backup (ephemeral analysis)
        verbose: Enable verbose output
        debug: Enable debug output

    Returns:
        Tuple of (hostname, backup_path) or (None, None) on failure.
        If no_backup=True, backup_path will be a temp directory.
    """
    # Find Windows root
    windows_root = find_windows_root(mount_path)
    if windows_root is None:
        warn(f"Could not find Windows directory in mount: {mount_path}")
        warn("Make sure the mount contains a Windows/ folder")
        return None, None

    good(f"Found Windows root: {windows_root}")

    # Determine hostname
    if not hostname:
        hostname = get_hostname_from_registry(windows_root, debug)
        if hostname:
            info(f"Detected hostname from registry: {hostname}")
        else:
            # Fall back to mount directory name
            hostname = Path(mount_path).name.upper()
            if hostname in (".", ""):
                hostname = "DISK_IMAGE"
            info(f"Using hostname: {hostname}")

    # Determine output directory
    if no_backup:
        # Create temp directory for ephemeral analysis
        backup_path = Path(tempfile.mkdtemp(prefix=f"taskhound_{hostname}_"))
        info(f"Ephemeral mode: using temp directory {backup_path}")
    else:
        backup_path = Path(backup_dir) / hostname if backup_dir else Path("dpapi_loot") / hostname
        backup_path.mkdir(parents=True, exist_ok=True)
        good(f"Creating backup at: {backup_path}")

    # Extract data
    status(f"Extracting scheduled tasks from {windows_root}...")
    task_count = extract_tasks(windows_root, backup_path, verbose, debug)

    status("Extracting DPAPI masterkeys...")
    masterkey_count = extract_masterkeys(windows_root, backup_path, verbose, debug)

    status("Extracting SYSTEM credentials...")
    credential_count = extract_credentials(windows_root, backup_path, verbose, debug)

    # Summary
    print()
    good(f"Extraction complete for {hostname}:")
    info(f"  Tasks:       {task_count}")
    info(f"  Masterkeys:  {masterkey_count}")
    info(f"  Credentials: {credential_count}")

    if task_count == 0:
        warn("No tasks extracted - nothing to analyze")
        return hostname, str(backup_path)

    # Create metadata file
    if not no_backup:
        metadata_file = backup_path / "extraction_info.txt"
        with open(metadata_file, "w") as f:
            f.write("TaskHound Disk Extraction\n")
            f.write("========================\n\n")
            f.write(f"Source:      {mount_path}\n")
            f.write(f"Windows:     {windows_root}\n")
            f.write(f"Hostname:    {hostname}\n")
            f.write(f"Extracted:   {datetime.now().isoformat()}\n\n")
            f.write(f"Tasks:       {task_count}\n")
            f.write(f"Masterkeys:  {masterkey_count}\n")
            f.write(f"Credentials: {credential_count}\n")

    print()
    return hostname, str(backup_path)
