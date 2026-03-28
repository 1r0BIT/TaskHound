"""
BloodHound OpenGraph Upload Module

Handles upload of OpenGraph files to BloodHound CE via API.
"""

import contextlib
import json
import time
from pathlib import Path
from typing import Optional

from ..utils.bh_auth import BloodHoundAuthenticator
from ..utils.console import spinner
from ..utils.logging import good, info, status, warn

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# HTTP timeout for all requests (seconds)
TIMEOUT = 30


def normalize_bloodhound_connector(connector: str, is_legacy: bool = False) -> str:
    """
    Normalize BloodHound connector URI to include scheme and port.

    Handles various input formats for both BHCE and Legacy:

    BHCE (is_legacy=False):
    - localhost -> http://localhost:8080
    - 192.0.2.54 -> http://192.0.2.54:8080
    - http://localhost -> http://localhost:8080
    - https://bh.domain.com -> https://bh.domain.com:443
    - http://localhost:8080 -> http://localhost:8080 (no change)

    Legacy (is_legacy=True):
    - localhost -> bolt://localhost:7687
    - 192.0.2.54 -> bolt://192.0.2.54:7687
    - bolt://localhost -> bolt://localhost:7687
    - bolt://neo4j.domain.com:7474 -> bolt://neo4j.domain.com:7474 (no change)

    Args:
        connector: BloodHound connector URI in various formats
        is_legacy: True if connecting to Legacy BloodHound (Neo4j), False for BHCE

    Returns:
        Normalized URI with scheme and port
    """
    from urllib.parse import urlparse

    # Parse the connector URI
    parsed = urlparse(connector)

    # If no scheme, assume default based on type
    if not parsed.scheme:
        # Check if it looks like just a hostname or IP
        connector = f"bolt://{connector}" if is_legacy else f"http://{connector}"
        parsed = urlparse(connector)

    # Determine default port based on scheme
    if parsed.scheme == "bolt":
        default_port = 7687
    elif parsed.scheme == "https":
        default_port = 443
    else:  # http
        default_port = 8080

    # If port is already specified, use it
    port = parsed.port or default_port

    # Reconstruct URI with explicit port
    netloc = parsed.hostname or parsed.netloc
    normalized = f"{parsed.scheme}://{netloc}:{port}"

    return normalized


def extract_host_from_connector(connector: str) -> str:
    """
    Extract just the hostname/IP from a connector URI.

    Used for legacy connectors that need just the hostname.

    Args:
        connector: Full connector URI (e.g., "bolt://localhost:7687", "http://bh.example.com:8080")

    Returns:
        Just the hostname/IP (e.g., "localhost", "bh.example.com")
    """
    from urllib.parse import urlparse

    parsed = urlparse(connector)

    # If no scheme was provided, the hostname might be in netloc or path
    if parsed.hostname:
        return parsed.hostname
    elif parsed.netloc:
        # Handle case like "192.168.1.1:8080" without scheme
        return parsed.netloc.split(":")[0]
    else:
        # Fallback: assume the whole thing is a hostname
        return connector.split(":")[0]


def find_model_json() -> Path:
    """
    Find model.json in multiple possible locations.

    Search order:
    1. config/model.json (primary - new location)
    2. ~/.config/taskhound/model.json (XDG standard - Linux/macOS)
    3. ~/.taskhound/model.json (legacy location)
    4. Current working directory (last resort with warning)

    Returns:
        Path to model.json

    Raises:
        FileNotFoundError: If model.json is not found in any location
    """
    search_paths = [
        # 1. Project config directory (relative to this file or CWD)
        Path(__file__).parent.parent.parent / "config" / "model.json",
        Path.cwd() / "config" / "model.json",
        # 2. User config directory (XDG standard for Linux/macOS)
        Path.home() / ".config" / "taskhound" / "model.json",
        # 3. Legacy home directory location
        Path.home() / ".taskhound" / "model.json",
        # 4. Current working directory (last resort)
        Path.cwd() / "model.json",
    ]

    for path in search_paths:
        if path.exists():
            # Warn if using CWD (security concern)
            if path == Path.cwd() / "model.json":
                warn("WARNING: Using model.json from current directory")
                warn("This can be a security risk - consider moving to config/model.json")
            return path

    # None found - provide helpful error message
    raise FileNotFoundError(
        "model.json not found. Searched locations:\n"
        + "\n".join(f"  - {p}" for p in search_paths)
        + "\n\nCreate config/model.json in your project directory or ~/.config/taskhound/model.json"
    )


def upload_opengraph_to_bloodhound(
    opengraph_file: str,
    bloodhound_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    api_key_id: Optional[str] = None,
    set_icon: bool = False,
    force_icon: bool = False,
    icon_name: str = "clock",
    icon_color: str = "#8B5CF6",
) -> bool:
    """
    Upload OpenGraph file to BloodHound Community Edition.

    Supports automatic protocol fallback - if http:// fails, tries https:// and vice versa.

    Args:
        opengraph_file: Path to the OpenGraph JSON file (contains both nodes and edges)
        bloodhound_url: BloodHound connector URI (various formats supported)
        username: BloodHound username (not needed if api_key/api_key_id provided)
        password: BloodHound password (not needed if api_key/api_key_id provided)
        api_key: BloodHound API key for HMAC authentication (requires api_key_id)
        api_key_id: BloodHound API key ID for HMAC authentication (requires api_key)
        set_icon: Whether to set custom icon for ScheduledTask nodes
        force_icon: Force icon update even if already exists (requires set_icon=True)
        icon_name: Icon name (if set_icon=True)
        icon_color: Icon color in hex format (if set_icon=True)

    Returns:
        True if upload succeeded, False otherwise
    """
    # Normalize URL to include scheme and port (BHCE only)
    bloodhound_url = normalize_bloodhound_connector(bloodhound_url, is_legacy=False)

    if not HAS_REQUESTS:
        warn("ERROR: 'requests' library not installed")
        warn("Install with: pip install requests")
        return False

    # Try to authenticate, with protocol fallback
    authenticator = _authenticate_with_fallback(
        bloodhound_url, username, password, api_key, api_key_id
    )

    if not authenticator:
        return False

    # Set custom icon if requested
    if set_icon:
        _set_custom_icon(authenticator, icon_name, icon_color, force_icon)

    # Upload the OpenGraph file
    status("[*] Starting upload, be patient")
    success = _upload_file(authenticator, opengraph_file, "OpenGraph")

    return success


def _authenticate_with_fallback(
    bloodhound_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    api_key_id: Optional[str] = None,
) -> Optional[BloodHoundAuthenticator]:
    """
    Authenticate to BloodHound with automatic protocol fallback.

    If http:// fails, tries https:// and vice versa.

    Args:
        bloodhound_url: Normalized BloodHound URL
        username: BloodHound username
        password: BloodHound password
        api_key: BloodHound API key
        api_key_id: BloodHound API key ID

    Returns:
        Authenticated BloodHoundAuthenticator or None if both protocols fail
    """
    # Try primary URL
    authenticator = _try_authenticate(bloodhound_url, username, password, api_key, api_key_id)
    if authenticator:
        return authenticator

    # Try alternate protocol
    alt_url = _get_alternate_protocol_uri(bloodhound_url)
    if alt_url:
        original_scheme = "https" if bloodhound_url.startswith("https://") else "http"
        alt_scheme = "http" if original_scheme == "https" else "https"
        warn(f"Connection failed with {original_scheme}://, trying {alt_scheme}://...")

        authenticator = _try_authenticate(alt_url, username, password, api_key, api_key_id)
        if authenticator:
            status(f"[+] Successfully connected using {alt_scheme}://")
            return authenticator

    return None


def _try_authenticate(
    url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    api_key_id: Optional[str] = None,
) -> Optional[BloodHoundAuthenticator]:
    """
    Try to authenticate to BloodHound at a specific URL.

    Returns:
        Authenticated BloodHoundAuthenticator or None if authentication fails
    """
    try:
        authenticator = BloodHoundAuthenticator(
            base_url=url,
            username=username,
            password=password,
            api_key=api_key,
            api_key_id=api_key_id,
            timeout=TIMEOUT,
        )

        # Test authentication
        if api_key and api_key_id:
            info(f"Using API key authentication for BloodHound at {url}")
            if not authenticator.request("GET", "/api/version"):
                return None
        else:
            if not authenticator.get_token():
                return None
            good(f"Authenticated to BloodHound at {url}")

        return authenticator

    except Exception as e:
        warn(f"Unexpected authentication error: {e}")
        return None


def _get_alternate_protocol_uri(uri: str) -> Optional[str]:
    """
    Get the alternate protocol URI (http <-> https).

    Only swaps the protocol, keeps the same port.

    Args:
        uri: Original URI (e.g., "http://localhost:8080")

    Returns:
        URI with alternate protocol, or None if not applicable
    """
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(uri)

    if parsed.scheme == "http":
        # http -> https (keep same port)
        new_netloc = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname
        return urlunparse(("https", new_netloc, parsed.path, "", "", ""))
    elif parsed.scheme == "https":
        # https -> http (keep same port)
        new_netloc = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname
        return urlunparse(("http", new_netloc, parsed.path, "", "", ""))

    return None


def _wait_for_job_completion(
    authenticator: BloodHoundAuthenticator,
    job_id: int,
    max_wait_time: int = 300,  # 5 minutes
    initial_delay: float = 1.0,
    max_delay: float = 10.0,
) -> bool:
    """
    Poll BloodHound for job completion with exponential backoff.

    Args:
        authenticator: Authenticated BloodHound connection helper
        job_id: Upload job ID to check
        max_wait_time: Maximum time to wait for job completion (seconds)
        initial_delay: Initial delay between polls (will increase exponentially)
        max_delay: Maximum delay between polls (seconds)

    Returns:
        True if job completed successfully, False otherwise
    """
    retry_delay = initial_delay
    max_retries = int(max_wait_time / initial_delay)  # Calculate max retries from wait time

    for attempt in range(max_retries):
        time.sleep(retry_delay)

        try:
            status_response = authenticator.request("GET", "/api/v2/file-upload?skip=0&limit=100")
            if not status_response:
                warn("Failed to get job status")
                continue

            status_response.raise_for_status()

            jobs = status_response.json().get("data", [])
            job_found = False
            for job in jobs:
                if job["id"] == job_id:
                    job_found = True
                    job_status = job.get("status", "")

                    # BloodHound API returns integer status codes, not strings
                    # Map known status codes to readable names
                    status_map = {
                        0: "running",
                        1: "completed",
                        2: "completed",  # success/completed
                        3: "failed",
                        4: "canceled",
                        5: "failed",  # timeout/all files failed
                        6: "ingesting",  # Still processing
                        7: "analyzing",  # Still processing
                    }

                    # Convert integer status to string
                    if isinstance(job_status, int):
                        status_name = status_map.get(job_status, f"unknown_{job_status}")
                    else:
                        status_name = str(job_status).lower() if job_status else "unknown"

                    if status_name in ["completed", "success"] or job_status == 2:
                        # Check for failed files
                        failed = job.get("failed_files_count", job.get("failed_files", 0))
                        if failed == 0:
                            status(f"[+] Data uploaded (Job {job_id})")
                            return True
                        else:
                            warn(f"Job {job_id} completed with {failed} failed files")
                            # Try to get error details
                            if "errors" in job:
                                for error in job["errors"][:3]:  # Show first 3 errors
                                    warn(f"  Error: {error}")
                            return False

                    elif status_name in ["failed", "error"] or job_status in [3, 4, 5]:
                        # Status 3 = failed, 4 = canceled, 5 = timeout/all files failed
                        error_msg = job.get("status_message", job.get("error", "Unknown error"))
                        warn(f"Job {job_id} failed: {error_msg}")
                        return False

                    elif status_name in ["running", "ingesting", "analyzing"] or job_status in [0, 6, 7]:
                        # Still processing, continue polling
                        info(f"Job {job_id} status: {status_name} (attempt {attempt + 1}/{max_retries})")
                        break

                    else:
                        # Unknown status - log but don't fail immediately
                        info(
                            f"Job {job_id} status: {job_status} ({status_name}) (attempt {attempt + 1}/{max_retries})"
                        )
                        # Continue polling in case it transitions to a known state

                    break

            if not job_found:
                info(f"Job {job_id} not found in recent jobs list (attempt {attempt + 1}/{max_retries})")

        except requests.Timeout:
            warn(f"Timeout checking job status (attempt {attempt + 1}/{max_retries})")
        except requests.RequestException as e:
            warn(f"Error checking job status (attempt {attempt + 1}/{max_retries}): {e}")

        # Exponential backoff, cap at 10 seconds
        retry_delay = min(retry_delay * 1.5, 10.0)

    warn(f"Timeout waiting for job {job_id} after {max_retries} attempts")
    return False


def _upload_file(
    authenticator: BloodHoundAuthenticator,
    file_path: str,
    file_type: str,
) -> bool:
    """
    Upload a single file to BloodHound with proper error handling and job polling.

    Args:
        authenticator: Authenticated BloodHound connection helper
        file_path: Path to file to upload
        file_type: Description of file type for logging

    Returns:
        True if upload and processing succeeded, False otherwise
    """
    try:
        # Start upload job
        job_response = authenticator.request("POST", "/api/v2/file-upload/start", {})
        if not job_response:
            warn("Failed to start upload job")
            return False

        job_response.raise_for_status()
        job_id = job_response.json()["data"]["id"]
        info(f"Started upload job {job_id}")

        # Upload file
        with open(file_path) as f:
            file_data = f.read()

        # Use spinner for the upload and processing (indeterminate duration)
        with spinner(f"Uploading {file_type} data ({len(file_data)} bytes)"):
            # For file upload, we need to be careful with Content-Type if using Bearer token
            # The authenticator handles JSON body encoding, but here we are sending raw bytes (JSON string)
            # The API expects application/json

            upload_response = authenticator.request(
                "POST",
                f"/api/v2/file-upload/{job_id}",
                body=file_data.encode(),
                headers={"Content-Type": "application/json"}
            )

            if not upload_response:
                warn("Failed to upload file content")
                return False

            upload_response.raise_for_status()

            # End job
            end_response = authenticator.request("POST", f"/api/v2/file-upload/{job_id}/end")
            if not end_response:
                warn("Failed to end upload job")
                return False

            end_response.raise_for_status()

            # Wait for processing with exponential backoff
            return _wait_for_job_completion(authenticator, job_id)

    except requests.Timeout:
        warn(f"Timeout uploading {file_type} file (request took longer than {TIMEOUT}s)")
        return False
    except requests.RequestException as e:
        warn(f"Network error uploading {file_type} file: {e}")
        return False
    except FileNotFoundError:
        warn(f"File not found: {file_path}")
        return False
    except Exception as e:
        warn(f"Unexpected error uploading {file_type} file: {e}")
        return False


def _set_custom_icon(
    authenticator: BloodHoundAuthenticator,
    icon_name: str,
    icon_color: str,
    force: bool,
) -> None:
    """
    Set custom icon for ScheduledTask nodes in BloodHound CE.

    Args:
        authenticator: Authenticated BloodHound connection helper
        icon_name: Font Awesome icon name
        icon_color: Hex color code
        force: If True, delete existing icon before creating new one
    """
    try:
        # First, check if icon already exists
        check_response = authenticator.request("GET", "/api/v2/custom-nodes")

        if check_response and check_response.status_code == 200:
            response_data = check_response.json()
            existing = response_data.get("data") if response_data else None

            if existing:
                for node in existing:
                    # Case-insensitive check for scheduledtask kind
                    kind_name = node.get("kindName", "").lower()
                    if kind_name == "scheduledtask":
                        node_id = node.get("id")
                        existing_icon = node.get("config", {}).get("icon", {})

                        # Check if icon matches what we want
                        if existing_icon.get("name") == icon_name and existing_icon.get("color") == icon_color:
                            info(f"scheduledtask icon already configured ({icon_name}, {icon_color})")
                            return

                        # Icon exists but is different
                        if force:
                            # Delete existing icon configuration
                            info("scheduledtask icon exists with different settings - forcing update")
                            info(f"Current: {existing_icon.get('name')} {existing_icon.get('color')}")
                            info(f"Requested: {icon_name} {icon_color}")
                            info("Deleting existing icon configuration...")

                            try:
                                delete_response = authenticator.request("DELETE", f"/api/v2/custom-nodes/{node_id}")

                                if delete_response and delete_response.status_code in [200, 204]:
                                    good("Deleted existing icon configuration")
                                else:
                                    status_code = delete_response.status_code if delete_response else "Unknown"
                                    warn(f"Failed to delete icon (status {status_code})")
                                    warn("Will attempt to create new icon anyway...")
                            except requests.Timeout:
                                warn(f"Timeout deleting icon (request took longer than {TIMEOUT}s)")
                                warn("Will attempt to create new icon anyway...")
                            except Exception as e:
                                warn(f"Error deleting icon: {e}")
                                warn("Will attempt to create new icon anyway...")
                        else:
                            info("ScheduledTask icon exists but with different settings")
                            info(f"Current: {existing_icon.get('name')} {existing_icon.get('color')}")
                            info(f"Requested: {icon_name} {icon_color}")
                            info("Keeping existing configuration (use --bh-force-icon to override)")
                            return

        # Icon doesn't exist (or was just deleted), upload model.json file
        # Find model.json in standard locations
        try:
            model_file = find_model_json()
            info(f"Loading icon configuration from: {model_file}")
        except FileNotFoundError as e:
            warn(f"{e}")
            # Fallback to hardcoded structure
            model_data = {
                "custom_types": {
                    "ScheduledTask": {"icon": {"type": "font-awesome", "name": icon_name, "color": icon_color}},
                    "WindowsService": {"icon": {"type": "font-awesome", "name": "gears", "color": "#06B6D4"}},
                }
            }
        else:
            # Load model.json (NetworkHound approach)
            with open(model_file, encoding="utf-8") as f:
                model_data = json.load(f)

        response = authenticator.request("POST", "/api/v2/custom-nodes", model_data)

        if response and response.status_code in [200, 201]:
            good(f"Custom icon set for 'ScheduledTask': {icon_name} ({icon_color})")
        elif response and response.status_code == 409:
            info("ScheduledTask icon already configured")
        else:
            # Non-critical error - print response for debugging
            status_code = response.status_code if response else "Unknown"
            warn(f"Could not set custom icon (status {status_code})")
            with contextlib.suppress(Exception):
                if response:
                    warn(f"Response: {response.text}")

    except requests.Timeout:
        warn(f"Timeout setting custom icon (request took longer than {TIMEOUT}s) (non-critical)")
    except Exception as e:
        # Non-critical - don't fail the whole upload
        warn(f"Failed to set custom icon: {e} (non-critical)")
