"""
BloodHound OpenGraph Upload Module

Handles upload of OpenGraph files to BloodHound CE via API.
"""

import time

from ..opengraph.schema import EXTENSION_SCHEMA
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


def _install_schema(authenticator: BloodHoundAuthenticator) -> bool:
    """Install the OpenGraph extension schema (``PUT /api/v2/extensions``, idempotent upsert).

    Declaring the schema is what makes TaskHound's edges traversable in BloodHound v9+
    pathfinding (the ``is_traversable`` flags live in the schema, not the edge payload), and
    must happen *before* the data upload — data ingested before the schema exists stays
    generic until re-uploaded.

    Returns False on pre-v9 servers (the endpoint 404s) or any error, so the caller falls
    back to a generic, Cypher-only upload. ``request()`` returns None on transport/auth
    failure and a real Response (incl. 4xx) otherwise.
    """
    resp = authenticator.request("PUT", "/api/v2/extensions", EXTENSION_SCHEMA)
    if resp is None:
        return False
    if resp.status_code in (200, 201):
        return True
    warn(f"Schema install failed: HTTP {resp.status_code} {resp.text[:200]}")
    return False


def upload_opengraph_batch(
    files: list[str],
    bloodhound_url: str,
    username: str | None = None,
    password: str | None = None,
    api_key: str | None = None,
    api_key_id: str | None = None,
) -> list[bool]:
    """Upload multiple OpenGraph files with a single auth session.

    Authenticates once, installs the v9 extension schema once (so edges are traversable),
    then uploads each file sequentially. Returns a list of success booleans, one per file.
    """
    bloodhound_url = normalize_bloodhound_connector(bloodhound_url, is_legacy=False)

    if not HAS_REQUESTS:
        warn("ERROR: 'requests' library not installed")
        return [False] * len(files)

    authenticator = _authenticate_with_fallback(
        bloodhound_url, username, password, api_key, api_key_id
    )
    if not authenticator:
        return [False] * len(files)

    # Install the extension schema once, before any upload, so edges ingest as traversable
    if _install_schema(authenticator):
        good("Extension schema installed — TaskHound edges are traversable (BH v9+).")
    else:
        warn("Extension schema not installed (pre-v9?); edges will be generic/Cypher-only.")

    results = []
    for og_file in files:
        status("[*] Starting upload, be patient")
        results.append(_upload_file(authenticator, og_file, "OpenGraph"))

    return results


def _authenticate_with_fallback(
    bloodhound_url: str,
    username: str | None = None,
    password: str | None = None,
    api_key: str | None = None,
    api_key_id: str | None = None,
) -> BloodHoundAuthenticator | None:
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
    username: str | None = None,
    password: str | None = None,
    api_key: str | None = None,
    api_key_id: str | None = None,
) -> BloodHoundAuthenticator | None:
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


def _get_alternate_protocol_uri(uri: str) -> str | None:
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
