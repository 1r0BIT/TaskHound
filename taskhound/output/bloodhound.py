"""
BloodHound OpenGraph Upload Module

Handles upload of OpenGraph files to BloodHound CE via API.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

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
        if is_legacy:
            connector = f"bolt://{connector}"
        else:
            connector = f"http://{connector}"
        parsed = urlparse(connector)
    
    # Determine default port based on scheme
    if parsed.scheme == 'bolt':
        default_port = 7687
    elif parsed.scheme == 'https':
        default_port = 443
    else:  # http
        default_port = 8080
    
    # If port is already specified, use it
    if parsed.port:
        port = parsed.port
    else:
        port = default_port
    
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
        return parsed.netloc.split(':')[0]
    else:
        # Fallback: assume the whole thing is a hostname
        return connector.split(':')[0]


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
                print("[!] WARNING: Using model.json from current directory")
                print("[!] This can be a security risk - consider moving to config/model.json")
            return path
    
    # None found - provide helpful error message
    raise FileNotFoundError(
        "model.json not found. Searched locations:\n" +
        "\n".join(f"  - {p}" for p in search_paths) +
        "\n\nCreate config/model.json in your project directory or ~/.config/taskhound/model.json"
    )


def upload_opengraph_to_bloodhound(
    opengraph_file: str,
    bloodhound_url: str,
    username: str,
    password: str,
    set_icon: bool = False,
    force_icon: bool = False,
    icon_name: str = "heart",
    icon_color: str = "#8B5CF6"
) -> bool:
    """
    Upload OpenGraph file to BloodHound Community Edition.
    
    Args:
        opengraph_file: Path to the OpenGraph JSON file (contains both nodes and edges)
        bloodhound_url: BloodHound connector URI (various formats supported)
        username: BloodHound username
        password: BloodHound password
        set_icon: Whether to set custom icon for ScheduledTask nodes
        force_icon: Force icon update even if already exists (requires set_icon=True)
        icon_name: Icon name (if set_icon=True)
        icon_color: Icon color in hex format (if set_icon=True)
        set_icon: Whether to set custom icon for ScheduledTask nodes
        icon_name: Icon name (if set_icon=True)
        icon_color: Icon color in hex format (if set_icon=True)
        
    Returns:
        True if upload succeeded, False otherwise
    """
    # Normalize URL to include scheme and port (BHCE only)
    bloodhound_url = normalize_bloodhound_connector(bloodhound_url, is_legacy=False)
    
    if not HAS_REQUESTS:
        print("[!] ERROR: 'requests' library not installed")
        print("[!] Install with: pip install requests")
        return False
    
    # Authenticate
    try:
        login_response = requests.post(
            f"{bloodhound_url}/api/v2/login",
            json={"login_method": "secret", "secret": password, "username": username},
            timeout=TIMEOUT
        )
        
        if login_response.status_code != 200:
            print(f"[!] BloodHound authentication failed - HTTP {login_response.status_code}")
            return False
        
        token = login_response.json()["data"]["session_token"]
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        print(f"[+] Authenticated to BloodHound at {bloodhound_url}")
    except requests.Timeout:
        print(f"[!] Timeout authenticating to BloodHound (request took longer than {TIMEOUT}s)")
        return False
    except requests.RequestException as e:
        print(f"[!] Network error during authentication: {e}")
        return False
    except (KeyError, ValueError) as e:
        print(f"[!] Invalid authentication response from BloodHound: {e}")
        return False
    except Exception as e:
        print(f"[!] Unexpected authentication error: {e}")
        return False
    
    # Set custom icon if requested
    if set_icon:
        _set_custom_icon(bloodhound_url, headers, icon_name, icon_color, force_icon)
    
    # Upload the OpenGraph file
    print(f"[*] Uploading OpenGraph data...")
    success = _upload_file(bloodhound_url, headers, opengraph_file, "OpenGraph")
    
    return success


def _wait_for_job_completion(
    bloodhound_url: str,
    headers: Dict,
    job_id: int,
    max_retries: int = 10,
    initial_delay: float = 1.0
) -> bool:
    """
    Poll BloodHound for job completion with exponential backoff.
    
    Args:
        bloodhound_url: BloodHound base URL
        headers: Authentication headers
        job_id: Upload job ID to check
        max_retries: Maximum number of polling attempts
        initial_delay: Initial delay between polls (will increase exponentially)
        
    Returns:
        True if job completed successfully, False otherwise
    """
    retry_delay = initial_delay
    
    for attempt in range(max_retries):
        time.sleep(retry_delay)
        
        try:
            status_response = requests.get(
                f"{bloodhound_url}/api/v2/file-upload?skip=0&limit=20",
                headers=headers,
                timeout=TIMEOUT
            )
            status_response.raise_for_status()
            
            jobs = status_response.json().get("data", [])
            for job in jobs:
                if job["id"] == job_id:
                    status = job.get("status", "")
                    
                    # BloodHound API returns integer status codes, not strings
                    # Map known status codes to readable names
                    status_map = {
                        0: "running",
                        1: "completed",
                        2: "completed",  # success/completed
                        3: "failed",
                        4: "canceled",
                        5: "timeout",
                        6: "ingesting",  # Still processing
                        7: "analyzing",  # Still processing
                    }
                    
                    # Convert integer status to string
                    if isinstance(status, int):
                        status_name = status_map.get(status, f"unknown_{status}")
                    else:
                        status_name = str(status).lower() if status else "unknown"
                    
                    if status_name in ["completed", "success"] or status == 2:
                        # Check for failed files
                        failed = job.get("failed_files_count", job.get("failed_files", 0))
                        if failed == 0:
                            print(f"[+] Upload job {job_id} completed successfully")
                            return True
                        else:
                            print(f"[!] Job {job_id} completed with {failed} failed files")
                            # Try to get error details
                            if "errors" in job:
                                for error in job["errors"][:3]:  # Show first 3 errors
                                    print(f"[!]   Error: {error}")
                            return False
                    
                    elif status_name in ["failed", "error"] or status == 3:
                        error_msg = job.get("error", "Unknown error")
                        print(f"[!] Job {job_id} failed: {error_msg}")
                        return False
                    
                    elif status_name in ["running", "ingesting", "analyzing"] or status in [0, 6, 7]:
                        # Still processing, continue polling
                        print(f"[*] Job {job_id} status: {status_name} (attempt {attempt+1}/{max_retries})")
                        break
                    
                    else:
                        # Unknown status - log but don't fail immediately
                        print(f"[*] Job {job_id} status: {status} ({status_name}) (attempt {attempt+1}/{max_retries})")
                        # Continue polling in case it transitions to a known state
                    
                    break
            
        except requests.Timeout:
            print(f"[!] Timeout checking job status (attempt {attempt+1}/{max_retries})")
        except requests.RequestException as e:
            print(f"[!] Error checking job status (attempt {attempt+1}/{max_retries}): {e}")
        
        # Exponential backoff, cap at 10 seconds
        retry_delay = min(retry_delay * 1.5, 10.0)
    
    print(f"[!] Timeout waiting for job {job_id} after {max_retries} attempts")
    return False


def _upload_file(bloodhound_url: str, headers: Dict, file_path: str, file_type: str) -> bool:
    """
    Upload a single file to BloodHound with proper error handling and job polling.
    
    Args:
        bloodhound_url: BloodHound base URL
        headers: Authentication headers
        file_path: Path to file to upload
        file_type: Description of file type for logging
        
    Returns:
        True if upload and processing succeeded, False otherwise
    """
    try:
        # Start upload job
        job_response = requests.post(
            f"{bloodhound_url}/api/v2/file-upload/start",
            headers=headers,
            json={},
            timeout=TIMEOUT
        )
        job_response.raise_for_status()
        job_id = job_response.json()["data"]["id"]
        print(f"[*] Started upload job {job_id}")
        
        # Upload file
        with open(file_path, "r") as f:
            file_data = f.read()
        
        print(f"[*] Uploading {file_type} data ({len(file_data)} bytes)...")
        upload_response = requests.post(
            f"{bloodhound_url}/api/v2/file-upload/{job_id}",
            headers={**headers, "Content-Type": "application/json"},
            data=file_data,
            timeout=TIMEOUT
        )
        upload_response.raise_for_status()
        
        # End job
        end_response = requests.post(
            f"{bloodhound_url}/api/v2/file-upload/{job_id}/end",
            headers=headers,
            timeout=TIMEOUT
        )
        end_response.raise_for_status()
        
        # Wait for processing with exponential backoff
        print(f"[*] Waiting for BloodHound to process the upload...")
        return _wait_for_job_completion(bloodhound_url, headers, job_id)
        
    except requests.Timeout:
        print(f"[!] Timeout uploading {file_type} file (request took longer than {TIMEOUT}s)")
        return False
    except requests.RequestException as e:
        print(f"[!] Network error uploading {file_type} file: {e}")
        return False
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error uploading {file_type} file: {e}")
        return False


def _set_custom_icon(bloodhound_url: str, headers: Dict, icon_name: str, icon_color: str, force: bool = False):
    """
    Set custom icon for ScheduledTask nodes by uploading model.json.
    
    Args:
        bloodhound_url: BloodHound base URL
        headers: Authentication headers
        icon_name: Font Awesome icon name
        icon_color: Hex color code
        force: If True, delete existing icon before creating new one
    """
    import json
    from pathlib import Path
    
    try:
        # First, check if icon already exists
        check_response = requests.get(
            f"{bloodhound_url}/api/v2/custom-nodes",
            headers=headers,
            timeout=TIMEOUT
        )
        
        if check_response.status_code == 200:
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
                            print(f"[*] scheduledtask icon already configured ({icon_name}, {icon_color})")
                            return
                        
                        # Icon exists but is different
                        if force:
                            # Delete existing icon configuration
                            print(f"[*] scheduledtask icon exists with different settings - forcing update")
                            print(f"[*] Current: {existing_icon.get('name')} {existing_icon.get('color')}")
                            print(f"[*] Requested: {icon_name} {icon_color}")
                            print(f"[*] Deleting existing icon configuration...")
                            
                            try:
                                delete_response = requests.delete(
                                    f"{bloodhound_url}/api/v2/custom-nodes/{node_id}",
                                    headers=headers,
                                    timeout=TIMEOUT
                                )
                                
                                if delete_response.status_code in [200, 204]:
                                    print(f"[+] Deleted existing icon configuration")
                                else:
                                    print(f"[!] Failed to delete icon (status {delete_response.status_code})")
                                    print(f"[!] Will attempt to create new icon anyway...")
                            except requests.Timeout:
                                print(f"[!] Timeout deleting icon (request took longer than {TIMEOUT}s)")
                                print(f"[!] Will attempt to create new icon anyway...")
                            except Exception as e:
                                print(f"[!] Error deleting icon: {e}")
                                print(f"[!] Will attempt to create new icon anyway...")
                        else:
                            print(f"[*] scheduledtask icon exists but with different settings")
                            print(f"[*] Current: {existing_icon.get('name')} {existing_icon.get('color')}")
                            print(f"[*] Requested: {icon_name} {icon_color}")
                            print(f"[*] Keeping existing configuration (use --bh-force-icon to override)")
                            return
        
        # Icon doesn't exist (or was just deleted), upload model.json file
        # Find model.json in standard locations
        try:
            model_file = find_model_json()
            print(f"[*] Loading icon configuration from: {model_file}")
        except FileNotFoundError as e:
            print(f"[!] {e}")
            # Fallback to hardcoded structure
            model_data = {
                "custom_types": {
                    "scheduledtask": {
                        "icon": {
                            "type": "font-awesome",
                            "name": icon_name,
                            "color": icon_color
                        }
                    }
                }
            }
        else:
            # Load model.json (NetworkHound approach)
            with open(model_file, 'r', encoding='utf-8') as f:
                model_data = json.load(f)
        
        response = requests.post(
            f"{bloodhound_url}/api/v2/custom-nodes",
            headers={**headers, "Content-Type": "application/json"},
            json=model_data,
            timeout=TIMEOUT
        )
        
        if response.status_code in [200, 201]:
            print(f"[+] Custom icon set for 'scheduledtask': {icon_name} ({icon_color})")
        elif response.status_code == 409:
            print(f"[*] scheduledtask icon already configured")
        else:
            # Non-critical error - print response for debugging
            print(f"[!] Could not set custom icon (status {response.status_code})")
            try:
                print(f"[!] Response: {response.text}")
            except:
                pass
            
    except requests.Timeout:
        print(f"[!] Timeout setting custom icon (request took longer than {TIMEOUT}s) (non-critical)")
    except Exception as e:
        # Non-critical - don't fail the whole upload
        print(f"[!] Failed to set custom icon: {e} (non-critical)")
