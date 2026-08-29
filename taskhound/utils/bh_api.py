import base64
import datetime
import hashlib
import hmac
from datetime import UTC

import requests


def bhce_signed_request(
    method: str, uri: str, base_url: str, api_key: str, api_key_id: str, body: bytes | None = None, timeout: int = 30
) -> requests.Response:
    """
    Make a signed request to BloodHound CE API using HMAC-SHA256 authentication.

    According to BloodHound CE API documentation, API key authentication uses
    hash-based message authentication code (HMAC) with the following signature chain:
    1. OperationKey: HMAC(api_key, method + uri)
    2. DateKey: HMAC(OperationKey, RFC3339_datetime[:13])  # truncated to hour
    3. Signature: HMAC(DateKey, body)  # body can be empty

    Args:
        method: HTTP method (GET, POST, etc.)
        uri: API endpoint path (e.g., '/api/version')
        base_url: Base URL of BloodHound CE instance
        api_key: API key for HMAC signing
        api_key_id: API key ID for Authorization header
        body: Optional request body as bytes
        timeout: Request timeout in seconds

    Returns:
        requests.Response object
    """
    # Initialize HMAC digester with API key as secret
    digester = hmac.new(api_key.encode(), None, hashlib.sha256)

    # OperationKey: HMAC digest of method + URI (no delimiter)
    digester.update(f"{method}{uri}".encode())
    digester = hmac.new(digester.digest(), None, hashlib.sha256)

    # DateKey: HMAC digest of RFC3339 datetime truncated to hour
    datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
    digester.update(datetime_formatted[:13].encode())
    digester = hmac.new(digester.digest(), None, hashlib.sha256)

    # Body signing: HMAC digest of request body (or empty)
    if body is not None:
        digester.update(body)

    # Build headers with HMAC signature
    headers = {
        "Authorization": f"bhesignature {api_key_id}",
        "RequestDate": datetime_formatted,
        "Signature": base64.b64encode(digester.digest()).decode(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # Make the signed request
    return requests.request(method=method, url=f"{base_url}{uri}", headers=headers, data=body, timeout=timeout)


def get_bloodhound_token(base_url: str, username: str, password: str, timeout: int = 30) -> str:
    """
    Get session token from BloodHound CE.
    Raises requests.RequestException or ValueError on failure.
    """
    response = requests.post(
        f"{base_url}/api/v2/login",
        json={"login_method": "secret", "secret": password, "username": username},
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    if "data" not in data or "session_token" not in data["data"]:
        raise ValueError("Invalid response format: missing session_token")
    return data["data"]["session_token"]


def enumerate_computers_from_bloodhound(
    base_url: str,
    token: str,
    timeout: int = 30,
) -> list[dict]:
    """
    Enumerate all computer objects from BloodHound CE with full properties.

    Uses the cypher endpoint with include_properties=true to get all computer
    attributes in a single efficient query.

    Args:
        base_url: BloodHound CE base URL (e.g., "http://localhost:8080")
        token: JWT session token from get_bloodhound_token()
        timeout: Request timeout in seconds

    Returns:
        List of computer dicts with properties:
        - name: FQDN (e.g., "SERVER01.DOMAIN.COM")
        - objectid: SID
        - enabled: bool
        - pwdlastset: Unix timestamp (int)
        - operatingsystem: OS string (e.g., "WINDOWS SERVER 2019 DATACENTER")
        - lastlogontimestamp: Unix timestamp (int)
        - lastseen: ISO timestamp of last BH collection
        - distinguishedname: Full DN
        - samaccountname: SAM name with $ suffix

    Raises:
        requests.RequestException: On network/HTTP errors
        ValueError: On invalid response format
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        f"{base_url}/api/v2/graphs/cypher",
        json={
            "query": "MATCH (c:Computer) RETURN c",
            "include_properties": True,
        },
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()

    data = response.json()
    if "data" not in data or "nodes" not in data["data"]:
        raise ValueError("Invalid response format: missing nodes data")

    computers = []
    for node in data["data"]["nodes"].values():
        props = node.get("properties", {})
        computers.append({
            "name": props.get("name", ""),
            "objectid": props.get("objectid", ""),
            "enabled": props.get("enabled"),
            "pwdlastset": props.get("pwdlastset"),
            "operatingsystem": props.get("operatingsystem", ""),
            "lastlogontimestamp": props.get("lastlogontimestamp"),
            "lastseen": props.get("lastseen", ""),
            "lastcollected": props.get("lastcollected", ""),
            "distinguishedname": props.get("distinguishedname", ""),
            "samaccountname": props.get("samaccountname", ""),
        })

    return computers


def get_bloodhound_data_age(computers: list[dict]) -> tuple[int, str]:
    """
    Calculate the age of BloodHound data based on lastseen/lastcollected timestamps.

    Args:
        computers: List of computer dicts from enumerate_computers_from_bloodhound()

    Returns:
        Tuple of (days_old: int, newest_timestamp: str)
        Returns (0, "") if no valid timestamps found
    """
    from datetime import datetime

    newest_ts = None
    newest_str = ""

    for comp in computers:
        for field in ("lastseen", "lastcollected"):
            ts_str = comp.get(field, "")
            if not ts_str:
                continue
            try:
                # Parse ISO timestamp (e.g., "2025-12-18T14:27:00.320042793Z")
                # Handle nanoseconds by truncating to microseconds
                if "." in ts_str:
                    base, frac = ts_str.rsplit(".", 1)
                    # Remove timezone suffix, keep max 6 digits for microseconds
                    frac_digits = "".join(c for c in frac if c.isdigit())[:6]
                    tz_suffix = "".join(c for c in frac if not c.isdigit())
                    ts_str = f"{base}.{frac_digits}{tz_suffix}"
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if newest_ts is None or ts > newest_ts:
                    newest_ts = ts
                    newest_str = comp.get(field, "")
            except (ValueError, TypeError):
                continue

    if newest_ts is None:
        return 0, ""

    now = datetime.now(UTC)
    age_days = (now - newest_ts).days
    return age_days, newest_str
