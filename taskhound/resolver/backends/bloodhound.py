# BloodHound Backend
#
# Resolution via BloodHound offline data and live API queries.


from ...parsers.highvalue import HighValueLoader
from ...utils.logging import debug, info


def resolve_sid_from_bloodhound(sid: str, hv_loader: HighValueLoader | None) -> str | None:
    """
    Resolve SID to username using BloodHound offline data.

    Args:
        sid: Windows SID to resolve
        hv_loader: Loaded BloodHound data (can be None)

    Returns:
        Username if found in BloodHound data, None otherwise
    """
    if not hv_loader or not hv_loader.loaded:
        return None

    # Check if SID exists in BloodHound data
    user_data = hv_loader.hv_sids.get(sid)
    if user_data:
        # Try to get samaccountname or name
        username = user_data.get("samaccountname") or user_data.get("name")
        if username:
            info(f"Resolved SID {sid} to {username} via BloodHound data")
            return username.strip().strip('"')

    return None


def resolve_sid_via_bloodhound_api(sid: str, bh_connector) -> str | None:
    """
    Resolve SID to username using live BloodHound API queries.

    This extends offline BloodHound data by querying the live database for SIDs
    that may exist in BloodHound but weren't in the offline export.

    Args:
        sid: Windows SID to resolve
        bh_connector: BloodHoundConnector instance with active connection

    Returns:
        Username if found via BloodHound API, None otherwise
    """
    if not bh_connector:
        return None

    try:
        # Build Cypher query to find user or computer by objectId (SID)
        query = f'MATCH (n) WHERE n.objectid = "{sid}" RETURN n.name AS name LIMIT 1'

        data = bh_connector.run_cypher_query(query)

        if data:
            # Extract name from Cypher query result
            if "data" in data and "data" in data["data"] and len(data["data"]["data"]) > 0:
                result = data["data"]["data"][0]
                if result and "name" in result:
                    username = result["name"]
                    info(f"Resolved SID {sid} to {username} via BloodHound API")
                    return username
        else:
            debug("BloodHound API SID query returned no data")

    except Exception as e:
        debug(f"BloodHound API SID resolution failed: {e}")

    return None


def extract_domain_sid_from_hv(hv_loader: HighValueLoader | None) -> str | None:
    """
    Extract domain SID from BloodHound data. Returns Admin SID (RID 500) for testing.

    Searches through all available SID sources in the HighValueLoader and returns
    the first valid domain SID with RID 500 appended (well-known Administrator).

    Args:
        hv_loader: HighValueLoader instance with BloodHound data

    Returns:
        Domain SID with RID 500 (e.g., "S-1-5-21-XXX-XXX-XXX-500") or None if not found
    """
    if not hv_loader or not hv_loader.loaded:
        return None

    # Try hv_sids first (keys are SIDs, values are metadata)
    hv_sids = getattr(hv_loader, "hv_sids", {})
    for sid in hv_sids:
        if sid and sid.startswith("S-1-5-21-"):
            parts = sid.split("-")
            if len(parts) >= 7:
                domain_sid = "-".join(parts[:-1])
                return f"{domain_sid}-500"

    # Try other sources (values contain 'objectid' or 'sid' fields)
    sid_sources = [
        getattr(hv_loader, "hv_users", {}),
    ]

    for source in sid_sources:
        for item in source.values():
            sid = item.get("objectid") or item.get("sid")
            if sid and sid.startswith("S-1-5-21-"):
                parts = sid.split("-")
                if len(parts) >= 7:
                    domain_sid = "-".join(parts[:-1])
                    return f"{domain_sid}-500"

    return None
