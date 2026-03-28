"""
OpenGraph Builder Module

Contains logic for building OpenGraph nodes, edges, and resolving identities.
"""

import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple

from bhopengraph import Edge, Node, Properties

from ..resolver import resolve_name_to_sid_via_ldap
from ..utils.cache_manager import get_cache
from ..utils.logging import debug, good, info, warn


def _create_task_object_id(hostname: str, task_path: str) -> str:
    """
    Create unique, deterministic object ID for scheduled task.

    Format: HOSTNAME_HASH_TASKNAME

    Uses MD5 hash to prevent collisions between similar paths:
    - \\Tasks\\My_Task vs \\Tasks_My\\Task would collide with simple replacement
    - Hash ensures uniqueness while keeping ID somewhat readable

    :param hostname: FQDN hostname (e.g., DC01.DOMAIN.LAB)
    :param task_path: Full task path (e.g., \\Microsoft\\Windows\\UpdateTask)
    :return: Unique object ID (e.g., DC01.DOMAIN.LAB_A3F2B1C8_UPDATETASK)
    """
    # Create deterministic identifier from hostname and full path
    identifier = f"{hostname.upper()}|{task_path.upper()}"

    # Generate short hash for uniqueness (8 chars is enough for collision resistance)
    hash_short = hashlib.md5(identifier.encode()).hexdigest()[:8].upper()

    # Extract task name from path for readability
    task_name = task_path.split("\\")[-1].upper()  # Get last part
    task_name = task_name.replace(" ", "_")[:40]  # Limit length, replace spaces

    # Combine into final ID
    return f"{hostname}_{hash_short}_{task_name}"


def _create_task_node(task: Dict) -> Node:
    """
    Creates a single ScheduledTask node using bhopengraph.

    :param task: Task dictionary from TaskHound engine
    :return: Node instance
    :raises ValueError: If required fields are missing or invalid
    """
    hostname = (task.get("host") or "").strip().upper()
    task_path = (task.get("path") or "").strip()

    # Validate required fields
    if not hostname:
        raise ValueError(f"Task missing 'host' field: {task}")
    if not task_path:
        raise ValueError(f"Task missing 'path' field: {task}")

    # Validate hostname is not empty/unknown
    if hostname.upper() in ("UNKNOWN_HOST", "UNKNOWN", ""):
        raise ValueError(f"Invalid hostname '{hostname}' for task: {task_path}")

    # Create a unique object ID using hash to prevent collisions
    object_id = _create_task_object_id(hostname, task_path)

    # Build command string
    command = task.get("command", "N/A")
    arguments = task.get("arguments")
    if arguments:
        command = f"{command} {arguments}"

    # Determine credentials status
    credentials_hint = task.get("credentials_hint", "unknown")
    logon_type = task.get("logon_type") or "Unknown"  # Handle None/null values

    # Build properties dict - bhopengraph Properties class validates schema compliance
    properties_dict = {
        "name": task_path,
        "hostname": hostname,
        "runas": task.get("runas") or "N/A",
        "enabled": str(task.get("enabled", "false")).lower() == "true",
        "command": command,
        "logontype": logon_type,
        "credentialsstored": credentials_hint == "stored_credentials",
    }

    # Add optional properties only if they have non-null values
    author = task.get("author")
    if author:
        properties_dict["author"] = author

    date = task.get("date")
    if date:
        properties_dict["date"] = date

    # Add trigger information if available
    trigger_type = task.get("trigger_type")
    if trigger_type:
        properties_dict["triggertype"] = trigger_type

        # Add schedule-specific details (only if non-null)
        start_boundary = task.get("start_boundary")
        if start_boundary:
            properties_dict["startboundary"] = start_boundary

        interval = task.get("interval")
        if interval:
            properties_dict["interval"] = interval

        duration = task.get("duration")
        if duration:
            properties_dict["duration"] = duration

        days_interval = task.get("days_interval")
        if days_interval:
            properties_dict["daysinterval"] = days_interval

    # Add password age analysis if available
    password_analysis = task.get("password_analysis")
    if password_analysis:
        properties_dict["passwordanalysis"] = password_analysis

    # Add classification (TIER-0, PRIV, TASK)
    task_type = task.get("type")
    if task_type:
        properties_dict["tasktype"] = task_type

    reason = task.get("reason")
    if reason:
        properties_dict["classification"] = reason

    # Create Node using bhopengraph (automatically validates schema)
    # Add TaskHound as custom kind for filtering in BloodHound
    # NOTE: First kind in array becomes "Primary Kind" in BloodHound UI
    node = Node(
        id=object_id,
        kinds=["ScheduledTask", "Base", "TaskHound"],
        properties=Properties(**properties_dict)
    )

    return node


def _create_principal_id(runas_user: str, local_domain: str, task: Dict, bh_connector=None, local_netbios: Optional[str] = None) -> Optional[str]:
    """
    Create BloodHound-compatible principal ID from RunAs user.

    Handles various formats and filters out accounts that should not have edges:
    - Built-in accounts (NT AUTHORITY\\SYSTEM, etc.)
    - SID format (S-1-5-*)
    - Cross-domain users (validates domain exists in BloodHound)

    Supported input formats:
    - UPN: user@domain.lab
    - NETBIOS: DOMAIN\\user
    - samAccountName: user

    :param runas_user: RunAs user from task (various formats)
    :param local_domain: FQDN domain of the computer (e.g., DOMAIN.LAB)
    :param task: Full task dict for logging context
    :param bh_connector: Optional BloodHoundConnector for cross-domain validation
    :param local_netbios: NetBIOS domain name (e.g., "CONTOSO"). If not provided, derives from FQDN first part
    :return: Principal ID in BloodHound format (USER@DOMAIN.LAB) or None if should skip
    """
    # Skip empty/invalid
    if not runas_user or runas_user.upper() == "N/A":
        return None

    # Handle SIDs (start with S-1-5-) - Return as-is for resolution by SID
    if runas_user.startswith("S-1-5-"):
        # Filter out well-known local/system SIDs
        # S-1-5-18: Local System, S-1-5-19: Local Service, S-1-5-20: Network Service
        if runas_user in ("S-1-5-18", "S-1-5-19", "S-1-5-20"):
            return None

        # Filter out Builtin domain (S-1-5-32-*) - e.g. Administrators, Users
        if runas_user.startswith("S-1-5-32-"):
            return None

        return runas_user

    # Skip built-in accounts that shouldn't have attack paths
    BUILTIN_ACCOUNTS = {
        'NT AUTHORITY\\SYSTEM',
        'NT AUTHORITY\\LOCAL SERVICE',
        'NT AUTHORITY\\NETWORK SERVICE',
        'NT AUTHORITY\\LOCALSERVICE',
        'NT AUTHORITY\\NETWORKSERVICE',
        'BUILTIN\\ADMINISTRATORS',
        'BUILTIN\\USERS',
        'NT AUTHORITY\\ANONYMOUS LOGON',
        'NT AUTHORITY\\AUTHENTICATED USERS',
        'SYSTEM',  # Sometimes appears without prefix
        'LOCAL SERVICE',
        'NETWORK SERVICE',
    }

    if runas_user.upper() in BUILTIN_ACCOUNTS:
        return None

    # Check if already in UPN format (user@domain.tld)
    if "@" in runas_user:
        # Already in UPN format - validate domain matches
        user_part, domain_part = runas_user.rsplit("@", 1)
        user_part = user_part.strip().upper()
        domain_part = domain_part.strip().upper()

        # Check if domain matches local domain (case-insensitive)
        if domain_part != local_domain.upper():
            # Cross-domain UPN - validate both domain and user exist in BloodHound
            if bh_connector:
                # Extract first component of FQDN for NETBIOS lookup
                netbios_name = domain_part.split(".")[0] if "." in domain_part else domain_part

                # Use complete validation workflow: domain + user
                user_info = bh_connector.validate_and_resolve_cross_domain_user(netbios_name, user_part)

                if user_info and not user_info.get('error_reason'):
                    # Both domain and user exist! Create edge with validated UPN
                    task_path = task.get("path", "unknown")
                    hostname = task.get("host", "unknown")
                    info(f"Cross-domain task on {hostname}: {task_path}")
                    info(f"  RunAs: {user_part}@{domain_part} → {user_info['name']} (validated in BH)")
                    info(f"  Domain: {user_info['domain_fqdn']}, User SID: {user_info['objectid']}")
                    return user_info['name']
                else:
                    # Domain or user doesn't exist in BloodHound
                    task_path = task.get("path", "unknown")
                    hostname = task.get("host", "unknown")
                    error_reason = user_info.get('error_reason') if user_info else 'unknown'

                    if error_reason == 'domain_not_found':
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user}")
                        warn(f"  [-] Domain '{netbios_name}' not found in BloodHound")
                        warn(f"  → Import '{netbios_name}' domain data to BloodHound to enable this edge")
                    elif error_reason == 'user_not_found':
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user}")
                        warn(f"  [+] Domain '{user_info['domain_fqdn']}' exists")
                        warn(f"  [-] User '{user_info['username']}' not found in domain")
                        warn("  → Likely orphaned task (user deleted) - enable orphaned node creation to capture")
                    else:
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user} (validation failed)")

                    return None
            else:
                # No connector - can't validate, skip for safety
                warn(f"Cross-domain UPN {runas_user} - skipping (no BloodHound connector)")
                return None

        # UPN domain matches - return normalized format
        return f"{user_part}@{local_domain}"

    # Parse NETBIOS domain\user format
    if "\\" in runas_user:
        domain_prefix, user = runas_user.split("\\", 1)
        domain_prefix = domain_prefix.strip().upper()
        user = user.strip().upper()

        # Explicit local account per MS-TSCH spec format 3 (.\username)
        if domain_prefix == ".":
            debug(f"Skipping explicit local account '{runas_user}' on {task.get('host', 'unknown')}: {task.get('path', 'unknown')}")
            return None

        # Use provided NetBIOS name, or derive from FQDN first part as fallback
        # The NetBIOS name can differ from FQDN first part (e.g., corp.example.com -> YOURCOMPANY)
        if local_netbios:
            local_domain_short = local_netbios.upper()
        else:
            local_domain_short = local_domain.split(".")[0].upper() if "." in local_domain else local_domain.upper()

        # Extract first part of domain_prefix for comparison (may be FQDN like THESIMPSONS.SPRINGFIELD.LOCAL)
        domain_prefix_short = domain_prefix.split(".")[0] if "." in domain_prefix else domain_prefix

        # Extract hostname from FQDN for local account detection (e.g., CLIENT01.DOMAIN.LAB -> CLIENT01)
        hostname_fqdn = task.get("host", "")
        hostname_short = hostname_fqdn.split(".")[0].upper() if "." in hostname_fqdn else hostname_fqdn.upper()

        # Check if it's a local account (NETBIOS domain matches hostname)
        is_local_account = (domain_prefix_short == hostname_short)

        # Check if cross-domain (domain doesn't match local domain AND not a local account)
        if domain_prefix_short != local_domain_short and not is_local_account:
            # Cross-domain task - validate both domain and user exist in BloodHound
            if bh_connector:
                # Use complete validation workflow: domain + user
                user_info = bh_connector.validate_and_resolve_cross_domain_user(domain_prefix_short, user)

                if user_info and not user_info.get('error_reason'):
                    # Both domain and user exist! Create edge with validated UPN
                    task_path = task.get("path", "unknown")
                    hostname = task.get("host", "unknown")
                    info(f"Cross-domain task on {hostname}: {task_path}")
                    info(f"  RunAs: {domain_prefix_short}\\{user} → {user_info['name']} (validated in BH)")
                    info(f"  Domain: {user_info['domain_fqdn']}, User SID: {user_info['objectid']}")
                    return user_info['name']
                else:
                    # Domain or user doesn't exist in BloodHound
                    task_path = task.get("path", "unknown")
                    hostname = task.get("host", "unknown")
                    error_reason = user_info.get('error_reason') if user_info else 'unknown'

                    if error_reason == 'domain_not_found':
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user}")
                        warn(f"  [-] Domain '{domain_prefix_short}' not found in BloodHound")
                        warn(f"  → Import '{domain_prefix_short}' domain data to BloodHound to enable this edge")
                    elif error_reason == 'user_not_found':
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user}")
                        warn(f"  [+] Domain '{user_info['domain_fqdn']}' exists")
                        warn(f"  [-] User '{user_info['username']}' not found in domain")
                        warn("  → Likely orphaned task (user deleted) - enable orphaned node creation to capture")
                    else:
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user} (validation failed)")

                    return None
            else:
                # No connector - can't validate, skip for safety
                warn(f"Cross-domain task {runas_user} - skipping (no BloodHound connector)")
                return None

        # If it's a local account, skip creating edge (local accounts aren't in BloodHound)
        if is_local_account:
            debug(f"Skipping local account: {runas_user} on {hostname_fqdn}")
            return None

        # Use full FQDN format
        return f"{user}@{local_domain}"
    else:
        # No domain prefix and no @ - potentially ambiguous
        # Per LookupAccountName() order, local accounts are resolved BEFORE domain.
        # Well-known local account names always resolve to local, never domain.
        user = runas_user.strip()
        task_path = task.get("path", "unknown")
        hostname = task.get("host", "unknown")

        KNOWN_LOCAL_ACCOUNTS = {
            "administrator", "guest", "defaultaccount", "wdagutilityaccount",
            "gast",  # German: guest
        }
        if user.lower() in KNOWN_LOCAL_ACCOUNTS:
            debug(f"Skipping known local account '{user}' on {hostname}: {task_path}")
            return None

        # Check per-host dynamic local account cache (populated by SAMR during scan)
        hostname_key = hostname.upper()
        if hostname_key:
            _cache = get_cache()
            local_users = (_cache.get("local_users", hostname_key) if _cache else None) or {}
            if user.lower() in local_users:
                rid = local_users[user.lower()]
                debug(f"Skipping per-host local account '{user}' (RID {rid}) on {hostname}: {task_path}")
                return None

        # Other bare names remain ambiguous - assume domain with a warning
        # MS-TSCH spec uses .\user for local, DOMAIN\user for domain
        warn(f"Ambiguous principal on {hostname}: {task_path}")
        warn(f"  RunAs: '{runas_user}' (no domain prefix) - assuming domain account {user.upper()}@{local_domain}")
        warn(f"  If this is a local account, it should be '.\\{runas_user}' per MS-TSCH spec")
        return f"{user.upper()}@{local_domain}"


def _create_relationship_edges(
    task: Dict,
    computer_map: Dict[str, Optional[Tuple[str, str, str]]],
    user_map: Dict[str, Optional[Tuple[str, str, str]]],
    bh_connector=None,
    allow_orphans: bool = False,
    netbios_name: Optional[str] = None,
) -> Tuple[List[Edge], Dict[str, int]]:
    """
    Creates edges for a task:
    1. (Computer)-[HasTask]->(ScheduledTask)
    2. (ScheduledTask)-[RunsAs]->(User)

    :param netbios_name: NetBIOS domain name for accurate domain comparison
    """
    edges = []
    skipped = {"computers": 0, "users": 0}

    hostname = (task.get("host") or "").strip().upper()
    task_path = (task.get("path") or "").strip()
    runas_user = (task.get("runas") or "").strip()

    # Helper to extract domain from FQDN
    fqdn_domain = "WORKGROUP"
    if "." in hostname:
        parts = hostname.split(".")
        if len(parts) >= 2:
            fqdn_domain = ".".join(parts[1:]).upper()

    debug(f"Creating edges for {task_path} on {hostname}. Allow orphans: {allow_orphans}")

    if not hostname or hostname == "UNKNOWN_HOST":
        return [], skipped

    # Create deterministic ID for the task node (must match _create_task_node)
    task_object_id = _create_task_object_id(hostname, task_path)

    # 1. Create (Computer)-[HasTask]->(ScheduledTask) edge
    edge_kind = "HasTask"
    if task.get("credentials_hint") == "stored_credentials":
        edge_kind = "HasTaskWithStoredCreds"

    computer_object_id = None
    computer_match_by = "name"  # Default fallback

    if hostname in computer_map:
        node_info = computer_map[hostname]
        debug(f"Computer {hostname} in map: {node_info}")

        if node_info is None:
            # Computer was queried but not found in BloodHound
            if not allow_orphans:
                warn(f"Skipping {edge_kind} edge: Computer '{hostname}' not found in BloodHound")
                warn(f"  Task: {task_path}")
                warn("  Use --allow-orphans to create edges to missing nodes")
                skipped["computers"] += 1
                # Don't create this edge
            else:
                # Fallback for orphaned mode
                debug(f"Creating orphaned edge for missing computer: {hostname}")
                has_task_edge = Edge(
                    start_node=hostname,
                    end_node=task_object_id,
                    kind=edge_kind,
                    start_match_by="name",
                    end_match_by="id"
                )
                edges.append(has_task_edge)
        else:
            # Node exists in BloodHound
            node_id, object_id, *rest = node_info
            if object_id:  # If we have an objectid (SID)
                computer_object_id = object_id
                computer_match_by = "id"  # match_by='id' looks for node where id property == object_id (SID)
                debug(f"Using id (objectid) for Computer: {hostname} → {object_id}")
            else:
                debug(f"No objectid for {hostname}, falling back to name matching")

            has_task_edge = Edge(
                start_node=computer_object_id if computer_object_id else hostname,
                end_node=task_object_id,
                kind=edge_kind,
                start_match_by=computer_match_by,
                end_match_by="id"
            )
            debug(f"Created {edge_kind} edge: {hostname} → {task_path} (match_by={computer_match_by})")
            edges.append(has_task_edge)
    else:
        debug(f"Computer {hostname} NOT in map")
        # Computer not in map - wasn't queried (shouldn't happen in normal flow)
        if not allow_orphans:
            warn(f"Computer '{hostname}' not in resolution map - skipping {edge_kind} edge")
            skipped["computers"] += 1
        else:
            # Fallback for orphaned mode
            has_task_edge = Edge(
                start_node=hostname,
                end_node=task_object_id,
                kind=edge_kind,
                start_match_by="name",
                end_match_by="id"
            )
            edges.append(has_task_edge)

    # 2. Create (ScheduledTask)-[RunsAs]->(Principal) edge
    # Use helper function to create principal ID with proper filtering
    principal_id = _create_principal_id(runas_user, fqdn_domain, task, bh_connector, local_netbios=netbios_name)

    if principal_id:
        # Prefer id (objectid/SID) matching, fall back to name matching
        # Note: In BloodHound, a node's 'id' property IS the objectid (SID for users/computers)
        user_object_id = None
        user_match_by = "name"  # Default fallback

        if user_map and principal_id in user_map:
            node_info = user_map[principal_id]

            if node_info is None:
                # User was queried but not found in BloodHound
                if not allow_orphans:
                    warn(f"Skipping RunsAs edge: User '{principal_id}' not found in BloodHound")
                    warn(f"  Task: {task_path}")
                    warn("  Use --allow-orphans to create edges to missing nodes")
                    skipped["users"] += 1
                    # Don't create this edge
                else:
                    # User opted in to orphaned edges - use name matching
                    debug(f"Creating orphaned edge for missing user: {principal_id}")
                    runs_as_edge = Edge(
                        start_node=task_object_id,
                        end_node=principal_id,
                        kind="RunsAs",
                        start_match_by="id",
                        end_match_by="name"
                    )
                    edges.append(runs_as_edge)
            else:
                # User exists in BloodHound
                node_id, object_id, *rest = node_info
                # Extract resolved name if available (3rd element in tuple)
                resolved_name = rest[0] if rest else None
                if object_id:  # If we have an objectid (SID)
                    user_object_id = object_id
                    user_match_by = "id"  # match_by='id' looks for node where id property == object_id (SID)
                    # Show resolved name alongside SID for better readability
                    display_name = resolved_name if resolved_name else principal_id
                    debug(f"Using id (objectid) for User: {display_name} → {object_id}")
                else:
                    debug(f"No objectid for {principal_id}, falling back to name matching")

                runs_as_edge = Edge(
                    start_node=task_object_id,
                    end_node=user_object_id if user_object_id else principal_id,
                    kind="RunsAs",
                    start_match_by="id",
                    end_match_by=user_match_by
                )
                # Show resolved name in edge creation log for clarity
                edge_display = resolved_name if resolved_name else principal_id
                debug(f"Created RunsAs edge: {task_path} → {edge_display} (match_by={user_match_by})")
                edges.append(runs_as_edge)
        else:
            # User not in map - wasn't queried (shouldn't happen in normal flow)
            if not allow_orphans:
                warn(f"User '{principal_id}' not in resolution map - skipping RunsAs edge")
                skipped["users"] += 1
            else:
                # Fallback for orphaned mode
                runs_as_edge = Edge(
                    start_node=task_object_id,
                    end_node=principal_id,
                    kind="RunsAs",
                    start_match_by="id",
                    end_match_by="name"
                )
                edges.append(runs_as_edge)

    return edges, skipped


def resolve_object_ids_chunked(
    computer_names: Set[str],
    user_names: Set[str],
    bh_connector,  # BloodHoundConnector instance
    ldap_config: Optional[Dict] = None,
    chunk_size: int = 10,
    computer_sids: Optional[Dict[str, str]] = None
) -> Tuple[Dict[str, Optional[Tuple[str, str, str]]], Dict[str, Optional[Tuple[str, str, str]]]]:
    """
    Resolve computer and user names to their node IDs and objectIds (SIDs) using BloodHound API.
    Falls back to LDAP if API queries fail (LDAP only provides objectId, not node_id).

    Workflow (optimized for SID-based lookup):
    1. If computer_sids provided: Query by objectId (SID) - most reliable!
    2. Otherwise: Query by name using WHERE IN clause
    3. Build name→(node_id, objectId) mappings from results
    4. If API fails, fallback to LDAP for missing entries (provides objectId only)

    Args:
        computer_names: Set of computer FQDNs (e.g., {"DC.CORP.LOCAL", "WEB01.CORP.LOCAL"})
        user_names: Set of user names in USER@DOMAIN.TLD format (e.g., {"ADMIN@CORP.LOCAL"})
        bh_connector: BloodHoundConnector instance for API queries
        ldap_config: Optional LDAP configuration for fallback
                    Expected keys: domain, dc_ip, username, password, hashes, kerberos
        chunk_size: Number of items per WHERE IN clause (default: 10)
        computer_sids: Optional mapping of FQDN→SID from SMB connections (preferred!)
                      Example: {"DC.CORP.LOCAL": "S-1-5-21-...-1000"}

    Returns:
        Tuple of (computer_map, user_map) where:
        - computer_map: {"DC.CORP.LOCAL": ("19", "S-1-5-21-...-1000")}
        - user_map: {"ADMIN@CORP.LOCAL": ("42", "S-1-5-21-...-500")}

        Note: If resolved via LDAP fallback, node_id will be empty string: ("", "S-1-5-21-...")
    """

    computer_sid_map: Dict[str, Optional[Tuple[str, str, str]]] = {}
    user_sid_map: Dict[str, Optional[Tuple[str, str, str]]] = {}

    # Initialize cache
    cache = get_cache()

    def _chunk_list(items: Set[str], size: int) -> List[List[str]]:
        """Split set into chunks of specified size."""
        items_list = sorted(items)  # Sort for consistent ordering
        return [items_list[i:i + size] for i in range(0, len(items_list), size)]

    def _query_bloodhound_with_sid_validation(names_with_sids: Dict[str, str], node_type: str) -> Dict[str, Tuple[str, str, str]]:
        """
        Query BloodHound API by name but VALIDATE with SID for correctness.

        This hybrid approach:
        - Queries by name (works reliably in BloodHound CE)
        - Validates returned node has matching SID (prevents wrong node)
        - Detects duplicate names (multiple nodes with same name)

        Args:
            names_with_sids: Dict mapping name→SID (e.g., {"DC.CORP.LOCAL": "S-1-5-21-...-1000"})
            node_type: "Computer" or "User"

        Returns:
            Mapping of name→(node_id, objectId)
            Example: {"DC.CORP.LOCAL": ("19", "S-1-5-21-...-1000")}
        """
        mapping = {}

        if not names_with_sids:
            return {}

        # Build Cypher query with WHERE IN clause for names
        names_list = list(names_with_sids.keys())
        names_list_str = ', '.join([f'"{name}"' for name in names_list])
        query = f'MATCH (n:{node_type}) WHERE n.name IN [{names_list_str}] RETURN n'

        try:
            debug(f"Querying {node_type} chunk with SID validation: {len(names_with_sids)} items")

            data = bh_connector.run_cypher_query(query)

            if data:
                nodes = data.get("data", {}).get("nodes", {})

                # Group nodes by name to detect duplicates
                nodes_by_name: Dict[str, List[Tuple[str, str, str]]] = {}
                for node_id, node in nodes.items():
                    name = node.get("label")
                    object_id = node.get("objectId")

                    if name not in nodes_by_name:
                        nodes_by_name[name] = []
                    nodes_by_name[name].append((node_id, object_id, name))

                # Process each name and validate SID
                for name, expected_sid in names_with_sids.items():
                    node_list = nodes_by_name.get(name, [])

                    if len(node_list) == 0:
                        debug(f"No {node_type} node found for {name}")
                        continue

                    if len(node_list) > 1:
                        # DUPLICATE NAMES DETECTED!
                        warn(f"[!] Duplicate {node_type} nodes found for {name}: {len(node_list)} nodes")
                        warn(f"   Node IDs: {[n[0] for n in node_list]}")
                        warn(f"   SIDs: {[n[1] for n in node_list]}")

                    # Find node with matching SID
                    matched_node = None
                    for node_id, object_id, node_name in node_list:
                        if object_id == expected_sid:
                            matched_node = (node_id, object_id, node_name)
                            break

                    if matched_node:
                        mapping[name] = matched_node
                        debug(f"[+] Validated {name} → node_id={matched_node[0]}, SID={matched_node[1]}")
                    else:
                        # SID mismatch - wrong computer!
                        warn(f"[!] SID mismatch for {name}:")
                        warn(f"   Expected SID: {expected_sid}")
                        warn(f"   BloodHound returned: {[n[1] for n in node_list]}")
                        warn("   Skipping this node (possible stale data or wrong computer)")

                return mapping
            else:
                return {}
        except Exception as e:
            warn(f"Error querying BloodHound with SID validation: {e}")
            if debug:  # type: ignore[truthy-function]  # intentional: guard debug-only traceback
                import traceback
                traceback.print_exc()
            return {}

    def _query_bloodhound_chunk(names: List[str], node_type: str) -> Dict[str, Tuple[str, str, str]]:
        """
        Query BloodHound API for a chunk of names using the connector.

        Args:
            names: List of names to query
            node_type: "Computer" or "User"

        Returns:
            Mapping of name→(node_id, objectId)
            Example: {"DC01.DOMAIN.LOCAL": ("19", "S-1-5-21-...-1000")}
        """
        mapping = {}

        # Build Cypher query with WHERE IN clause
        names_list_str = ', '.join([f'"{name}"' for name in names])
        query = f'MATCH (n:{node_type}) WHERE n.name IN [{names_list_str}] RETURN n'

        try:
            debug(f"Querying {node_type} chunk: {len(names)} items")

            data = bh_connector.run_cypher_query(query)

            if data:
                nodes = data.get("data", {}).get("nodes", {})

                # Nodes are returned as dict keyed by node ID (THIS is the graph database ID!)
                for node_id, node in nodes.items():
                    # Properties are at top level of node, not nested
                    name = node.get("label")  # 'label' contains the name
                    object_id = node.get("objectId")  # 'objectId' not 'objectid'

                    if name and object_id:
                        mapping[name] = (node_id, object_id, name)  # Return BOTH IDs + Name
                        debug(f"Resolved {name} → node_id={node_id}, objectId={object_id}")

                return mapping
            else:
                return {}

        except Exception as e:
            warn(f"BloodHound API query failed: {e}")
            import traceback
            debug(traceback.format_exc())
            return {}

    def _query_bloodhound_by_sid_chunk(sids: List[str], node_type: str) -> Dict[str, Tuple[str, str, str]]:
        """
        Query BloodHound API for a chunk of SIDs (objectIds).

        Args:
            sids: List of SIDs to query
            node_type: "Computer" or "User"

        Returns:
            Mapping of SID→(node_id, objectId)
            Example: {"S-1-5-21-...": ("19", "S-1-5-21-...")}
        """
        mapping = {}

        # Build Cypher query with WHERE IN clause
        sids_list_str = ', '.join([f'"{sid}"' for sid in sids])
        query = f'MATCH (n:{node_type}) WHERE n.objectid IN [{sids_list_str}] RETURN n'

        try:
            debug(f"Querying {node_type} chunk by SID: {len(sids)} items")

            data = bh_connector.run_cypher_query(query)

            if data:
                nodes = data.get("data", {}).get("nodes", {})

                for node_id, node in nodes.items():
                    object_id = node.get("objectId")
                    name = node.get("label")
                    if object_id:
                        mapping[object_id] = (node_id, object_id, name)
                        debug(f"Resolved SID {object_id} → node_id={node_id}, name={name}")

                return mapping
            else:
                return {}

        except Exception as e:
            warn(f"BloodHound API query failed: {e}")
            import traceback
            debug(traceback.format_exc())
            return {}

    def _ldap_fallback(names: List[str], is_computer: bool) -> Dict[str, Tuple[str, str, str]]:
        """
        Fallback to LDAP for resolving names to SIDs.
        Note: LDAP can only provide objectId (SID), not the BloodHound node_id.

        Args:
            names: List of names that couldn't be resolved via API
            is_computer: True for computers, False for users

        Returns:
            Mapping of name→("", SID)  # Empty node_id since LDAP doesn't provide it
        """
        mapping = {}

        if not ldap_config:
            warn("LDAP fallback requested but no LDAP config provided")
            return {}

        domain = ldap_config.get("domain")
        if not domain:
            warn("LDAP config missing 'domain' key")
            return {}

        for name in names:
            try:
                sid = resolve_name_to_sid_via_ldap(
                    name=name,
                    domain=domain,
                    is_computer=is_computer,
                    dc_ip=ldap_config.get("dc_ip"),
                    username=ldap_config.get("username"),
                    password=ldap_config.get("password"),
                    hashes=ldap_config.get("hashes"),
                    kerberos=ldap_config.get("kerberos", False)
                )

                if sid:
                    mapping[name] = ("", sid, name)  # Empty node_id, only objectId from LDAP
                    info(f"LDAP fallback resolved {name} → {sid}")
                else:
                    debug(f"LDAP fallback failed for {name}")

            except Exception as e:
                warn(f"LDAP fallback error for {name}: {e}")

        return mapping

    # Process computers in chunks
    if computer_names:
        info(f"Resolving {len(computer_names)} computer names to objectIds...")

        # Check cache first
        cached_computers = set()
        if cache:
            for name in computer_names:
                cached_val = cache.get("principals", name)
                if cached_val:
                    computer_sid_map[name] = tuple(cached_val)
                    cached_computers.add(name)

            if cached_computers:
                info(f"Resolved {len(cached_computers)} computers from cache")

        # Filter out cached computers
        remaining_computers = computer_names - cached_computers

        if remaining_computers:
            # OPTIMIZATION: Use SID validation if available (captured from SMB connection)
            if computer_sids:
                # Split into: computers with known SIDs vs computers without SIDs
                computers_with_sids = {name: sid for name, sid in computer_sids.items() if name in remaining_computers and sid}
                computers_without_sids = remaining_computers - set(computers_with_sids.keys())

                if computers_with_sids:
                    info(f"Using SID validation for {len(computers_with_sids)} computers (from SMB connection)")

                    # Chunk the computers with SIDs
                    computers_list = list(computers_with_sids.keys())
                    name_chunks = [computers_list[i:i + chunk_size] for i in range(0, len(computers_list), chunk_size)]

                    for i, chunk in enumerate(name_chunks, 1):
                        debug(f"Processing computer chunk {i}/{len(name_chunks)} with SID validation")

                        # Build name→SID mapping for this chunk
                        chunk_name_sid_map = {name: computers_with_sids[name] for name in chunk}

                        # Query by name BUT validate with SID
                        chunk_mapping = _query_bloodhound_with_sid_validation(chunk_name_sid_map, "Computer")
                        computer_sid_map.update(chunk_mapping)

                        # Cache results
                        if cache:
                            for name, val in chunk_mapping.items():
                                cache.set("principals", name, val)

                        info(f"[*] Chunk {i}/{len(name_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved and validated")

                # Fall back to name-based lookup WITHOUT validation for computers without SIDs
                if computers_without_sids:
                    info(f"Using name-based lookup for {len(computers_without_sids)} computers (no SID for validation)")
                    computer_chunks = _chunk_list(computers_without_sids, chunk_size)
                else:
                    computer_chunks = []
            else:
                # No SIDs available, use traditional name-based lookup
                info("No computer SIDs available - using name-based lookup (may have duplicates)")
                computer_chunks = _chunk_list(remaining_computers, chunk_size)

            # Process any remaining computers via name-based lookup
            for i, chunk in enumerate(computer_chunks, 1):
                debug(f"Processing computer name chunk {i}/{len(computer_chunks)}")

                # Try BloodHound API by name
                chunk_mapping = _query_bloodhound_chunk(chunk, "Computer")
                computer_sid_map.update(chunk_mapping)

                # Cache API results
                if cache:
                    for name, val in chunk_mapping.items():
                        cache.set("principals", name, val)

                # Find missing entries
                resolved_names = set(chunk_mapping.keys())
                missing_names = set(chunk) - resolved_names

                if missing_names:
                    info(f"Chunk {i}/{len(computer_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API, {len(missing_names)} missing")

                    # Try LDAP fallback for missing entries
                    if ldap_config:
                        fallback_mapping = _ldap_fallback(list(missing_names), is_computer=True)
                        computer_sid_map.update(fallback_mapping)

                        # Cache LDAP results
                        if cache:
                            for name, val in fallback_mapping.items():
                                cache.set("principals", name, val)

                        still_missing = missing_names - set(fallback_mapping.keys())
                        if still_missing:
                            warn(f"Could not resolve computers: {', '.join(sorted(still_missing))}")
                            # Mark missing computers as None so we can detect them later
                            for missing_name in still_missing:
                                computer_sid_map[missing_name] = None
                    else:
                        warn(f"No LDAP config for fallback. Missing computers: {', '.join(sorted(missing_names))}")
                        # Mark missing computers as None so we can detect them later
                        for missing_name in missing_names:
                            computer_sid_map[missing_name] = None
                else:
                    info(f"Chunk {i}/{len(computer_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API")

    # Process users in chunks
    if user_names:
        info(f"Resolving {len(user_names)} user names to objectIds...")

        # Check cache first
        cached_users = set()
        if cache:
            for name in user_names:
                cached_val = cache.get("principals", name)
                if cached_val:
                    user_sid_map[name] = tuple(cached_val)
                    cached_users.add(name)

            if cached_users:
                info(f"Resolved {len(cached_users)} users from cache")

        # Filter out cached users
        remaining_users = user_names - cached_users

        if remaining_users:
            # Split into Names and SIDs
            names_to_resolve = set()
            sids_to_resolve = set()

            for name in remaining_users:
                if name.startswith("S-1-5-"):
                    sids_to_resolve.add(name)
                else:
                    names_to_resolve.add(name)

            # Resolve SIDs directly
            if sids_to_resolve:
                info(f"Resolving {len(sids_to_resolve)} users by SID...")
                sid_chunks = _chunk_list(sids_to_resolve, chunk_size)
                for i, chunk in enumerate(sid_chunks, 1):
                    debug(f"Processing user SID chunk {i}/{len(sid_chunks)}")
                    results = _query_bloodhound_by_sid_chunk(chunk, "User")

                    # Map SID -> (NodeID, SID)
                    user_sid_map.update(results)

                    # Also cache these results
                    if cache:
                        for sid, val in results.items():
                            cache.set("principals", sid, list(val))

                    info(f"SID Chunk {i}/{len(sid_chunks)}: {len(results)}/{len(chunk)} resolved")

            # Resolve Names
            if names_to_resolve:
                user_chunks = _chunk_list(names_to_resolve, chunk_size)

                for i, chunk in enumerate(user_chunks, 1):
                    debug(f"Processing user chunk {i}/{len(user_chunks)}")

                    # Try BloodHound API first
                    chunk_mapping = _query_bloodhound_chunk(chunk, "User")
                    user_sid_map.update(chunk_mapping)

                    # Cache API results
                    if cache:
                        for name, val in chunk_mapping.items():
                            cache.set("principals", name, val)

                    # Find missing entries
                    resolved_names = set(chunk_mapping.keys())
                    missing_names = set(chunk) - resolved_names

                    if missing_names:
                        info(f"Chunk {i}/{len(user_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API, {len(missing_names)} missing")

                        # Try LDAP fallback for missing entries
                        if ldap_config:
                            fallback_mapping = _ldap_fallback(list(missing_names), is_computer=False)
                            user_sid_map.update(fallback_mapping)

                            # Cache LDAP results
                            if cache:
                                for name, val in fallback_mapping.items():
                                    cache.set("principals", name, val)

                            still_missing = missing_names - set(fallback_mapping.keys())
                            if still_missing:
                                warn(f"Could not resolve users: {', '.join(sorted(still_missing))}")
                                # Mark missing users as None so we can detect them later
                                for missing_name in still_missing:
                                    user_sid_map[missing_name] = None
                        else:
                            warn(f"No LDAP config for fallback. Missing users: {', '.join(sorted(missing_names))}")
                            # Mark missing users as None so we can detect them later
                            for missing_name in missing_names:
                                user_sid_map[missing_name] = None
                    else:
                        info(f"Chunk {i}/{len(user_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API")

    good(f"Resolution complete: {len(computer_sid_map)} computers, {len(user_sid_map)} users")
    return computer_sid_map, user_sid_map


# ---------------------------------------------------------------------------
# Windows Service OpenGraph builders
# ---------------------------------------------------------------------------


def _create_service_object_id(hostname: str, service_name: str) -> str:
    """
    Create unique, deterministic object ID for a Windows service.

    Format: HOSTNAME_HASH_SERVICENAME
    Same pattern as _create_task_object_id but for services.
    """
    identifier = f"{hostname.upper()}|SVC|{service_name.upper()}"
    hash_short = hashlib.md5(identifier.encode()).hexdigest()[:8].upper()
    safe_name = service_name.upper().replace(" ", "_")[:40]
    return f"{hostname}_{hash_short}_{safe_name}"


def _create_service_node(svc: Dict) -> Node:
    """
    Create a WindowsService node for BloodHound OpenGraph.

    Node kinds: ["WindowsService", "Base", "TaskHound"]
    """
    hostname = (svc.get("host") or "").strip().upper()
    service_name = (svc.get("service_name") or "").strip()

    if not hostname:
        raise ValueError(f"Service missing 'host' field: {svc}")
    if not service_name:
        raise ValueError(f"Service missing 'service_name' field: {svc}")

    object_id = _create_service_object_id(hostname, service_name)

    properties_dict: Dict[str, Any] = {
        "name": service_name,
        "hostname": hostname,
        "servicename": service_name,
    }

    # Add optional properties
    display_name = svc.get("display_name")
    if display_name:
        properties_dict["displayname"] = display_name

    start_name = svc.get("start_name")
    if start_name:
        properties_dict["startname"] = start_name

    binary_path = svc.get("binary_path")
    if binary_path:
        properties_dict["binarypath"] = binary_path

    start_type = svc.get("start_type")
    if start_type:
        properties_dict["starttype"] = start_type

    service_type = svc.get("service_type")
    if service_type:
        properties_dict["servicetype"] = str(service_type)

    state = svc.get("state")
    if state:
        properties_dict["state"] = state

    svc_type = svc.get("type")
    if svc_type:
        properties_dict["serviceclassification"] = svc_type

    reason = svc.get("reason")
    if reason:
        properties_dict["classification"] = reason

    password_analysis = svc.get("password_analysis")
    if password_analysis:
        properties_dict["passwordanalysis"] = password_analysis

    properties_dict["credentialsstored"] = True  # All domain-account services store creds
    properties_dict["isgmsa"] = svc.get("is_gmsa", False)

    return Node(
        id=object_id,
        kinds=["WindowsService", "Base", "TaskHound"],
        properties=Properties(**properties_dict),
    )


def _create_service_edges(
    svc: Dict,
    computer_map: Dict,
    user_map: Dict,
    bh_connector=None,
    allow_orphans: bool = False,
    netbios_name: Optional[str] = None,
) -> Tuple[List["Edge"], Dict[str, int]]:
    """
    Create edges for a Windows service node.

    Edge types:
    - HasServiceWithStoredCreds: Computer → WindowsService (all domain-account services)
    - RunsAs: WindowsService → User
    """
    from bhopengraph import Edge

    edges: List[Edge] = []
    skipped = {"computers": 0, "users": 0}

    hostname = (svc.get("host") or "").strip().upper()
    service_name = (svc.get("service_name") or "").strip()
    start_name = (svc.get("start_name") or "").strip()

    if not hostname or not service_name:
        return edges, skipped

    service_id = _create_service_object_id(hostname, service_name)

    # Helper to extract domain from FQDN
    def _extract_domain(fqdn: str) -> str:
        if "." in fqdn:
            parts = fqdn.split(".")
            if len(parts) >= 2:
                return ".".join(parts[1:]).upper()
        return "WORKGROUP"

    # Edge: Computer → WindowsService (HasServiceWithStoredCreds)
    computer_info = computer_map.get(hostname)
    if computer_info:
        _, computer_sid, *_ = computer_info
        if computer_sid:
            edges.append(Edge(
                start_node=computer_sid,
                end_node=service_id,
                kind="HasServiceWithStoredCreds",
                start_match_by="id",
                end_match_by="id",
            ))
    elif allow_orphans:
        edges.append(Edge(
            start_node=hostname,
            end_node=service_id,
            kind="HasServiceWithStoredCreds",
            start_match_by="name",
            end_match_by="id",
        ))
    else:
        skipped["computers"] += 1

    # Edge: WindowsService → User (RunsAs)
    if start_name:
        fqdn_domain = _extract_domain(hostname)
        principal_id = _create_principal_id(start_name, fqdn_domain, svc, bh_connector, local_netbios=netbios_name)

        if principal_id:
            user_info = user_map.get(principal_id)
            if user_info:
                _, user_sid, *_ = user_info
                if user_sid:
                    edges.append(Edge(
                        start_node=service_id,
                        end_node=user_sid,
                        kind="RunsAs",
                        start_match_by="id",
                        end_match_by="id",
                    ))
                elif allow_orphans:
                    edges.append(Edge(
                        start_node=service_id,
                        end_node=principal_id,
                        kind="RunsAs",
                        start_match_by="id",
                        end_match_by="name",
                    ))
                else:
                    skipped["users"] += 1
            elif allow_orphans:
                edges.append(Edge(
                    start_node=service_id,
                    end_node=principal_id,
                    kind="RunsAs",
                    start_match_by="id",
                    end_match_by="name",
                ))
            else:
                skipped["users"] += 1

    return edges, skipped
