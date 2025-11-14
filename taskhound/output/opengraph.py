"""
BloodHound OpenGraph Data Generator

This module is responsible for converting TaskHound's internal data structures
into JSON files that are ingestible by BloodHound's OpenGraph feature.

Now using the official bhopengraph library (https://github.com/p0dalirius/bhopengraph)
for type-safe, schema-validated graph generation.

It will generate two main files:
- scheduled_tasks_nodes.json: Contains the custom 'ScheduledTask' nodes.
- scheduled_tasks_edges.json: Contains the custom 'HasTask' and 'RunsAs' relationships.
"""

import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from bhopengraph import OpenGraph, Node, Edge, Properties
from ..utils.logging import good, info, warn, debug
from ..utils.sid_resolver import resolve_name_to_sid_via_ldap


def _get_bloodhound_token(api_url: str, username: str, password: str) -> Optional[str]:
    """
    Authenticate to BloodHound CE API and get session token.
    
    Args:
        api_url: BloodHound API base URL (e.g., "http://127.0.0.1:8080")
        username: BloodHound username
        password: BloodHound password
        
    Returns:
        Session token string, or None if authentication fails
    """
    import requests
    
    try:
        response = requests.post(
            f"{api_url}/api/v2/login",
            json={"login_method": "secret", "secret": password, "username": username},
            timeout=30
        )
        
        if response.status_code != 200:
            warn(f"BloodHound authentication failed - HTTP {response.status_code}")
            return None
        
        token = response.json()["data"]["session_token"]
        debug(f"Successfully authenticated to BloodHound at {api_url}")
        return token
        
    except requests.Timeout:
        warn(f"Timeout authenticating to BloodHound (>30s)")
        return None
    except requests.RequestException as e:
        warn(f"Network error during authentication: {e}")
        return None
    except (KeyError, ValueError) as e:
        warn(f"Invalid authentication response from BloodHound: {e}")
        return None
    except Exception as e:
        warn(f"Unexpected authentication error: {e}")
        return None


def resolve_object_ids_chunked(
    computer_names: Set[str],
    user_names: Set[str],
    bh_api_url: str,
    bh_token: str,
    ldap_config: Optional[Dict] = None,
    chunk_size: int = 10
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Resolve computer and user names to their objectIds (SIDs) using BloodHound API.
    Falls back to LDAP if API queries fail.
    
    Workflow:
    1. Query BloodHound API in chunks using WHERE IN clause
    2. Build name→objectId mappings from results
    3. If API fails, fallback to LDAP for missing entries
    
    Args:
        computer_names: Set of computer FQDNs (e.g., {"DC.CORP.LOCAL", "WEB01.CORP.LOCAL"})
        user_names: Set of user names in USER@DOMAIN.TLD format (e.g., {"ADMIN@CORP.LOCAL"})
        bh_api_url: BloodHound CE API base URL (e.g., "http://127.0.0.1:8080")
        bh_token: API authentication token
        ldap_config: Optional LDAP configuration for fallback
                    Expected keys: domain, dc_ip, username, password, hashes, kerberos
        chunk_size: Number of items per WHERE IN clause (default: 10)
        
    Returns:
        Tuple of (computer_sid_map, user_sid_map) where:
        - computer_sid_map: {"DC.CORP.LOCAL": "S-1-5-21-...-1000"}
        - user_sid_map: {"ADMIN@CORP.LOCAL": "S-1-5-21-...-500"}
    """
    import requests
    
    computer_sid_map = {}
    user_sid_map = {}
    
    def _chunk_list(items: Set[str], size: int) -> List[List[str]]:
        """Split set into chunks of specified size."""
        items_list = sorted(list(items))  # Sort for consistent ordering
        return [items_list[i:i + size] for i in range(0, len(items_list), size)]
    
    def _query_bloodhound_chunk(names: List[str], node_type: str) -> Dict[str, str]:
        """
        Query BloodHound API for a chunk of names.
        
        Args:
            names: List of names to query
            node_type: "Computer" or "User"
            
        Returns:
            Mapping of name→objectId
        """
        mapping = {}
        
        # Build Cypher query with WHERE IN clause
        names_list_str = ', '.join([f'"{name}"' for name in names])
        query = f'MATCH (n:{node_type}) WHERE n.name IN [{names_list_str}] RETURN n'
        
        try:
            debug(f"Querying {node_type} chunk: {len(names)} items")
            response = requests.post(
                f"{bh_api_url}/api/v2/graphs/cypher",
                headers={
                    "Authorization": f"Bearer {bh_token}",
                    "Content-Type": "application/json"
                },
                json={"query": query},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                nodes = data.get("data", {}).get("nodes", {})
                
                # Nodes are returned as dict keyed by node ID
                for node_id, node in nodes.items():
                    # Properties are at top level of node, not nested
                    name = node.get("label")  # 'label' contains the name
                    object_id = node.get("objectId")  # 'objectId' not 'objectid'
                    
                    if name and object_id:
                        mapping[name] = object_id
                        debug(f"Resolved {name} → {object_id}")
                
                return mapping
            else:
                warn(f"BloodHound API returned status {response.status_code}: {response.text}")
                return {}
                
        except Exception as e:
            warn(f"BloodHound API query failed: {e}")
            return {}
    
    def _ldap_fallback(names: List[str], is_computer: bool) -> Dict[str, str]:
        """
        Fallback to LDAP for resolving names to SIDs.
        
        Args:
            names: List of names that couldn't be resolved via API
            is_computer: True for computers, False for users
            
        Returns:
            Mapping of name→SID
        """
        mapping = {}
        
        if not ldap_config:
            warn(f"LDAP fallback requested but no LDAP config provided")
            return {}
        
        domain = ldap_config.get("domain")
        if not domain:
            warn(f"LDAP config missing 'domain' key")
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
                    mapping[name] = sid
                    info(f"LDAP fallback resolved {name} → {sid}")
                else:
                    debug(f"LDAP fallback failed for {name}")
                    
            except Exception as e:
                warn(f"LDAP fallback error for {name}: {e}")
        
        return mapping
    
    # Process computers in chunks
    if computer_names:
        info(f"Resolving {len(computer_names)} computer names to objectIds...")
        computer_chunks = _chunk_list(computer_names, chunk_size)
        
        for i, chunk in enumerate(computer_chunks, 1):
            debug(f"Processing computer chunk {i}/{len(computer_chunks)}")
            
            # Try BloodHound API first
            chunk_mapping = _query_bloodhound_chunk(chunk, "Computer")
            computer_sid_map.update(chunk_mapping)
            
            # Find missing entries
            resolved_names = set(chunk_mapping.keys())
            missing_names = set(chunk) - resolved_names
            
            if missing_names:
                info(f"Chunk {i}/{len(computer_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API, {len(missing_names)} missing")
                
                # Try LDAP fallback for missing entries
                if ldap_config:
                    fallback_mapping = _ldap_fallback(list(missing_names), is_computer=True)
                    computer_sid_map.update(fallback_mapping)
                    
                    still_missing = missing_names - set(fallback_mapping.keys())
                    if still_missing:
                        warn(f"Could not resolve computers: {', '.join(sorted(still_missing))}")
                else:
                    warn(f"No LDAP config for fallback. Missing computers: {', '.join(sorted(missing_names))}")
            else:
                info(f"Chunk {i}/{len(computer_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API")
    
    # Process users in chunks
    if user_names:
        info(f"Resolving {len(user_names)} user names to objectIds...")
        user_chunks = _chunk_list(user_names, chunk_size)
        
        for i, chunk in enumerate(user_chunks, 1):
            debug(f"Processing user chunk {i}/{len(user_chunks)}")
            
            # Try BloodHound API first
            chunk_mapping = _query_bloodhound_chunk(chunk, "User")
            user_sid_map.update(chunk_mapping)
            
            # Find missing entries
            resolved_names = set(chunk_mapping.keys())
            missing_names = set(chunk) - resolved_names
            
            if missing_names:
                info(f"Chunk {i}/{len(user_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API, {len(missing_names)} missing")
                
                # Try LDAP fallback for missing entries
                if ldap_config:
                    fallback_mapping = _ldap_fallback(list(missing_names), is_computer=False)
                    user_sid_map.update(fallback_mapping)
                    
                    still_missing = missing_names - set(fallback_mapping.keys())
                    if still_missing:
                        warn(f"Could not resolve users: {', '.join(sorted(still_missing))}")
                else:
                    warn(f"No LDAP config for fallback. Missing users: {', '.join(sorted(missing_names))}")
            else:
                info(f"Chunk {i}/{len(user_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API")
    
    good(f"Resolution complete: {len(computer_sid_map)} computers, {len(user_sid_map)} users")
    return computer_sid_map, user_sid_map


def generate_opengraph_files(output_dir: str, tasks: List[Dict],
                            bh_api_url: Optional[str] = None,
                            bh_username: Optional[str] = None,
                            bh_password: Optional[str] = None,
                            ldap_config: Optional[Dict] = None) -> str:
    """
    Main function to generate OpenGraph file using bhopengraph library.

    :param output_dir: The directory to write the JSON file to.
    :param tasks: A list of task dictionaries from the TaskHound engine.
    :param bh_api_url: BloodHound API URL for objectId resolution (optional)
    :param bh_username: BloodHound username for API authentication (optional)
    :param bh_password: BloodHound password for API authentication (optional)
    :param ldap_config: LDAP configuration for fallback resolution (optional)
    :return: Path to the generated OpenGraph file
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Create a single OpenGraph instance for both nodes and edges
    # Don't use source_kind to avoid adding it to stub Computer/User nodes
    graph = OpenGraph()

    # Create and add task nodes
    skipped_nodes = 0
    for task in tasks:
        try:
            node = _create_task_node(task)
            graph.add_node(node)
        except ValueError as e:
            warn(f"Skipping invalid task: {e}")
            skipped_nodes += 1
    
    if skipped_nodes > 0:
        warn(f"Skipped {skipped_nodes} invalid tasks (missing host/path)")
    
    info(f"Created {graph.get_node_count()} ScheduledTask nodes")

    # Resolve objectIds if BloodHound API is available
    computer_sid_map = {}
    user_sid_map = {}
    
    if bh_api_url and bh_username and bh_password:
        # Extract unique computer and user names from tasks
        computer_names = set()
        user_names = set()
        
        for task in tasks:
            hostname = task.get("host", "").strip().upper()
            if hostname and hostname not in ("UNKNOWN_HOST", "UNKNOWN", ""):
                computer_names.add(hostname)
            
            runas_user = task.get("runas", "").strip()
            if runas_user and runas_user not in ("N/A", "", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                # Extract domain from hostname for principal ID construction
                def _extract_domain_from_fqdn(fqdn: str) -> str:
                    if "." in fqdn:
                        parts = fqdn.split(".")
                        if len(parts) >= 2:
                            return ".".join(parts[1:]).upper()
                    return "WORKGROUP"
                
                fqdn_domain = _extract_domain_from_fqdn(hostname)
                principal_id = _create_principal_id(runas_user, fqdn_domain, task)
                
                if principal_id:  # Only add if it passed filtering
                    user_names.add(principal_id)
        
        info(f"Extracted {len(computer_names)} unique computers and {len(user_names)} unique users")
        
        # Get API token
        bh_token = _get_bloodhound_token(bh_api_url, bh_username, bh_password)
        
        if bh_token:
            # Resolve names to objectIds using chunked queries
            computer_sid_map, user_sid_map = resolve_object_ids_chunked(
                computer_names=computer_names,
                user_names=user_names,
                bh_api_url=bh_api_url,
                bh_token=bh_token,
                ldap_config=ldap_config,
                chunk_size=10
            )
        else:
            warn("Failed to get BloodHound API token - edges will use name matching (may create duplicates)")
    
    # TESTING: Skip stub nodes when using name matching
    # Name matching should find existing Computer/User nodes directly
    
    # Create and add relationship edges
    for task in tasks:
        task_edges = _create_relationship_edges(task, computer_sid_map, user_sid_map)
        for edge in task_edges:
            # Use add_edge_without_validation to allow edges to reference
            # Computer/User nodes that exist in BloodHound but not in our local graph
            graph.add_edge_without_validation(edge)
    
    info(f"Created {graph.get_edge_count()} relationships (HasTask + RunsAs)")

    # Export to single file - bhopengraph includes both nodes and edges automatically
    output_file = output_path / "taskhound_opengraph.json"
    graph.export_to_file(str(output_file))
    
    good(f"OpenGraph file: {output_file}")
    
    return str(output_file)


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
    hostname = task.get("host", "").strip().upper()
    task_path = task.get("path", "").strip()
    
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
        "objectid": object_id,
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
        kinds=["scheduledtask", "Base", "TaskHound"],
        properties=Properties(**properties_dict)
    )
    
    return node


def _create_principal_id(runas_user: str, local_domain: str, task: Dict) -> Optional[str]:
    """
    Create BloodHound-compatible principal ID from RunAs user.
    
    Handles various formats and filters out accounts that should not have edges:
    - Built-in accounts (NT AUTHORITY\\SYSTEM, etc.)
    - SID format (S-1-5-*)
    - Cross-domain users (with warning)
    
    Supported input formats:
    - UPN: user@domain.lab
    - NETBIOS: DOMAIN\\user
    - samAccountName: user
    
    :param runas_user: RunAs user from task (various formats)
    :param local_domain: FQDN domain of the computer (e.g., DOMAIN.LAB)
    :param task: Full task dict for logging context
    :return: Principal ID in BloodHound format (USER@DOMAIN.LAB) or None if should skip
    """
    # Skip empty/invalid
    if not runas_user or runas_user.upper() == "N/A":
        return None
    
    # Skip SIDs (start with S-1-5-)
    if runas_user.startswith("S-1-5-"):
        return None
    
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
            # Cross-domain UPN!
            task_path = task.get("path", "unknown")
            hostname = task.get("host", "unknown")
            warn(f"Cross-domain task detected on {hostname}: {task_path}")
            warn(f"  RunAs user: {runas_user} (local domain: {local_domain})")
            warn(f"  Edge will not be created unless '{domain_part}' domain exists in BloodHound")
            return None
        
        # UPN domain matches - return normalized format
        return f"{user_part}@{local_domain}"
    
    # Parse NETBIOS domain\user format
    if "\\" in runas_user:
        domain_prefix, user = runas_user.split("\\", 1)
        domain_prefix = domain_prefix.strip().upper()
        user = user.strip().upper()
        
        # Extract first part of FQDN for comparison (e.g., DOMAIN.LAB -> DOMAIN)
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
            # Cross-domain task!
            task_path = task.get("path", "unknown")
            hostname = task.get("host", "unknown")
            warn(f"Cross-domain task detected on {hostname}: {task_path}")
            warn(f"  RunAs user: {runas_user} (local domain: {local_domain})")
            warn(f"  Edge will not be created unless '{domain_prefix_short}' domain exists in BloodHound")
            # TODO: Check if domain exists in BloodHound data
            # For now, skip cross-domain tasks to avoid broken edges
            return None
        
        # If it's a local account, skip creating edge (local accounts aren't in BloodHound)
        if is_local_account:
            debug(f"Skipping local account: {runas_user} on {hostname_fqdn}")
            return None
        
        # Use full FQDN format
        return f"{user}@{local_domain}"
    else:
        # No domain prefix and no @ - assume local domain
        user = runas_user.strip().upper()
        return f"{user}@{local_domain}"


def _create_relationship_edges(task: Dict, 
                              computer_sid_map: Dict[str, str] = None,
                              user_sid_map: Dict[str, str] = None) -> List[Edge]:
    """
    Creates HasTask and RunsAs edges for a single task using bhopengraph.
    
    If SID mappings are provided, uses objectIds directly (best practice).
    Otherwise falls back to name matching (may create duplicate nodes).
    
    :param task: Task dictionary from TaskHound engine
    :param computer_sid_map: Optional mapping of computer FQDN → objectId (SID)
    :param user_sid_map: Optional mapping of user principal → objectId (SID)
    :return: List of Edge instances
    """
    edges = []
    hostname = task.get("host", "UNKNOWN_HOST").upper()
    task_path = task.get("path", "UNKNOWN_PATH")
    runas_user = task.get("runas", "N/A")

    # Extract domain from hostname FQDN (e.g., DC01.DOMAIN.LAB -> DOMAIN.LAB)
    # Note: hostname is already resolved to FQDN via SMB in engine.py:630 (get_server_fqdn)
    def _extract_domain_from_fqdn(fqdn: str) -> str:
        """Extract domain from FQDN hostname."""
        if "." in fqdn:
            parts = fqdn.split(".")
            if len(parts) >= 2:
                return ".".join(parts[1:]).upper()
        return "WORKGROUP"  # Fallback for non-domain systems
    
    fqdn_domain = _extract_domain_from_fqdn(hostname)

    # Create task object ID using hash-based function (same as in _create_task_node)
    task_object_id = _create_task_object_id(hostname, task_path)

    # 1. Create (Computer)-[HasTask]->(ScheduledTask) edge
    # Differentiate edge type based on whether credentials are stored
    credentials_hint = task.get("credentials_hint", "unknown")
    has_stored_creds = credentials_hint == "stored_credentials"
    
    # Use different edge kind based on credential storage
    edge_kind = "HasTaskWithStoredCreds" if has_stored_creds else "HasTask"
    
    has_task_edge = Edge(
        start_node=hostname,  # Computer name (FQDN from SMB resolution)
        end_node=task_object_id,
        kind=edge_kind,
        start_match_by="name",  # Match existing Computer node by name property
        end_match_by="id"  # Match ScheduledTask node by id field
    )
    debug(f"Created {edge_kind} edge: {hostname} → {task_path}")
    
    edges.append(has_task_edge)

    # 2. Create (ScheduledTask)-[RunsAs]->(Principal) edge
    # Use helper function to create principal ID with proper filtering
    principal_id = _create_principal_id(runas_user, fqdn_domain, task)
    
    if principal_id:
        # TESTING: Force name matching to see if objectId matching is the issue
        runs_as_edge = Edge(
            start_node=task_object_id,
            end_node=principal_id,  # Principal ID (USER@DOMAIN.LAB format)
            kind="RunsAs",
            start_match_by="id",  # Match ScheduledTask node by id field
            end_match_by="name"  # Match existing User node by name property
        )
        debug(f"Created RunsAs edge with name matching: {task_path} → {principal_id}")
        
        edges.append(runs_as_edge)

    return edges
