#!/usr/bin/env python3
"""
Simple BloodHound Connector for TaskHound

Provides basic connectivity to BloodHound instances for real-time high-value user data.
Supports both BHCE (API) and Legacy (Neo4j Bolt) connections.

Author: 0xr0BIT
"""

import contextlib
import json
from typing import Any

import requests

try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None  # type: ignore[assignment, misc]  # conditional import fallback
from ..resolver import TrustInfo
from ..utils.bh_auth import BloodHoundAuthenticator
from ..utils.helpers import sanitize_json_string
from ..utils.logging import debug, good, status, warn


def _bhce_nodes(data: dict | None) -> dict:
    """Return the nodes map from a BHCE cypher response (data["data"]["nodes"]), or {}."""
    return (data or {}).get("data", {}).get("nodes", {})


def _first_node(nodes: dict) -> Any:
    """Return the first node from a BHCE nodes map. Caller must ensure nodes is non-empty."""
    return list(nodes.values())[0]


def _safe_get_sam(data: dict, key: str) -> str:
    """
    Safely extract SAM account name from data, handling None values.

    Args:
        data: Dictionary containing user data
        key: Key to look up ('SamAccountName', 'samaccountname', etc.)

    Returns:
        Lowercase SAM account name as string, empty string if None/missing
    """
    value = data.get(key, "")
    if value is None:
        return ""
    return str(value).lower()


class BloodHoundConnector:
    """Simple BloodHound connector for both BHCE and Legacy"""

    def __init__(
        self,
        bh_type: str,
        ip: str,
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
        api_key_id: str | None = None,
        timeout: int = 120,
    ):
        self.bh_type = bh_type  # 'bhce' or 'legacy'
        self.ip = ip
        self.username = username
        self.password = password
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.timeout = timeout
        self.users_data: dict[str, Any] = {}

        # Initialize authenticator for BHCE
        # ip can be a full URI (http://host:port) or just hostname
        if "://" in self.ip:
            base_url = self.ip
        else:
            base_url = f"http://{self.ip}:8080"
        self.authenticator = BloodHoundAuthenticator(
            base_url=base_url,
            username=username,
            password=password,
            api_key=api_key,
            api_key_id=api_key_id,
            timeout=timeout,
        )

    def run_cypher_query(self, query: str) -> dict | None:
        """
        Execute a Cypher query against BloodHound CE (API) or Legacy (Neo4j Bolt).

        Args:
            query: The Cypher query string

        Returns:
            JSON response data (dict) or None if failed.
            Format: {"data": {"data": [records], "nodes": {...}}} for compatibility.
        """
        if self.bh_type == "bhce":
            return self._run_cypher_query_bhce(query)
        else:
            return self._run_cypher_query_legacy(query)

    def _run_cypher_query_bhce(self, query: str) -> dict | None:
        """Execute Cypher query against BHCE via REST API."""
        # Prepare Query Body - include_properties=True ensures node properties are returned
        body = {"query": query, "include_properties": True}

        try:
            response = self.authenticator.request("POST", "/api/v2/graphs/cypher", body)

            if response and response.status_code == 200:
                return response.json()
            elif response:
                warn(f"BloodHound API returned status {response.status_code}: {response.text}")
                return None
            else:
                # Error already logged by authenticator
                return None

        except Exception as e:
            warn(f"Error executing Cypher query: {e}")
            return None

    @contextlib.contextmanager
    def _legacy_driver(self):
        """Yield a Neo4j driver for the legacy bolt connection (port 7687); always closes it.

        Callers must still guard `if GraphDatabase is None` first — the no-driver
        return value differs per caller. The try/finally here guarantees the driver
        is closed even when a caller returns from inside a `with driver.session()`.
        """
        driver = GraphDatabase.driver(f"bolt://{self.ip}:7687", auth=(self.username, self.password))  # type: ignore[arg-type]  # Optional credentials validated before use
        try:
            yield driver
        finally:
            driver.close()

    def _run_cypher_query_legacy(self, query: str) -> dict | None:
        """
        Execute Cypher query against Legacy BloodHound via Neo4j Bolt.

        Returns data in BHCE-compatible format for caller compatibility.
        """
        if GraphDatabase is None:
            debug("neo4j library not installed - cannot execute Legacy Cypher query")
            return None

        try:
            with self._legacy_driver() as driver, driver.session() as session:
                result = session.run(query)
                # Convert Neo4j records to list of dicts
                records = [dict(record) for record in result]

            # Return in BHCE-compatible format
            # BHCE returns: {"data": {"data": [...], "nodes": {...}}}
            # For simple queries like SID resolution, callers expect data.data[0].name
            return {"data": {"data": records}}

        except Exception as e:
            debug(f"Legacy Cypher query failed: {e}")
            return None

    def connect_and_query(self) -> bool:
        """Connect to BloodHound and query high-value users"""
        try:
            if self.bh_type == "bhce":
                return self._query_bhce()
            elif self.bh_type == "legacy":
                return self._query_legacy()
            else:
                warn(f"Unknown BloodHound type: {self.bh_type}")
                return False
        except Exception as e:
            warn(f"BloodHound connection failed: {e}")
            return False

    def _query_bhce(self) -> bool:
        """Query BHCE via API"""
        # base_url is handled by authenticator

        # Get authentication headers
        try:
            # Test connection
            response = self.authenticator.request("GET", "/api/version")

            if not response or response.status_code != 200:
                warn(f"BloodHound connection failed - HTTP {response.status_code if response else 'No Response'}")
                return False

            status(f"[+] Connected to BHCE at {self.authenticator.base_url}")
            status("[*] Collecting high-value user data from BloodHound (be patient)")

        except requests.exceptions.ConnectionError:
            warn(f"BloodHound BHCE connection failed at {self.authenticator.base_url}")
            warn("Check if BHCE is running and accessible")
            return False
        except requests.exceptions.Timeout:
            warn(f"BloodHound BHCE connection timed out at {self.authenticator.base_url}")
            return False

        # Comprehensive query for BHCE - simplified format that BHCE actually supports
        # BHCE requires path-based queries, not direct property returns
        comprehensive_query = """
        MATCH (n)
        WHERE coalesce(n.system_tags, "") CONTAINS "admin_tier_0"
           OR n.highvalue = true
           OR n.admincount = true
        MATCH p = (n)-[:MemberOf*0..]->(g:Group)
        RETURN p
        """

        # Single comprehensive query for all users
        query_data = {"query": comprehensive_query, "include_properties": True}

        try:
            response = self.authenticator.request("POST", "/api/v2/graphs/cypher", query_data)

            if not response or response.status_code != 200:
                warn(f"BloodHound BHCE query failed - HTTP {response.status_code if response else 'No Response'}")
                if response and response.status_code == 400:
                    warn("Query format error - check Cypher syntax")
                return False

            # Parse response with JSON sanitization
            sanitized_response = sanitize_json_string(response.text)
            result = json.loads(sanitized_response)

            # Parse BHCE results - handle the actual BHCE response format
            if "data" in result:
                response_data = result["data"]
                users_found: set[str] = set()  # Track unique users

                # BHCE returns nodes in a different format than expected
                if "nodes" in response_data:
                    # Handle direct node results (from simple user queries)
                    nodes = response_data["nodes"]
                    for _, node_data in nodes.items():
                        if node_data.get("kind") == "User":
                            properties = node_data.get("properties", {})
                            # Get group memberships for this user
                            username = properties.get("samaccountname", "")
                            group_sids, group_names = self._get_user_groups_bhce(username)
                            properties["group_sids"] = group_sids
                            properties["group_names"] = group_names
                            self._process_bhce_user(properties, users_found)

                elif isinstance(response_data, list):
                    # Handle list format (from path queries)
                    # Paths contain user→group relationships via MemberOf edges
                    for item in response_data:
                        if isinstance(item, dict) and "segments" in item:
                            # Extract user and their group memberships from path
                            user_node = None
                            group_sids = []
                            group_names = []

                            for segment in item.get("segments", []):
                                start_node = segment.get("start", {})
                                end_node = segment.get("end", {})

                                # Find the user node (should be at start of path)
                                if (
                                    start_node.get("labels")
                                    and "User" in start_node["labels"]
                                    and user_node is None
                                ):
                                    user_node = start_node.get("properties", {})

                                # Collect groups from end nodes
                                if end_node.get("labels") and "Group" in end_node["labels"]:
                                    group_props = end_node.get("properties", {})
                                    group_sid = group_props.get("objectid", "")
                                    group_name = group_props.get("name", "")
                                    if group_sid and group_sid not in group_sids:
                                        group_sids.append(group_sid)
                                        group_names.append(group_name)

                            # Process user with collected group memberships
                            if user_node:
                                user_node["group_sids"] = group_sids
                                user_node["group_names"] = group_names
                                self._process_bhce_user(user_node, users_found)

                        # Handle direct user results (from fallback query)
                        elif isinstance(item, dict):
                            sam = _safe_get_sam(item, "samaccountname")
                            if sam and sam not in users_found:
                                self._process_bhce_user(item, users_found)

                good(f"Retrieved {len(self.users_data)} high-value users from BHCE")
                return True
            else:
                warn("No data found in BHCE response")
                return True

        except requests.exceptions.Timeout:
            warn("BloodHound BHCE query timed out")
            return False

    def _query_legacy(self) -> bool:
        """Query Legacy BloodHound via Neo4j Bolt"""
        if GraphDatabase is None:
            warn("neo4j library not installed - required for Legacy BloodHound connection")
            warn("Install with: pip install neo4j")
            return False

        # Comprehensive query for both high-value and Tier 0 users
        # This combines high-value detection with Tier 0 group membership
        comprehensive_query = """
        MATCH (u:User)
        WHERE u.highvalue = true
           OR u.admincount = true
        OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
        WITH u, properties(u) as all_props, collect(g.name) as groups, collect(g.objectid) as group_sids
        RETURN u.samaccountname AS SamAccountName, all_props, groups, group_sids
        ORDER BY SamAccountName
        UNION
        MATCH (u:User)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid =~ 'S-1-5-32-544.*'
           OR g.objectid =~ '.*-512$'
           OR g.objectid =~ '.*-519$'
           OR g.objectid =~ '.*-518$'
           OR g.objectid =~ '.*-516$'
           OR g.objectid =~ '.*-526$'
           OR g.objectid =~ '.*-527$'
           OR g.objectid =~ '.*-500$'
        OPTIONAL MATCH (u)-[:MemberOf*1..]->(all_g:Group)
        WITH u, properties(u) as all_props, collect(all_g.name) as groups, collect(all_g.objectid) as group_sids
        RETURN u.samaccountname AS SamAccountName, all_props, groups, group_sids
        ORDER BY SamAccountName
        """

        try:
            with self._legacy_driver() as driver:
                # Test connection
                try:
                    with driver.session() as session:
                        result = session.run("MATCH (n) RETURN count(n) LIMIT 1")
                        record = result.single()
                        if record is None:
                            return False
                        record[0]  # This will raise an exception if connection fails

                    status(f"[+] Connected to Legacy BloodHound at {self.ip}:7687")
                    status("[*] Collecting high-value user data from BloodHound (be patient)")

                except Exception as e:
                    if "authentication" in str(e).lower() or "credentials" in str(e).lower():
                        warn("BloodHound login failed - invalid credentials")
                    else:
                        warn(f"BloodHound Legacy connection failed at {self.ip}:7687")
                        warn("Check if Neo4j is running and accessible")
                    return False

                with driver.session() as session:
                    users_found: set[str] = set()

                    # Single comprehensive query instead of multiple queries
                    try:
                        result = session.run(comprehensive_query)
                        for record in result:
                            self._process_legacy_user(record, users_found)

                        if len(users_found) == 0:
                            warn("No high-value or Tier 0 users found in Legacy BloodHound")
                        else:
                            good(f"Retrieved {len(users_found)} high-value users from Legacy BloodHound")

                    except Exception as e:
                        warn(f"Legacy BloodHound query failed: {e}")
                        return False

                return True

        except Exception as e:
            warn(f"BloodHound query execution failed: {e}")
            return False

    def _get_user_groups_bhce(self, username: str) -> tuple:
        """Get group memberships for a user in BHCE"""
        if not username:
            return [], []

        try:
            # Query for this user's group memberships using samaccountname
            group_query = f"""
            MATCH (u:User {{samaccountname: "{username}"}})-[:MemberOf*1..]->(g:Group)
            RETURN g
            """

            # run_cypher_query handles auth and returns the node in the "nodes" map
            data = self.run_cypher_query(group_query)

            if data:
                # Parse the response to extract group data
                # run_cypher_query returns the JSON response directly
                group_sids = []
                group_names = []

                if "data" in data and "nodes" in data["data"]:
                    nodes = data["data"]["nodes"]
                    for _, node_data in nodes.items():
                        if node_data.get("kind") == "Group":
                            properties = node_data.get("properties", {}) or {}
                            objectid = properties.get("objectid", "") or ""
                            name = properties.get("name", "") or ""

                            if objectid:
                                group_sids.append(objectid)
                                group_names.append(name)

                return group_sids, group_names
            else:
                return [], []

        except Exception:
            return [], []

    def _process_bhce_user(self, user_data: dict, users_found: set):
        """Process a user from BHCE format and add to users_data"""
        sam = _safe_get_sam(user_data, "samaccountname")
        if not sam or sam in users_found:
            return

        users_found.add(sam)
        self.users_data[sam] = {
            "sid": user_data.get("objectid", user_data.get("sid", "")) or "",
            "samaccountname": sam,
            "domain": user_data.get("domain", "") or "",
            "admincount": user_data.get("admincount", False),
            "pwdlastset": user_data.get("pwdlastset"),
            "lastlogon": user_data.get("lastlogon"),
            "system_tags": user_data.get("system_tags", "") or "",
            "highvalue": user_data.get("highvalue", False),
            "groups": user_data.get("group_sids", []) or [],  # Actual group SIDs
            "group_names": user_data.get("group_names", []) or [],
        }

    def _process_legacy_user(self, record, users_found: set):
        """Process a user from Legacy BloodHound format (matches README query)"""
        sam = _safe_get_sam(record, "SamAccountName")
        if not sam or sam in users_found:
            return

        users_found.add(sam)
        all_props = record.get("all_props", {}) or {}  # Ensure it's never None
        groups = record.get("groups", []) or []  # Ensure it's never None
        group_sids = record.get("group_sids", []) or []  # Ensure it's never None

        # Ensure all_props is a dictionary
        if not isinstance(all_props, dict):
            all_props = {}

        self.users_data[sam] = {
            "SamAccountName": sam,
            "all_props": all_props,
            "groups": group_sids,  # SIDs for compatibility with existing code
            "group_names": groups,  # Display names
            # Extract common fields from all_props for compatibility (with None safety)
            "sid": all_props.get("objectid", "") or "",
            "samaccountname": sam,
            "domain": all_props.get("domain", "") or "",
            "admincount": all_props.get("admincount", False),
            "pwdlastset": all_props.get("pwdlastset"),
            "lastlogon": all_props.get("lastlogon"),
        }

    def get_all_computers(self) -> dict[str, str]:
        """
        Get all computer objects from BloodHound and return hostname -> SID mapping.

        Works with both BHCE (API) and Legacy BloodHound (Neo4j).

        Returns:
            Dict mapping uppercase hostname (without domain suffix) to SID
            Example: {"DC01": "S-1-5-21-...-1001", "FILESERVER": "S-1-5-21-...-1002"}
        """
        computers: dict[str, str] = {}

        # Same Cypher query works for both BHCE and Legacy
        query = "MATCH (c:Computer) RETURN c"

        try:
            if self.bh_type == "bhce":
                data = self.run_cypher_query(query)

                if data:
                    nodes = _bhce_nodes(data)

                    for _, node_data in nodes.items():
                        object_id = node_data.get("objectId", "")
                        label = node_data.get("label", "")

                        if not object_id or not label:
                            continue

                        # Extract hostname from label (e.g., "DC01.CORP.LOCAL@CORP.LOCAL" -> "DC01")
                        hostname = label.split("@")[0] if "@" in label else label

                        # Strip domain suffix
                        if "." in hostname:
                            hostname = hostname.split(".")[0]

                        hostname = hostname.upper()
                        if hostname:
                            computers[hostname] = object_id.upper()

            elif self.bh_type == "legacy":
                if GraphDatabase is None:
                    warn("neo4j library not installed - required for Legacy BloodHound")
                    return computers

                with self._legacy_driver() as driver, driver.session() as session:
                    result = session.run(query)
                    for record in result:
                        node = record["c"]
                        properties = dict(node) if node else {}

                        object_id = properties.get("objectid", "")
                        name = properties.get("name", "")

                        if not object_id or not name:
                            continue

                        # Extract hostname from name (e.g., "DC01.CORP.LOCAL" -> "DC01")
                        hostname = name
                        if "." in hostname:
                            hostname = hostname.split(".")[0]

                        hostname = hostname.upper()
                        if hostname:
                            computers[hostname] = object_id.upper()

            debug(f"BloodHound: Loaded {len(computers)} computer SIDs")
            return computers

        except Exception as e:
            warn(f"Error querying computers from BloodHound: {e}")
            return computers

    def query_domain_by_netbios(self, netbios_name: str) -> dict[str, str] | None:
        """
        Query BloodHound for domain by NETBIOS name using STARTS WITH matching.

        This handles NETBIOS → FQDN resolution for cross-domain tasks:
        - "THESIMPSONS" → "THESIMPSONS.SPRINGFIELD.LOCAL"
        - "DEV" → "DEV.CONTOSO.COM"

        Args:
            netbios_name: NETBIOS domain name (e.g., "THESIMPSONS", "DEV")

        Returns:
            Dict with 'name' (FQDN) and 'objectid' (domain SID), or None if not found
        """
        if self.bh_type != "bhce":
            warn("Domain query only supported for BloodHound CE")
            return None

        try:
            # Build Cypher query with case-insensitive STARTS WITH
            # Note: Must add '.' after NETBIOS to avoid matching parent domains
            # Example: "SPRINGFIELD." matches "SPRINGFIELD.LOCAL" not "THESIMPSONS.SPRINGFIELD.LOCAL"
            query = f"MATCH (d:Domain) WHERE toLower(d.name) STARTS WITH '{netbios_name.lower()}.' RETURN d"

            data = self.run_cypher_query(query)

            if data:
                nodes = _bhce_nodes(data)

                if not nodes:
                    return None
                if len(nodes) > 1:
                    # Multiple matches - extremely rare but possible; warn and take the first
                    domain_names = [n.get("label") for n in nodes.values()]
                    warn(f"Multiple domains match NETBIOS '{netbios_name}': {domain_names}")
                node = _first_node(nodes)
                return {"name": node.get("label"), "objectid": node.get("objectId")}
            return None

        except Exception as e:
            warn(f"Error querying domain '{netbios_name}': {e}")
            return None

    def query_all_domain_sids(self) -> dict[str, str | TrustInfo]:
        """
        Query BloodHound for all domain SID prefixes (own domain + trusts).

        This is used during warmup to cache known domain SID prefixes for
        efficient classification of SIDs during scanning. Unknown SID prefixes
        are likely local machine accounts that cannot be resolved via DC.

        Also queries trust relationships to determine trust type:
        - SameForestTrust: Intra-forest trust (GC will work for resolution)
        - CrossForestTrust: External trust (GC won't work, need DNS/FQDN)

        Returns:
            Dict mapping domain SID prefix -> TrustInfo (for trusts) or domain FQDN string (for own domain)
            e.g., "S-1-5-21-123-456-789" -> TrustInfo(fqdn="CHILD.CORP.LOCAL", is_intra_forest=True)
        """
        result: dict[str, str | TrustInfo] = {}

        if self.bh_type != "bhce":
            debug("Domain SID query only supported for BloodHound CE")
            return result

        try:
            # First, query all Domain nodes - they contain the domain SID as objectId
            query = "MATCH (d:Domain) RETURN d"
            data = self.run_cypher_query(query)

            if data:
                # Parse nodes from BHCE response format (same as other methods)
                nodes = _bhce_nodes(data)

                for _, node_data in nodes.items():
                    # Extract name (label) and objectId from node
                    name = node_data.get("label", "")
                    objectid = node_data.get("objectId", "")

                    if name and objectid and objectid.startswith("S-1-5-21-"):
                        # Store the SID prefix (domains don't have trailing RID in objectid)
                        # Domain SIDs are S-1-5-21-X-Y-Z format
                        # Initially store as string (own domain), will upgrade trusts below
                        result[objectid] = name
                        debug(f"Cached domain SID: {objectid} -> {name}")

            # Now query trust relationships to determine trust type
            # SameForestTrust = intra-forest, CrossForestTrust = external
            trust_query = "MATCH p = (:Domain)-[r:SameForestTrust|CrossForestTrust]->(:Domain) RETURN p"
            trust_data = self.run_cypher_query(trust_query)

            if trust_data:
                # BHCE response: nodes is dict {id: node}, edges is list of edge objects
                data_section = trust_data.get("data", {})
                edges = data_section.get("edges", [])  # List of edge dicts
                nodes = data_section.get("nodes", {})  # Dict of node_id -> node

                for edge_data in edges:
                    edge_kind = edge_data.get("kind", "")
                    target_node_id = str(edge_data.get("target", ""))

                    # Find target domain node to get its SID
                    target_node = nodes.get(target_node_id, {})
                    target_sid = target_node.get("objectId", "")
                    target_name = target_node.get("label", "")

                    if target_sid and target_sid.startswith("S-1-5-21-"):
                        # Determine trust type from edge kind
                        is_intra_forest = edge_kind == "SameForestTrust"

                        # Upgrade from string to TrustInfo
                        result[target_sid] = TrustInfo(
                            fqdn=target_name,
                            is_intra_forest=is_intra_forest,
                            trust_attributes=0,  # BloodHound doesn't expose this
                        )
                        trust_type = "intra-forest" if is_intra_forest else "external"
                        debug(f"Trust type for {target_name}: {trust_type}")

            if result:
                # Count trust types for logging
                # Note: "own" domain is determined at runtime by SID resolver using local_domain_sid_prefix
                # Here we just report what BloodHound knows about trust relationships
                intra_count = sum(1 for v in result.values() if isinstance(v, TrustInfo) and v.is_intra_forest)
                external_count = sum(1 for v in result.values() if isinstance(v, TrustInfo) and not v.is_intra_forest)
                trust_info = ""
                if intra_count or external_count:
                    trust_info = f" ({intra_count} intra-forest, {external_count} external trusts)"
                good(f"Loaded {len(result)} domain SID prefixes from BloodHound{trust_info}")

        except Exception as e:
            warn(f"Error querying domain SIDs from BloodHound: {e}")

        return result

    def query_user_by_upn(self, upn: str) -> dict[str, str] | None:
        """
        Query BloodHound for user by UPN (User Principal Name).

        Validates that a user exists in BloodHound and retrieves their node info.
        Used for cross-domain user validation without requiring LDAP queries.

        Args:
            upn: User Principal Name (e.g., "ADMINISTRATOR@THESIMPSONS.SPRINGFIELD.LOCAL")

        Returns:
            Dict with 'name' (UPN), 'objectid' (user SID), and 'node_id' (BH node ID), or None if not found
        """
        if self.bh_type != "bhce":
            warn("User query only supported for BloodHound CE")
            return None

        try:
            # Build Cypher query - match by name (which is UPN for users in BloodHound)
            # Use case-insensitive matching for reliability
            query = f"MATCH (u:User) WHERE toLower(u.name) = '{upn.lower()}' RETURN u"

            data = self.run_cypher_query(query)

            if data:
                nodes = _bhce_nodes(data)

                if not nodes:
                    return None
                if len(nodes) > 1:
                    # Multiple matches - should never happen for UPN (unique), but handle it
                    warn(f"Multiple users match UPN '{upn}': {[n.get('label') for n in nodes.values()]}")
                node_id = list(nodes.keys())[0]
                node = _first_node(nodes)
                return {"name": node.get("label"), "objectid": node.get("objectId"), "node_id": node_id}
            return None

        except Exception as e:
            warn(f"Error querying user '{upn}': {e}")
            return None

    def get_user_properties(self, identifier: str) -> dict[str, Any] | None:
        """
        Query BloodHound for a user's properties by SID or UPN.

        IMPORTANT: Always prefer SID lookups to avoid cross-domain ambiguity.
        sAMAccountName is NOT unique across domains - only SIDs are!

        This is used for on-demand lookups of user properties like pwdLastSet
        for users not in the pre-loaded high-value data.

        Args:
            identifier: User identifier - can be:
                - SID (e.g., "S-1-5-21-123-456-789-1001") - PREFERRED
                - UPN (e.g., "admin@CORP.LOCAL") - unique across domains
                - DOMAIN\\user format - will be converted to UPN if possible

        Returns:
            Dict with user properties including 'pwdlastset', 'lastlogon', 'sid', etc.
            or None if user not found
        """
        if self.bh_type == "bhce":
            return self._get_user_properties_bhce(identifier)
        else:
            return self._get_user_properties_legacy(identifier)

    def _get_user_properties_bhce(self, identifier: str) -> dict[str, Any] | None:
        """Get user properties from BloodHound CE API.

        Queries by SID (objectId) when possible, falls back to UPN (name).
        NEVER queries by sAMAccountName alone due to cross-domain ambiguity.
        """
        try:
            # Determine query type based on identifier format
            identifier = identifier.strip()

            if identifier.upper().startswith("S-1-5-"):
                # SID lookup - PREFERRED (globally unique)
                query = f"MATCH (u:User) WHERE u.objectid = '{identifier.upper()}' RETURN u"
                debug(f"Querying BloodHound by SID: {identifier}")
            elif "@" in identifier:
                # UPN lookup - also unique (user@DOMAIN.FQDN)
                query = f"MATCH (u:User) WHERE toLower(u.name) = '{identifier.lower()}' RETURN u"
                debug(f"Querying BloodHound by UPN: {identifier}")
            elif "\\" in identifier:
                # DOMAIN\user format - need to convert to query both domain and sam
                # This is less reliable but better than sam alone
                parts = identifier.split("\\", 1)
                domain_part = parts[0].upper()
                user_part = parts[1].lower()
                # Query by both domain and samaccountname to reduce ambiguity
                query = f"MATCH (u:User) WHERE toLower(u.samaccountname) = '{user_part}' AND toUpper(u.domain) CONTAINS '{domain_part}' RETURN u"
                debug(f"Querying BloodHound by domain+sam: {identifier}")
            else:
                # Plain username - DANGEROUS, may match multiple domains!
                # Log a warning but try anyway
                debug(f"WARNING: Querying by sAMAccountName alone is ambiguous: {identifier}")
                query = f"MATCH (u:User) WHERE toLower(u.samaccountname) = '{identifier.lower()}' RETURN u LIMIT 1"

            data = self.run_cypher_query(query)

            if data:
                nodes = _bhce_nodes(data)

                if nodes:
                    node_data = _first_node(nodes)
                    properties = node_data.get("properties", {})

                    return {
                        "samaccountname": properties.get("samaccountname", ""),
                        "sid": node_data.get("objectId", ""),
                        "pwdlastset": properties.get("pwdlastset"),
                        "lastlogon": properties.get("lastlogon"),
                        "admincount": properties.get("admincount", False),
                        "enabled": properties.get("enabled", True),
                        "domain": properties.get("domain", ""),
                    }
            return None

        except Exception as e:
            debug(f"Error querying user properties for '{identifier}': {e}")
            return None

    def _get_user_properties_legacy(self, identifier: str) -> dict[str, Any] | None:
        """Get user properties from Legacy BloodHound via Neo4j.

        Queries by SID (objectid) when possible, falls back to UPN (name).
        NEVER queries by sAMAccountName alone due to cross-domain ambiguity.
        """
        if GraphDatabase is None:
            debug("neo4j library not installed - cannot query Legacy BloodHound")
            return None

        try:
            identifier = identifier.strip()

            # Determine query type based on identifier format
            if identifier.upper().startswith("S-1-5-"):
                # SID lookup - PREFERRED
                query = f"MATCH (u:User) WHERE u.objectid = '{identifier.upper()}' RETURN u"
            elif "@" in identifier:
                # UPN lookup
                query = f"MATCH (u:User) WHERE toLower(u.name) = '{identifier.lower()}' RETURN u"
            elif "\\" in identifier:
                # DOMAIN\user format
                parts = identifier.split("\\", 1)
                domain_part = parts[0].upper()
                user_part = parts[1].lower()
                query = f"MATCH (u:User) WHERE toLower(u.samaccountname) = '{user_part}' AND toUpper(u.domain) CONTAINS '{domain_part}' RETURN u"
            else:
                # Plain username - ambiguous
                debug(f"WARNING: Querying by sAMAccountName alone is ambiguous: {identifier}")
                query = f"MATCH (u:User) WHERE toLower(u.samaccountname) = '{identifier.lower()}' RETURN u LIMIT 1"

            with self._legacy_driver() as driver, driver.session() as session:
                result = session.run(query)
                record = result.single()

                if record:
                    user_node = record["u"]
                    properties = dict(user_node)

                    return {
                        "samaccountname": properties.get("samaccountname", ""),
                        "sid": properties.get("objectid", ""),
                        "pwdlastset": properties.get("pwdlastset"),
                        "lastlogon": properties.get("lastlogon"),
                        "admincount": properties.get("admincount", False),
                        "enabled": properties.get("enabled", True),
                        "domain": properties.get("domain", ""),
                    }

            return None

        except Exception as e:
            debug(f"Error querying Legacy BH user properties for '{identifier}': {e}")
            return None

    def get_user_gmsa_status(self, username: str) -> dict[str, Any] | None:
        """
        Query BloodHound for user's gMSA/MSA status.

        BloodHound CE stores 'gmsa' and 'msa' boolean properties on User nodes,
        derived from objectClass during SharpHound collection:
        - gmsa=true: objectClass contains 'msds-groupmanagedserviceaccount'
        - msa=true: objectClass contains 'msds-managedserviceaccount'

        Args:
            username: Username to query (with or without domain prefix)

        Returns:
            Dict with 'is_gmsa', 'is_msa', 'name', 'objectid' or None if not found
        """
        if self.bh_type != "bhce":
            # Legacy BloodHound also has these properties, but use Neo4j differently
            return self._get_user_gmsa_status_legacy(username)

        try:
            # Extract username part (remove domain prefix if present)
            clean_username = username
            if "\\" in username:
                clean_username = username.split("\\")[-1]
            elif "@" in username:
                clean_username = username.split("@")[0]

            # Keep the $ suffix for gMSA/MSA accounts - BloodHound stores them with $
            # e.g., "GMSATASK2$@BADSUCCESSOR.LAB"
            query_username = clean_username

            # Build query - search by samaccountname (case-insensitive)
            # Using samaccountname is more reliable than name (UPN) since we have the account name directly
            query = f"MATCH (u:User) WHERE toLower(u.samaccountname) = '{query_username.lower()}' RETURN u"

            data = self.run_cypher_query(query)

            if data:
                nodes = _bhce_nodes(data)

                if nodes:
                    # Get first matching user
                    node_id = list(nodes.keys())[0]
                    node_data = nodes[node_id]
                    properties = node_data.get("properties", {})

                    is_gmsa = properties.get("gmsa", False)
                    is_msa = properties.get("msa", False)

                    # Fallback 1: Check for incoming ReadGMSAPassword edges
                    # This is the most reliable indicator - only gMSAs have this ACL
                    if not is_gmsa and not is_msa:
                        sam = properties.get("samaccountname", "")
                        if sam and self._has_read_gmsa_password_edge(sam):
                            is_gmsa = True
                            debug(f"[BloodHound gMSA] Detected via ReadGMSAPassword edge: {sam}")

                    # Fallback 2: Check distinguishedname for Managed Service Accounts container
                    # SharpHound may not always populate gmsa/msa properties
                    if not is_gmsa and not is_msa:
                        dn = properties.get("distinguishedname", "").upper()
                        if "CN=MANAGED SERVICE ACCOUNTS," in dn:
                            # Account is in MSA container - determine type by $ suffix
                            sam = properties.get("samaccountname", "")
                            if sam.endswith("$"):
                                is_gmsa = True  # gMSA accounts have $ suffix
                                debug(f"[BloodHound gMSA] Detected via DN container: {dn}")
                            else:
                                is_msa = True  # Standalone MSA without $ suffix
                                debug(f"[BloodHound MSA] Detected via DN container: {dn}")

                    return {
                        "is_gmsa": is_gmsa,
                        "is_msa": is_msa,
                        "name": node_data.get("label", ""),
                        "objectid": node_data.get("objectId", ""),
                        "node_id": node_id,
                    }
            return None

        except Exception as e:
            debug(f"Error querying gMSA status for '{username}': {e}")
            return None

    def _has_read_gmsa_password_edge(self, user_name: str) -> bool:
        """
        Check if a user has incoming ReadGMSAPassword edges.

        This is a definitive indicator that the account is a gMSA - only gMSAs
        have this ACL edge in BloodHound.

        Args:
            user_name: The user's sAMAccountName (e.g., "gMSATask2$")

        Returns:
            True if the user has ReadGMSAPassword edges, False otherwise
        """
        try:
            # Query for incoming ReadGMSAPassword edges to this user by sAMAccountName
            query = f"MATCH p=()-[:ReadGMSAPassword]->(u) WHERE toLower(u.samaccountname) = '{user_name.lower()}' RETURN u"
            data = self.run_cypher_query(query)

            if data:
                nodes = _bhce_nodes(data)
                return len(nodes) > 0

            return False
        except Exception as e:
            debug(f"Error checking ReadGMSAPassword edge for '{user_name}': {e}")
            return False

    def _get_user_gmsa_status_legacy(self, username: str) -> dict[str, Any] | None:
        """
        Query Legacy BloodHound (Neo4j) for user's gMSA/MSA status.

        Args:
            username: Username to query (with or without domain prefix)

        Returns:
            Dict with 'is_gmsa', 'is_msa', 'name', 'objectid' or None if not found
        """
        if GraphDatabase is None:
            debug("neo4j library not installed - cannot query Legacy BloodHound for gMSA status")
            return None

        try:
            # Extract username part
            clean_username = username
            if "\\" in username:
                clean_username = username.split("\\")[-1]
            elif "@" in username:
                clean_username = username.split("@")[0]

            # Keep the $ suffix for gMSA/MSA accounts - BloodHound stores them with $
            query_username = clean_username

            # Build query - search by samaccountname (more reliable than UPN)
            query = f"MATCH (u:User) WHERE toLower(u.samaccountname) = '{query_username.lower()}' RETURN u"

            with self._legacy_driver() as driver, driver.session() as session:
                result = session.run(query)
                record = result.single()

                if record:
                    node = record["u"]
                    properties = dict(node) if node else {}

                    is_gmsa = properties.get("gmsa", False)
                    is_msa = properties.get("msa", False)
                    user_name = properties.get("name", "")
                    sam = properties.get("samaccountname", "")

                    # Fallback 1: Check for incoming ReadGMSAPassword edges
                    if not is_gmsa and not is_msa and sam:
                        edge_query = f"MATCH ()-[:ReadGMSAPassword]->(u) WHERE toLower(u.samaccountname) = '{sam.lower()}' RETURN u"
                        edge_result = session.run(edge_query)
                        if edge_result.single():
                            is_gmsa = True
                            debug(f"[Legacy BH gMSA] Detected via ReadGMSAPassword edge: {sam}")

                    # Fallback 2: Check distinguishedname for Managed Service Accounts container
                    # SharpHound may not always populate gmsa/msa properties
                    if not is_gmsa and not is_msa:
                        dn = properties.get("distinguishedname", "").upper()
                        if "CN=MANAGED SERVICE ACCOUNTS," in dn:
                            if sam.endswith("$"):
                                is_gmsa = True
                                debug(f"[Legacy BH gMSA] Detected via DN container: {dn}")
                            else:
                                is_msa = True
                                debug(f"[Legacy BH MSA] Detected via DN container: {dn}")

                    return {
                        "is_gmsa": is_gmsa,
                        "is_msa": is_msa,
                        "name": user_name,
                        "objectid": properties.get("objectid", ""),
                    }

            return None

        except Exception as e:
            debug(f"Error querying Legacy BH gMSA status for '{username}': {e}")
            return None

    def validate_and_resolve_cross_domain_user(self, netbios_domain: str, username: str) -> dict[str, str | None] | None:
        """
        Complete cross-domain user resolution workflow:
        1. Resolve NETBIOS domain to FQDN via BloodHound
        2. Construct UPN with resolved FQDN
        3. Validate user exists in BloodHound
        4. Return user info with SID and node ID

        This replaces LDAP-based resolution and works across domain trusts
        without requiring additional credentials or network access.

        Args:
            netbios_domain: NETBIOS domain name (e.g., "THESIMPSONS", "DEV")
            username: Username without domain (e.g., "ADMINISTRATOR")

        Returns:
            Dict with 'name' (full UPN), 'objectid' (SID), 'node_id', 'domain_fqdn', and 'error_reason',
            or None if not found (with error_reason indicating what failed)
        """
        # Step 1: Resolve domain
        domain_info = self.query_domain_by_netbios(netbios_domain)
        if not domain_info:
            return {"error_reason": "domain_not_found", "domain": netbios_domain}

        domain_fqdn = domain_info["name"]

        # Step 2: Construct UPN and query for user
        upn = f"{username.upper()}@{domain_fqdn}"
        user_info = self.query_user_by_upn(upn)

        if not user_info:
            return {
                "error_reason": "user_not_found",
                "domain": netbios_domain,
                "domain_fqdn": domain_fqdn,
                "username": username,
                "upn": upn,
            }

        # Step 3: Return combined info
        return {
            "name": user_info["name"],
            "objectid": user_info["objectid"],
            "node_id": user_info["node_id"],
            "domain_fqdn": domain_fqdn,
            "domain_sid": domain_info["objectid"],
            "error_reason": None,  # Success
        }

    def get_users_data(self) -> dict[str, Any]:
        """Get the retrieved users data"""
        return self.users_data

    def save_to_file(self, filepath: str) -> bool:
        """Save users data to JSON file (compatible with --bh-data)"""
        try:
            # Convert to list format (compatible with existing HighValueLoader)
            users_list = list(self.users_data.values())

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(users_list, f, indent=2, default=str)

            good(f"BloodHound data saved to {filepath}")
            return True

        except Exception as e:
            warn(f"Failed to save BloodHound data: {e}")
            return False


def connect_bloodhound(args) -> tuple[dict[str, Any] | None, BloodHoundConnector | None]:
    """
    Connect to BloodHound and retrieve high-value users data.

    Supports automatic protocol fallback - if http:// fails, tries https:// and vice versa.

    Args:
        args: Parsed command line arguments

    Returns:
        Tuple of (users_data, connector_instance) or (None, None) if connection failed
    """
    if not args.bh_live:
        return None, None

    # Determine BloodHound type
    bh_type = "bhce" if args.bhce else "legacy"
    is_legacy = bh_type == "legacy"

    # Normalize the connector URI (preserves scheme and adds port if missing)
    from ..output.bloodhound import normalize_bloodhound_connector

    connector_uri = normalize_bloodhound_connector(args.bh_connector, is_legacy=is_legacy)

    display_type = "BHCE" if args.bhce else "Legacy"
    good(f"Connecting to {display_type} BloodHound at {connector_uri}...")

    # Create connector and attempt connection
    connector = BloodHoundConnector(
        bh_type=bh_type,
        ip=connector_uri,  # Full URI with scheme and port
        username=args.bh_user,
        password=args.bh_password,
        api_key=getattr(args, "bh_api_key", None),
        api_key_id=getattr(args, "bh_api_key_id", None),
        timeout=getattr(args, "bh_timeout", 120),
    )

    if connector.connect_and_query():
        users_data = connector.get_users_data()

        # Save to file if requested
        if args.bh_save:
            connector.save_to_file(args.bh_save)

        return users_data, connector

    # Connection failed - try alternate protocol (http <-> https)
    if not is_legacy:  # Only for BHCE (Legacy uses bolt://)
        from ..output.bloodhound import _get_alternate_protocol_uri

        alt_uri = _get_alternate_protocol_uri(connector_uri)
        if alt_uri:
            original_scheme = "https" if connector_uri.startswith("https://") else "http"
            alt_scheme = "http" if original_scheme == "https" else "https"
            warn(f"Connection failed with {original_scheme}://, trying {alt_scheme}://...")

            connector = BloodHoundConnector(
                bh_type=bh_type,
                ip=alt_uri,
                username=args.bh_user,
                password=args.bh_password,
                api_key=getattr(args, "bh_api_key", None),
                api_key_id=getattr(args, "bh_api_key_id", None),
                timeout=getattr(args, "bh_timeout", 120),
            )

            if connector.connect_and_query():
                status(f"[+] Successfully connected using {alt_scheme}://")
                users_data = connector.get_users_data()

                # Save to file if requested
                if args.bh_save:
                    connector.save_to_file(args.bh_save)

                return users_data, connector

    warn("BloodHound connection failed - continuing without high-value data")
    return None, None


