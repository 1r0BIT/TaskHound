# High-value (BloodHound) loader and lookup helpers.
#
# This module loads a CSV or JSON export (from BloodHound/Neo4j) that lists
# high-value users and their SIDs. It provides a small in-memory lookup
# so the rest of the tool can mark tasks that run as those accounts.
#
# The expected schema is simple: rows must contain `SamAccountName` and
# `sid`. The loader is intentionally tolerant of common export quirks
# (UTF-8 BOM, quoted fields, NETBIOS prefixes like DOMAIN\user).

import csv
import json
import os
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from ..utils.date_parser import parse_iso_date, parse_timestamp
from ..utils.helpers import sanitize_json_string
from ..utils.logging import good, warn


def _analyze_password_freshness(task_date: str | None, pwd_change_date: datetime | None) -> tuple[str, str]:
    # Enhanced password analysis relative to task creation date with detailed explanations.
    # Returns (risk_level, explanation) tuple.
    if not task_date or not pwd_change_date:
        return "UNKNOWN", "Insufficient date information for password analysis"

    try:
        # Parse task date (format: 2025-09-18T23:04:37.3089851)
        task_dt = parse_iso_date(task_date)
        if not task_dt:
            return "UNKNOWN", "Date parsing error: Invalid format"

        # Enhanced analysis with better messaging
        if task_dt < pwd_change_date:
            return "BAD", "Password changed AFTER task creation, Password could be stale"
        else:
            return "GOOD", "Password changed BEFORE task creation, password is valid!"
    except (ValueError, TypeError) as e:
        return "UNKNOWN", f"Date parsing error: {e}"


# Well-known Tier 0 SIDs for direct SID-based detection
TIER0_SIDS = {
    "S-1-5-32-544": "Administrators",  # Local Administrators
    "S-1-5-21-{domain}-512": "Domain Admins",  # Domain Admins (domain-relative)
    "S-1-5-21-{domain}-516": "Domain Controllers",  # Domain Controllers
    "S-1-5-21-{domain}-518": "Schema Admins",  # Schema Admins
    "S-1-5-21-{domain}-519": "Enterprise Admins",  # Enterprise Admins
    "S-1-5-21-{domain}-526": "Key Admins",  # Key Admins (Windows Server 2016+)
    "S-1-5-21-{domain}-527": "Enterprise Key Admins",  # Enterprise Key Admins (Windows Server 2016+)
    "S-1-5-21-{domain}-500": "Administrator",  # Built-in Administrator account
    # Additional AdminSDHolder protected groups (lower privilege but still Tier 0)
    "S-1-5-32-551": "Backup Operators",  # Backup Operators
    "S-1-5-32-549": "Server Operators",  # Server Operators
    "S-1-5-32-548": "Account Operators",  # Account Operators
    "S-1-5-32-550": "Print Operators",  # Print Operators
}


class HighValueLoader:
    # Load and query a high-value users export (CSV or JSON).
    # Supports both Legacy BloodHound and BloodHound Community Edition formats.
    #
    # Attributes:
    #     path: source file path
    #     hv_users: mapping from samaccountname -> metadata (currently only sid)
    #     hv_sids: mapping from sid -> metadata (currently only sam)
    #     hv_computers: mapping from hostname (uppercase) -> SID
    #     loaded: True if load() succeeded
    #     format_type: "legacy", "bhce", or "unknown"

    def __init__(self, path: str):
        self.path = path
        self.hv_users: dict[str, dict[str, Any]] = {}
        self.hv_sids: dict[str, dict[str, Any]] = {}
        self.hv_computers: dict[str, str] = {}  # hostname -> SID mapping for computers
        self.hv_domain_sids: dict[str, str] = {}  # domain SID prefix -> FQDN mapping
        self.loaded = False
        self.format_type = "unknown"

    def load(self) -> bool:
        # Detect file type and populate internal maps.
        #
        # Returns True on success, False on any error or unsupported format.
        ext = os.path.splitext(self.path)[1].lower()
        try:
            if ext == ".json":
                ok = self._load_json()
            elif ext == ".csv":
                ok = self._load_csv()
            else:
                warn(f"Unsupported file type for --bh-data: {ext}")
                return False
        except Exception as e:
            warn(f"Failed to load High Value data: {e}")
            return False
        self.loaded = ok
        return ok

    @staticmethod
    def _has_fields(headers: Iterable[str]) -> bool:
        # Return True if headers contain the required fields.
        #
        # Header names are checked case-insensitively.
        # Supports both traditional format and new "all_props" lazy query format.
        if not headers:
            return False
        lower = {h.strip().lower() for h in headers}

        # Traditional format: SamAccountName + (sid OR objectid)
        traditional_format = {"samaccountname"}.issubset(lower) and (
            {"sid"}.issubset(lower) or {"objectid"}.issubset(lower)
        )

        # New lazy query format: SamAccountName + all_props
        new_format = {"samaccountname", "all_props"}.issubset(lower)

        return traditional_format or new_format

    @staticmethod
    def _schema_help():
        # Print a simple help if the schema is wrong
        warn("Invalid schema in custom HV file!")
        warn("    Required fields: SamAccountName + (sid OR objectid)")
        warn("    Optional fields: groups, group_names, pwdlastset, lastlogon")
        warn("    Additional fields: Any BloodHound attribute will be preserved")

    def _parse_list_field(self, data: Any) -> list[str]:
        """
        Parse a field that might be a list, a JSON string array, or a simple string.
        Returns a list of strings.
        """
        if not data:
            return []

        result = []
        if isinstance(data, list):
            result = [str(x).strip() for x in data if x]
        elif isinstance(data, str):
            s = data.strip().strip('"')
            if s.startswith("[") and s.endswith("]"):
                try:
                    parsed = json.loads(s)
                    if isinstance(parsed, list):
                        result = [str(x) for x in parsed]
                except (json.JSONDecodeError, TypeError):
                    # Fallback: treat as single item stripped of brackets
                    result = [s.strip("[]")]
            else:
                # Treat as single item
                result = [s]
        return result

    def _process_user_data(self, row: dict[str, Any]) -> bool:
        # Process a single user record from JSON or CSV data.
        # Extracts required fields and preserves all BloodHound attributes.
        # Supports both traditional format and new "all_props" lazy query format.

        # Check if this is the new "all_props" format
        if "all_props" in row:
            return self._process_all_props_format(row)
        else:
            return self._process_traditional_format(row)

    def _process_all_props_format(self, row: dict[str, Any]) -> bool:
        # Process the new lazy query format with "all_props" object
        # Returns False for invalid records (which will be skipped)
        sam_raw = (row.get("SamAccountName") or "").strip().strip('"').lower()
        all_props_raw = row.get("all_props", {})

        if not sam_raw or not all_props_raw:
            return False

        # Handle all_props as string (CSV) or dict (JSON)
        if isinstance(all_props_raw, str):
            # Parse string representation of dict from CSV (best effort)
            all_props_str = all_props_raw.strip().strip('"')
            all_props = {}

            try:
                # Use regex patterns to extract key information from the string
                import re

                # Extract objectid (SID) - this is critical
                objectid_match = re.search(r'objectid[:\s]*["\']?([S-1-5-][^"\'}\s,]+)', all_props_str)
                if objectid_match:
                    all_props["objectid"] = objectid_match.group(1)

                # Extract pwdlastset timestamp
                pwd_match = re.search(r"pwdlastset[:\s]*([0-9.]+)", all_props_str)
                if pwd_match:
                    all_props["pwdlastset"] = float(pwd_match.group(1))

                # Extract lastlogon timestamp
                logon_match = re.search(r"lastlogon[:\s]*([0-9.]+)", all_props_str)
                if logon_match:
                    all_props["lastlogon"] = float(logon_match.group(1))

                # Extract common boolean fields
                for field in ["highvalue", "enabled", "admincount", "sensitive", "pwdneverexpires"]:
                    field_match = re.search(rf"{field}[:\s]*(\w+)", all_props_str)
                    if field_match:
                        value_str = field_match.group(1).lower()
                        all_props[field] = value_str in ("true", "yes", "1")

                # Extract string fields (name, domain, description, etc.)
                for field in ["name", "domain", "description", "distinguishedname", "samaccountname"]:
                    field_match = re.search(rf'{field}[:\s]*["\']([^"\']+)["\']', all_props_str)
                    if field_match:
                        all_props[field] = field_match.group(1)

                # If we couldn't extract objectid, this record is invalid
                if "objectid" not in all_props:
                    return False

            except (TypeError, AttributeError, re.error):
                # If regex parsing fails completely, skip this record
                return False
        else:
            all_props = all_props_raw

        # Extract SID from all_props
        sid_raw = (all_props.get("objectid") or "").strip().strip('"')
        if not sid_raw:
            return False

        # Normalize sam (handle DOMAIN\user format)
        sam = sam_raw.split("\\", 1)[1] if "\\" in sam_raw else sam_raw

        sid = sid_raw.upper()

        # Process group information from the separate fields
        # Use helper to parse potential JSON arrays or lists
        group_names = self._parse_list_field(row.get("groups"))
        groups = self._parse_list_field(row.get("group_sids"))

        # Create user data starting with all_props and add our additional fields
        user_data = dict(all_props)  # Copy all BloodHound properties
        user_data.update(
            {
                "sid": sid,
                "groups": groups,
                "group_names": group_names,
                "pwdlastset": parse_timestamp(all_props.get("pwdlastset")),
                "lastlogon": parse_timestamp(all_props.get("lastlogon")),
            }
        )

        self.hv_users[sam] = user_data
        # Create SID lookup with sam field added
        self.hv_sids[sid] = dict(user_data)
        self.hv_sids[sid]["sam"] = sam
        return True

    def _process_traditional_format(self, row: dict[str, Any]) -> bool:
        # Process traditional format (existing logic)

        # Extract required fields with fallback names
        sam_raw = (row.get("SamAccountName") or row.get("samaccountname") or "").strip().strip('"').lower()
        sid_raw = (row.get("sid") or row.get("objectid") or "").strip().strip('"')

        if not sam_raw or not sid_raw:
            return False

        # Normalize sam (handle DOMAIN\user format)
        sam = sam_raw.split("\\", 1)[1] if "\\" in sam_raw else sam_raw

        sid = sid_raw.upper()

        # Process group information
        groups = []
        group_names = []

        # Handle group_names field (preferred for human-readable names)
        raw_data = row.get("group_names") or row.get("groups")
        parsed_list = self._parse_list_field(raw_data)

        if parsed_list:
            # Heuristic: check if first item looks like a SID
            if parsed_list[0].upper().startswith("S-1-5-"):
                groups = parsed_list
            else:
                group_names = parsed_list

        # Create user data with core fields
        user_data = {
            "sid": sid,
            "groups": groups,
            "group_names": group_names,
            "pwdlastset": parse_timestamp(row.get("pwdlastset")),
            "lastlogon": parse_timestamp(row.get("lastlogon")),
        }

        # Preserve ALL additional BloodHound attributes for future extensibility
        excluded_keys = {"samaccountname", "sid", "objectid", "groups", "group_names", "pwdlastset", "lastlogon"}
        for key, value in row.items():
            if key.lower() not in excluded_keys:
                # Store additional attributes (enabled, admincount, dontreqpreauth, etc.)
                user_data[key.lower()] = value

        self.hv_users[sam] = user_data
        # Create SID lookup with sam field added
        self.hv_sids[sid] = dict(user_data)
        self.hv_sids[sid]["sam"] = sam
        return True

    def _load_json(self) -> bool:
        with open(self.path, encoding="utf-8-sig") as f:
            # Read raw content and sanitize backslashes before JSON parsing
            raw_content = f.read()
            sanitized_content = sanitize_json_string(raw_content)
            data = json.loads(sanitized_content)
        if not data:
            return False

        # Detect format type
        if self._is_bhce_format(data):
            self.format_type = "bhce"
            good("BloodHound Community Edition export detected")
            return self._load_bhce_json(data)
        elif isinstance(data, list) and len(data) > 0:
            # Check if it's legacy format
            if self._has_fields(data[0].keys()):
                self.format_type = "legacy"
                good("Legacy BloodHound export detected")
                return self._load_legacy_json(data)
            else:
                self._schema_help()
                return False
        else:
            warn("Unrecognized JSON format")
            return False

    def _is_bhce_format(self, data: Any) -> bool:
        # Detect BHCE format by presence of isTierZero field in nodes
        if not isinstance(data, dict):
            return False

        nodes = data.get("nodes", {})
        if not isinstance(nodes, dict):
            return False

        # Check if any node has isTierZero field (key indicator)
        return any(
            isinstance(node_data, dict) and "isTierZero" in node_data
            for node_data in nodes.values()
        )

    def _load_bhce_json(self, data: dict[str, Any]) -> bool:
        # Load BloodHound Community Edition format
        nodes = data.get("nodes", {})
        edges = data.get("edges", [])

        # Process each node
        for _, node_data in nodes.items():
            if not isinstance(node_data, dict):
                continue

            node_kind = node_data.get("kind")

            # Extract core fields
            object_id = (node_data.get("objectId") or "").strip()
            label = (node_data.get("label") or "").strip()
            properties = node_data.get("properties", {})

            if not object_id or not label:
                continue

            # Process Computer nodes - store hostname -> SID mapping
            if node_kind == "Computer":
                # Extract hostname from label (e.g., "DC01.CORP.LOCAL@CORP.LOCAL" -> "DC01")
                hostname = label.split("@")[0] if "@" in label else label

                # Strip domain suffix to get just hostname
                if "." in hostname:
                    hostname = hostname.split(".")[0]

                hostname = hostname.upper()
                if hostname:
                    self.hv_computers[hostname] = object_id.upper()
                continue  # Don't process computers as users

            # Only process Users for high-value detection
            if node_kind != "User":
                continue

            # Extract samaccountname from label (e.g., "HIGHPRIV@BADSUCCESSOR.LAB" -> "highpriv")
            if "@" in label:
                sam = label.split("@")[0].lower()
            else:
                sam_value = properties.get("samaccountname", "") or ""
                sam = str(sam_value).strip().lower()

            if not sam:
                continue

            # Build user data structure compatible with existing code
            user_data = {
                "sid": object_id.upper(),
                "groups": [],  # Will be populated from edges
                "group_names": [],  # Will be populated from edges
                "pwdlastset": parse_timestamp(properties.get("pwdlastset")),
                "lastlogon": parse_timestamp(properties.get("lastlogon")),
            }

            # Copy all properties for extensibility
            # Exclude fields we've already processed with special handling
            for key, value in properties.items():
                if key.lower() not in ["samaccountname", "objectid", "pwdlastset", "lastlogon"]:
                    user_data[key.lower()] = value

            # Add BHCE-specific fields
            user_data["istierzero"] = node_data.get("isTierZero", False)
            user_data["system_tags"] = properties.get("system_tags", "")

            # Store in lookup dictionaries
            self.hv_users[sam] = user_data
            self.hv_sids[object_id.upper()] = dict(user_data)
            self.hv_sids[object_id.upper()]["sam"] = sam

        # Process edges to build group membership information
        # This enables accurate Tier-0 classification based on actual group memberships
        self._process_bhce_edges(nodes, edges)

        return True

    def _process_bhce_edges(self, nodes: dict[str, Any], edges: list[dict[str, Any]]) -> None:
        """Process BHCE edges to extract group membership information"""
        # Create a mapping of node IDs to group information
        groups = {}
        for node_id, node_data in nodes.items():
            if node_data.get("kind") == "Group":
                properties = node_data.get("properties", {})
                groups[node_id] = {"objectid": properties.get("objectid", ""), "name": properties.get("name", "")}

        # Process MemberOf edges to build user group memberships
        for edge in edges:
            if not isinstance(edge, dict):
                continue

            # Look for MemberOf relationships
            if edge.get("kind") != "MemberOf" and edge.get("label") != "MemberOf":
                continue

            source_id = edge.get("source", "")
            target_id = edge.get("target", "")

            if not source_id or not target_id:
                continue

            # Find the user (source) and group (target)
            source_node = nodes.get(source_id, {})
            target_group = groups.get(target_id)

            if source_node.get("kind") != "User" or not target_group:
                continue

            # Extract user info
            properties = source_node.get("properties", {})
            label = source_node.get("label", "")

            if "@" in label:
                sam = label.split("@")[0].lower()
            else:
                sam_value = properties.get("samaccountname", "") or ""
                sam = str(sam_value).strip().lower()

            if not sam or sam not in self.hv_users:
                continue

            # Add group membership to user data
            group_sid = target_group["objectid"]
            group_name = target_group["name"]

            if group_sid and group_sid not in self.hv_users[sam]["groups"]:
                self.hv_users[sam]["groups"].append(group_sid)
                self.hv_users[sam]["group_names"].append(group_name)

                # Also update the SID-based lookup
                user_sid = self.hv_users[sam]["sid"]
                if (
                    user_sid in self.hv_sids
                    and group_sid not in self.hv_sids[user_sid]["groups"]
                ):
                    self.hv_sids[user_sid]["groups"].append(group_sid)
                    self.hv_sids[user_sid]["group_names"].append(group_name)

    def _load_legacy_json(self, data: list[dict[str, Any]]) -> bool:
        # Load legacy BloodHound format
        for row in data:
            self._process_user_data(row)
        return True

    def _load_csv(self) -> bool:
        # csv.DictReader handles quoted fields; support UTF-8 BOM via utf-8-sig
        with open(self.path, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            if not self._has_fields(reader.fieldnames):
                self._schema_help()
                return False

            # Check if this is a lazy query format (all_props) and warn about CSV limitations
            if reader.fieldnames and "all_props" in [h.strip().lower() for h in reader.fieldnames]:
                warn("CSV format detected with 'all_props' field (lazy query)")
                warn("RECOMMENDATION: Use JSON format for lazy queries - CSV parsing may be inaccurate")

            for row in reader:
                self._process_user_data(row)
        return True

    def is_account_enabled(self, runas: str) -> bool | None:
        """
        Check if a user account is enabled in Active Directory.

        Args:
            runas: The account to check (SID, DOMAIN\\user, or plain username)

        Returns:
            True if enabled, False if disabled, None if unknown/not found
        """
        if not runas:
            return None

        val = runas.strip()
        user_data = None

        # Look up user data
        if val.upper().startswith("S-1-5-"):
            user_data = self.hv_sids.get(val.upper())
        else:
            sam = val.split("\\", 1)[1].lower() if "\\" in val else val.lower()
            user_data = self.hv_users.get(sam)

        if not user_data:
            return None

        enabled = user_data.get("enabled")
        if enabled is None:
            return None

        # Handle various formats (bool, string "true"/"false", etc.)
        if isinstance(enabled, bool):
            return enabled
        if isinstance(enabled, str):
            return enabled.lower() in ("true", "1", "yes")
        return bool(enabled)

    def check_highvalue(self, runas: str) -> bool:
        # Return True if the given RunAs value matches a known high-value account.
        #
        # Accepts SIDs (S-1-5-...) or NETBIOS\sam or plain sam.
        if not runas:
            return False
        val = runas.strip()
        # SID form
        if val.upper().startswith("S-1-5-"):
            return val.upper() in self.hv_sids  # Convert to uppercase for consistent lookup
        # Bare names (no domain prefix, no UPN @) resolve to LOCAL accounts first per
        # LookupAccountName() order: built-in/local → primary domain → trusted domains.
        # Never match a bare name against domain data — require an explicit qualifier.
        if "\\" not in val and "@" not in val:
            return False
        # NETBIOS\sam or UPN user@domain
        if "\\" in val:
            sam = val.split("\\", 1)[1].lower()
        else:
            sam = val.split("@", 1)[0].lower()
        return sam in self.hv_users

    def check_highvalue_bare(self, sam: str) -> bool:
        r"""Match a BARE sAMAccountName directly against high-value domain data.

        Bypasses check_highvalue()'s bare-name guard. The caller is responsible for
        ensuring the bare name is a domain account and not a local one (e.g. via
        resolver.is_probably_local_bare_name).
        """
        if not sam:
            return False
        return sam.strip().lower() in self.hv_users

    def check_tier0(self, runas: str) -> tuple[bool, list[str]]:
        # Return (True, reasons) if the given RunAs value belongs to Tier 0 groups.
        # Enhanced to include AdminSDHolder detection via admincount=1
        # Supports both Legacy and BHCE formats
        #
        # Uses SID-based detection instead of name matching for language independence.
        # Accepts SIDs (S-1-5-...) or NETBIOS\sam or plain sam.
        if not runas:
            return False, []

        val = runas.strip()
        user_data = None

        # Look up user data from BloodHound
        if val.upper().startswith("S-1-5-"):
            user_data = self.hv_sids.get(val.upper())  # Convert to uppercase for consistent lookup
        elif "\\" not in val and "@" not in val:
            # Bare names (no domain prefix, no UPN @) resolve to LOCAL accounts first per
            # LookupAccountName() order: built-in/local → primary domain → trusted domains.
            # Never match a bare name against domain data — require an explicit qualifier.
            pass
        elif "\\" in val:
            # NETBIOS\sam
            sam = val.split("\\", 1)[1].lower()
            user_data = self.hv_users.get(sam)
        else:
            # UPN format: user@domain
            sam = val.split("@", 1)[0].lower()
            user_data = self.hv_users.get(sam)

        return self._tier0_from_user_data(user_data)

    def check_tier0_bare(self, sam: str) -> tuple[bool, list[str]]:
        r"""Match a BARE sAMAccountName directly against Tier-0 domain data.

        Bypasses check_tier0()'s bare-name guard. The caller is responsible for
        ensuring the bare name is a domain account and not a local one (e.g. via
        resolver.is_probably_local_bare_name).
        """
        if not sam:
            return False, []
        return self._tier0_from_user_data(self.hv_users.get(sam.strip().lower()))

    def _tier0_from_user_data(self, user_data: dict | None) -> tuple[bool, list[str]]:
        """Compute (is_tier0, reasons) from a resolved BloodHound user record.

        Shared by check_tier0() (SID / qualified-name lookup) and check_tier0_bare()
        (bare sAMAccountName lookup).
        """
        if not user_data:
            return False, []

        tier0_reasons = []

        # Check 1: Group membership verification (PRIMARY - most accurate)
        # This works for both Legacy and BHCE and provides ground truth
        group_sids = user_data.get("groups", [])  # This contains the actual SIDs
        group_names = user_data.get("group_names", [])  # This contains display names

        # Create a mapping of SID to display name for output
        sid_to_name = {}
        if len(group_sids) == len(group_names):
            sid_to_name = dict(zip(group_sids, group_names, strict=False))

        matching_tier0_groups = []
        has_actual_tier0_groups = False

        for group_sid in group_sids:
            group_sid_upper = group_sid.upper()

            # Check against well-known Tier 0 SIDs
            for tier0_sid_pattern, default_name in TIER0_SIDS.items():
                if tier0_sid_pattern.startswith("S-1-5-21-{domain}"):
                    # Domain-relative SID - extract the pattern
                    # e.g., S-1-5-21-{domain}-512 matches S-1-5-21-1234567890-1234567890-1234567890-512
                    rid = tier0_sid_pattern.split("-")[-1]  # Get the RID (512, 519, etc.)
                    if group_sid_upper.startswith("S-1-5-21-") and group_sid_upper.endswith(f"-{rid}"):
                        # Use the display name from BloodHound if available, otherwise use default
                        display_name = sid_to_name.get(group_sid, default_name)
                        matching_tier0_groups.append(display_name)
                        has_actual_tier0_groups = True
                        break
                elif group_sid_upper == tier0_sid_pattern.upper():
                    # Exact SID match (builtin groups like Administrators)
                    display_name = sid_to_name.get(group_sid, default_name)
                    matching_tier0_groups.append(display_name)
                    has_actual_tier0_groups = True
                    break

        if has_actual_tier0_groups:
            tier0_reasons.append("TIER0 Group Membership")

        # Check 2: AdminSDHolder protection (admincount=1)
        # IMPORTANT: AdminSDHolder alone is NOT sufficient for TIER-0 classification!
        # Many service accounts have admincount=1 due to historical group membership
        # that was later removed (AdminSDHolder protection persists).
        # Only add AdminSDHolder as additional context when user has actual TIER-0 groups.
        admincount = user_data.get("admincount")
        has_adminsd_holder = admincount and str(admincount).lower() in ("1", "true")

        if has_adminsd_holder and has_actual_tier0_groups:
            # AdminSDHolder is additional evidence alongside actual group membership
            tier0_reasons.append("AdminSDHolder")

        # Note: A user with high-value=true but NO actual Tier-0 groups will be classified as PRIV
        # A user with admincount=1 but NO actual Tier-0 groups will be classified as PRIV
        # This fixes false positives from historical AdminSDHolder protection
        return len(tier0_reasons) > 0, tier0_reasons

    def analyze_password_age(self, runas: str, task_date: str) -> tuple[str, str]:
        # Simple boolean password analysis for DPAPI dump viability.
        # Returns (status, explanation) tuple.
        #
        # Args:
        #     runas: The user account running the task (DOMAIN\\user or SID)
        #     task_date: Task creation date (ISO format: 2025-09-18T23:04:37.3089851)
        #
        # Returns:
        #     Tuple of (status, explanation) where status is one of:
        #     - "GOOD": Stored password likely valid for DPAPI dump
        #     - "BAD": Stored password likely invalid, DPAPI dump unlikely to work
        #     - "UNKNOWN": Insufficient data for analysis
        if not runas or not task_date:
            return "UNKNOWN", "Insufficient data for password age analysis"

        val = runas.strip()
        user_data = None

        # Look up user data (same logic as check_tier0)
        if val.upper().startswith("S-1-5-"):
            user_data = self.hv_sids.get(val.upper())  # Convert to uppercase for consistent lookup
        else:
            sam = val.split("\\", 1)[1].lower() if "\\" in val else val.lower()
            user_data = self.hv_users.get(sam)

        if not user_data:
            return "UNKNOWN", "User not found in BloodHound data"

        pwd_change_date = user_data.get("pwdlastset")
        if not pwd_change_date:
            return "UNKNOWN", "Password change date not available in BloodHound data"

        return _analyze_password_freshness(task_date, pwd_change_date)
