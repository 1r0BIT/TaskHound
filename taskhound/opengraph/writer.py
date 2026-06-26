"""
OpenGraph Writer Module

Contains logic for generating and writing OpenGraph files (nodes and edges).
"""

import json
from pathlib import Path
from typing import Any

from bhopengraph import Node, OpenGraph, Properties

from ..models.service import ServiceRow
from ..models.task import TaskRow
from ..utils.logging import debug, error, info, status, warn
from .builder import (
    _create_principal_id,
    _create_relationship_edges,
    _create_service_edges,
    _create_service_node,
    _create_task_node,
    extract_domain_from_fqdn,
    resolve_object_ids_chunked,
)
from .schema import EXTENSION_SCHEMA, SCHEMA_FILENAME

# BloodHound OpenGraph source_kind — namespaces all TaskHound-generated nodes/edges.
# Must be passed to OpenGraph(source_kind=...) at construction time: bhopengraph stamps
# this onto every node's `kinds` when the node is added, so assigning it after the
# add_node() calls would populate metadata only and miss the node kinds. Task and service
# graphs share this kind (they are already distinguished by node kind and by file).
SOURCE_KIND = "TaskHound"


def _write_extension_schema(output_path: Path) -> None:
    """Drop the v9 OpenGraph extension schema next to the graph data.

    Lets the schema be hand-installed via the BloodHound OpenGraph Management UI on
    instances where API install (``_install_schema`` during upload) is undesirable. Best
    effort — a failure here must not abort graph generation.
    """
    schema_path = output_path / SCHEMA_FILENAME
    try:
        with open(schema_path, "w", encoding="utf-8") as f:
            json.dump(EXTENSION_SCHEMA, f, indent=2)
        debug(f"Extension schema written: {schema_path}")
    except OSError as e:
        warn(f"Could not write extension schema to {schema_path}: {e}")


def generate_opengraph_files(
    output_dir: str,
    tasks: list[dict | TaskRow],
    bh_connector=None,
    ldap_config: dict | None = None,
    allow_orphans: bool = False,
    computer_sids: dict[str, str] | None = None,
    netbios_name: str | None = None,
) -> str | None:
    """
    Generates OpenGraph compatible JSON files for BloodHound.

    Process:
    1. Collect all unique computer and user names from tasks
    2. Resolve them to BloodHound node IDs (graph IDs) and objectIds (SIDs) in bulk
    3. Create TH_ScheduledTask nodes
    4. Create edges using resolved IDs (reliable) or names (fallback)
    5. Write to JSON file

    :param tasks: List of task dictionaries
    :param output_dir: Directory to write output files
    :param bh_connector: Optional BloodHoundConnector for API lookups
    :param ldap_config: Optional LDAP config for fallback resolution
    :param allow_orphans: If True, create edges even when nodes are missing from BloodHound
    :param computer_sids: Optional mapping of FQDN→SID from SMB connections (preferred!)
    :param netbios_name: NetBIOS domain name (e.g., "CONTOSO") - used for accurate domain comparison
    """
    # Convert TaskRow objects to dicts if needed
    task_dicts: list[dict[str, Any]] = []
    for t in tasks:
        if isinstance(t, TaskRow):
            task_dicts.append(t.to_dict())
        else:
            task_dicts.append(t)

    # Filter out failure rows (e.g. failed SMB connections)
    valid_tasks = [t for t in task_dicts if t.get("type") != "FAILURE"]

    info(f"Generating OpenGraph data for {len(valid_tasks)} tasks...")

    if not valid_tasks:
        warn("No valid tasks provided for OpenGraph generation - creating empty graph")

    # Initialize OpenGraph container
    graph = OpenGraph(source_kind=SOURCE_KIND)

    # 1. Collect unique names for resolution
    computer_names: set[str] = set()
    user_names: set[str] = set()

    _extract_domain = extract_domain_from_fqdn

    info("Collecting unique principals for resolution...")
    for task in valid_tasks:
        # Add computer hostname (FQDN)
        hostname = (task.get("host") or "").strip().upper()
        if hostname and hostname != "UNKNOWN_HOST":
            computer_names.add(hostname)

        # Add RunAs user
        runas = (task.get("runas") or "").strip()
        if runas and runas != "N/A":
            # Use helper to normalize principal ID
            fqdn_domain = _extract_domain(hostname)
            principal_id = _create_principal_id(runas, fqdn_domain, task, bh_connector, local_netbios=netbios_name)
            if principal_id:
                user_names.add(principal_id)

    info(f"Found {len(computer_names)} unique computers and {len(user_names)} unique users")

    # 2. Resolve names to IDs if connector is available
    computer_map: dict[str, tuple | None] = {}
    user_map: dict[str, tuple | None] = {}

    if bh_connector:
        info("Resolving Principals...")
        computer_map, user_map = resolve_object_ids_chunked(
            computer_names,
            user_names,
            bh_connector,
            ldap_config,
            computer_sids=computer_sids
        )
    else:
        warn("No BloodHound connector available - skipping ID resolution (using name matching only)")
        warn("Note: Name matching is less reliable and may create duplicate nodes")

    # 2.5 Add Placeholder Nodes for Principals
    # bhopengraph requires that start/end nodes of an edge exist in the graph object.
    # We must add placeholder nodes for all Computers and Users referenced in the edges.
    info("Adding placeholder nodes for principals...")

    # Add Computer Nodes
    for name in computer_names:
        sid = None
        resolved_name = None
        node_info = computer_map.get(name)
        if node_info:
             _, sid, *rest = node_info
             if rest:
                 resolved_name = rest[0]

        if sid:
            # We have a SID - use it as ID (matches builder.py logic)
            # Note: 'objectid' is reserved in BH v8.9.0+; identity is carried by id=.
            node = Node(
                id=sid,
                kinds=["Computer", "Base"],
                properties=Properties(name=resolved_name or name)
            )
            graph.add_node(node)
            debug(f"Added placeholder node for Computer: {resolved_name or name} ({sid})")
        elif allow_orphans:
            # No SID, but orphans allowed - use Name as ID
            node = Node(
                id=name,
                kinds=["Computer", "Base"],
                properties=Properties(name=name)
            )
            graph.add_node(node)
            debug(f"Added orphaned placeholder node for Computer: {name}")

    # Add User Nodes
    for name in user_names:
        sid = None
        resolved_name = None
        node_info = user_map.get(name)
        if node_info:
             _, sid, *rest = node_info
             if rest:
                 resolved_name = rest[0]

        if sid:
            node = Node(
                id=sid,
                kinds=["User", "Base"],
                properties=Properties(name=resolved_name or name)
            )
            graph.add_node(node)
            debug(f"Added placeholder node for User: {resolved_name or name} ({sid})")
        elif allow_orphans:
            node = Node(
                id=name,
                kinds=["User", "Base"],
                properties=Properties(name=name)
            )
            graph.add_node(node)
            debug(f"Added orphaned placeholder node for User: {name}")

    # 3. Build Graph
    info("Building graph nodes and edges...")
    skipped_counts = {"computers": 0, "users": 0}

    for task in valid_tasks:
        try:
            # Create Task Node
            task_node = _create_task_node(task)
            graph.add_node(task_node)

            # Create Edges
            edges, skipped = _create_relationship_edges(
                task,
                computer_map,
                user_map,
                bh_connector,
                allow_orphans,
                netbios_name=netbios_name,
            )

            for edge in edges:
                graph.add_edge(edge)

            skipped_counts["computers"] += skipped["computers"]
            skipped_counts["users"] += skipped["users"]

        except ValueError as e:
            debug(f"Skipping invalid task: {e}")
            continue
        except Exception as e:
            warn(f"Error processing task {task.get('path', 'unknown')}: {e}")
            import traceback
            debug(traceback.format_exc())
            continue

    # Report skipped edges
    if skipped_counts["computers"] > 0 or skipped_counts["users"] > 0:
        warn("Skipped edges due to missing BloodHound nodes:")
        if skipped_counts["computers"] > 0:
            warn(f"  - {skipped_counts['computers']} tasks skipped because Computer node was missing")
        if skipped_counts["users"] > 0:
            warn(f"  - {skipped_counts['users']} RunsAs edges skipped because User node was missing")
        warn("  (Use --allow-orphans to create these edges anyway)")

    # 4. Write Output
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Write standard OpenGraph JSON
    json_path = output_path / "taskhound_opengraph.json"
    info(f"Writing OpenGraph data to {json_path}...")

    try:
        # bhopengraph handles the JSON serialization structure
        with open(json_path, 'w', encoding='utf-8') as f:
            # Get the dictionary representation
            graph_dict = graph.export_to_dict()
            # Write with indentation for readability
            json.dump(graph_dict, f, indent=2)

        status(f"[+] OpenGraph json generated. {len(graph.nodes)} nodes and {len(graph.edges)} edges")

        # Drop the extension schema alongside the data for manual UI install
        _write_extension_schema(output_path)

        # Also write raw data for debugging/manual import
        data_path = output_path / "taskhound_data.json"
        with open(data_path, 'w', encoding='utf-8') as f:
            json.dump(tasks, f, indent=2, default=str)
        debug(f"Wrote raw task data to {data_path}")

        return str(json_path)

    except Exception as e:
        error(f"Failed to write OpenGraph files: {e}")
        import traceback
        debug(traceback.format_exc())
        return None


def generate_service_opengraph_files(
    output_dir: str,
    services: list[dict | ServiceRow],
    bh_connector=None,
    ldap_config: dict | None = None,
    allow_orphans: bool = False,
    computer_sids: dict[str, str] | None = None,
    netbios_name: str | None = None,
) -> str | None:
    """
    Generate OpenGraph JSON for Windows service findings.

    Writes to a separate file (taskhound_services_opengraph.json) with
    TH_WindowsService nodes (distinct from the task graph's TH_ScheduledTask nodes)
    to avoid contaminating the task OpenGraph data when re-uploading. Both
    graphs share the "TaskHound" source_kind.

    :param services: List of ServiceRow objects or dicts
    :param output_dir: Directory to write output files
    :param bh_connector: Optional BloodHoundConnector
    :param ldap_config: Optional LDAP config for fallback resolution
    :param allow_orphans: Create edges even when target nodes are missing
    :param computer_sids: FQDN→SID mapping from SMB connections
    :param netbios_name: NetBIOS domain name
    """
    svc_dicts: list[dict[str, Any]] = []
    for s in services:
        if isinstance(s, ServiceRow):
            svc_dicts.append(s.to_dict())
        else:
            svc_dicts.append(s)

    valid_services = [s for s in svc_dicts if s.get("type") not in ("FAILURE", "SKIPPED")]

    info(f"Generating service OpenGraph data for {len(valid_services)} services...")

    if not valid_services:
        warn("No valid services for OpenGraph generation")
        return None

    graph = OpenGraph(source_kind=SOURCE_KIND)

    # Collect unique names for resolution
    computer_names: set[str] = set()
    user_names: set[str] = set()

    _extract_domain = extract_domain_from_fqdn

    for svc in valid_services:
        hostname = (svc.get("host") or "").strip().upper()
        if hostname:
            computer_names.add(hostname)

        start_name = (svc.get("start_name") or "").strip()
        if start_name:
            fqdn_domain = _extract_domain(hostname)
            principal_id = _create_principal_id(start_name, fqdn_domain, svc, bh_connector, local_netbios=netbios_name)
            if principal_id:
                user_names.add(principal_id)

    # Resolve names to IDs
    computer_map: dict[str, tuple | None] = {}
    user_map: dict[str, tuple | None] = {}

    if bh_connector:
        info("Resolving service principals...")
        computer_map, user_map = resolve_object_ids_chunked(
            computer_names, user_names, bh_connector, ldap_config,
            computer_sids=computer_sids,
        )

    # Add placeholder nodes for principals
    for name in computer_names:
        node_info = computer_map.get(name)
        sid = node_info[1] if node_info and len(node_info) > 1 else None
        resolved_name = node_info[2] if node_info and len(node_info) > 2 else None
        if sid:
            graph.add_node(Node(id=sid, kinds=["Computer", "Base"], properties=Properties(name=resolved_name or name)))
        elif allow_orphans:
            graph.add_node(Node(id=name, kinds=["Computer", "Base"], properties=Properties(name=name)))

    for name in user_names:
        node_info = user_map.get(name)
        sid = node_info[1] if node_info and len(node_info) > 1 else None
        resolved_name = node_info[2] if node_info and len(node_info) > 2 else None
        if sid:
            graph.add_node(Node(id=sid, kinds=["User", "Base"], properties=Properties(name=resolved_name or name)))
        elif allow_orphans:
            graph.add_node(Node(id=name, kinds=["User", "Base"], properties=Properties(name=name)))

    # Build service nodes and edges
    skipped_counts = {"computers": 0, "users": 0}

    for svc in valid_services:
        try:
            svc_node = _create_service_node(svc)
            graph.add_node(svc_node)

            edges, skipped = _create_service_edges(
                svc, computer_map, user_map, bh_connector, allow_orphans,
                netbios_name=netbios_name,
            )
            for edge in edges:
                graph.add_edge(edge)

            skipped_counts["computers"] += skipped["computers"]
            skipped_counts["users"] += skipped["users"]

        except ValueError as e:
            debug(f"Skipping invalid service: {e}")
        except Exception as e:
            warn(f"Error processing service {svc.get('service_name', 'unknown')}: {e}")

    if skipped_counts["computers"] > 0 or skipped_counts["users"] > 0:
        warn(f"Skipped service edges: {skipped_counts['computers']} computer, {skipped_counts['users']} user (use --bh-allow-orphans)")

    # Write output
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    json_path = output_path / "taskhound_services_opengraph.json"
    info(f"Writing service OpenGraph data to {json_path}...")

    try:
        with open(json_path, "w", encoding="utf-8") as f:
            graph_dict = graph.export_to_dict()
            json.dump(graph_dict, f, indent=2)

        status(f"[+] Service OpenGraph generated. {len(graph.nodes)} nodes and {len(graph.edges)} edges")

        # Drop the extension schema alongside the data for manual UI install
        _write_extension_schema(output_path)

        return str(json_path)

    except Exception as e:
        error(f"Failed to write service OpenGraph files: {e}")
        return None
