"""BloodHound v9 OpenGraph extension schema — single source of truth for TaskHound's
custom node/edge kinds and their pathfinding traversability.

BloodHound CE v9 requires every custom node AND edge kind to carry the extension
namespace prefix ("TH_"); unprefixed kinds are rejected by the ``PUT /api/v2/extensions``
validator. The kind strings declared here MUST match the kinds emitted by ``builder.py``
(enforced by ``tests/test_opengraph_schema_consistency.py``) — a mismatch silently makes
the edge non-traversable in pathfinding rather than erroring.

``source_kind`` ("TaskHound", see ``writer.SOURCE_KIND``) is upload-grouping metadata and
is *separate* from the namespace — it is intentionally NOT prefixed.

Traversability (see the handoff §5 decisions):
- creds-bearing edges (HasTaskWithStoredCreds, HasServiceWithStoredCreds) and RunsAs are
  traversable — they form the real Computer → ScheduledTask/Service → RunAs-principal path.
- HasTask (no stored creds) is non-traversable: a bare task definition carries no credential
  material, so making it traversable would inflate pathfinding with false attack paths.
"""

NAMESPACE = "TH"

# Node kinds (custom — prefixed). Native Computer/User/Base kinds are NOT declared here.
NODE_SCHEDULED_TASK = f"{NAMESPACE}_ScheduledTask"
NODE_WINDOWS_SERVICE = f"{NAMESPACE}_WindowsService"

# Edge kinds (custom — prefixed).
EDGE_HAS_TASK = f"{NAMESPACE}_HasTask"
EDGE_HAS_TASK_WITH_CREDS = f"{NAMESPACE}_HasTaskWithStoredCreds"
EDGE_RUNS_AS = f"{NAMESPACE}_RunsAs"
EDGE_HAS_SERVICE_WITH_CREDS = f"{NAMESPACE}_HasServiceWithStoredCreds"

# Filename the schema is also written to (next to the graph JSON) for manual install
# via the BloodHound OpenGraph Management UI on instances where API install is undesirable.
SCHEMA_FILENAME = "taskhound_extension_schema.json"

EXTENSION_SCHEMA = {
    "schema": {
        "name": "TaskHound",
        "display_name": "TaskHound (by 0xr0BIT)",
        "version": "v1.0.0",
        "namespace": NAMESPACE,
    },
    "node_kinds": [
        {
            "name": NODE_SCHEDULED_TASK,
            "display_name": "Scheduled Task",
            "description": "A Windows scheduled task discovered by TaskHound.",
            "is_display_kind": True,
            "icon": "clock",
            "color": "#8B5CF6",
        },
        {
            "name": NODE_WINDOWS_SERVICE,
            "display_name": "Windows Service",
            "description": "A Windows service running as a domain account.",
            "is_display_kind": True,
            "icon": "gears",
            "color": "#06B6D4",
        },
    ],
    "relationship_kinds": [
        {
            "name": EDGE_HAS_TASK_WITH_CREDS,
            "description": "Computer stores credentials for this task's RunAs principal.",
            "is_traversable": True,
        },
        {
            "name": EDGE_HAS_SERVICE_WITH_CREDS,
            "description": "Computer stores credentials for this service's account.",
            "is_traversable": True,
        },
        {
            "name": EDGE_RUNS_AS,
            "description": "Task/Service executes as this principal.",
            "is_traversable": True,
        },
        {
            "name": EDGE_HAS_TASK,
            "description": "Computer hosts this task (no stored creds).",
            "is_traversable": False,
        },
    ],
    "environments": [],
    "relationship_findings": [],
}
