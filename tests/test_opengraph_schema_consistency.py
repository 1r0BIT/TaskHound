"""Schema <-> emitted-kind consistency for the v9 OpenGraph extension.

Traversability lives in the extension schema, and BloodHound only treats an edge as
traversable when the kind in the *uploaded data* exactly matches a declared
``relationship_kind``. A drift between what ``builder.py`` emits and what
``schema.EXTENSION_SCHEMA`` declares does NOT raise — it silently degrades the edge to
non-traversable. These tests are the guard against that (mirrors RoastGraph's test_match.py).
"""

from unittest.mock import Mock

import pytest

from taskhound.opengraph.builder import (
    _create_relationship_edges,
    _create_service_edges,
    _create_service_node,
    _create_task_node,
)
from taskhound.opengraph.schema import (
    EDGE_HAS_SERVICE_WITH_CREDS,
    EDGE_HAS_TASK,
    EDGE_HAS_TASK_WITH_CREDS,
    EDGE_RUNS_AS,
    EXTENSION_SCHEMA,
    NAMESPACE,
    NODE_SCHEDULED_TASK,
    NODE_WINDOWS_SERVICE,
)

PREFIX = f"{NAMESPACE}_"
SCHEMA_NODE_KINDS = {n["name"] for n in EXTENSION_SCHEMA["node_kinds"]}
SCHEMA_EDGE_KINDS = {r["name"] for r in EXTENSION_SCHEMA["relationship_kinds"]}


def _emit_kinds():
    """Build representative task/service nodes+edges and collect every kind they emit.

    Exercises every edge branch so an unconverted literal anywhere surfaces here:
      - resolved   (key -> (gid, sid)):  id-matched normal branch
      - orphan-miss (key -> None):       queried-but-not-found + --allow-orphans branch
      - not-in-map  ({}):                key-absent + --allow-orphans branch
    ...across both the stored-creds and no-creds task paths and the service path.
    """
    node_kinds: set[str] = set()
    edge_kinds: set[str] = set()

    task_creds = {"host": "DC01.CORP.LOCAL", "path": "\\A", "runas": "svc@CORP.LOCAL",
                  "credentials_hint": "stored_credentials"}
    task_nocreds = {"host": "DC01.CORP.LOCAL", "path": "\\B", "runas": "svc@CORP.LOCAL"}
    svc = {"host": "DC01.CORP.LOCAL", "service_name": "MSSQLSERVER", "start_name": "sqladmin@CORP.LOCAL"}

    cmap = {"DC01.CORP.LOCAL": ("gid", "S-1-5-21-COMP")}
    cmiss = {"DC01.CORP.LOCAL": None}  # queried but not found in BloodHound
    umap_task = {"SVC@CORP.LOCAL": ("gid", "S-1-5-21-USER")}
    umiss_task = {"SVC@CORP.LOCAL": None}
    umap_svc = {"SQLADMIN@CORP.LOCAL": ("gid", "S-1-5-21-SQL")}
    umiss_svc = {"SQLADMIN@CORP.LOCAL": None}

    task_combos = (({}, {}), (cmap, umap_task), (cmiss, umiss_task))
    svc_combos = (({}, {}), (cmap, umap_svc), (cmiss, umiss_svc))

    for t in (task_creds, task_nocreds):
        node_kinds.update(_create_task_node(t).kinds)
        for cm, um in task_combos:
            edges, _ = _create_relationship_edges(t, cm, um, allow_orphans=True)
            edge_kinds.update(e.kind for e in edges)

    node_kinds.update(_create_service_node(svc).kinds)
    for cm, um in svc_combos:
        edges, _ = _create_service_edges(svc, cm, um, allow_orphans=True)
        edge_kinds.update(e.kind for e in edges)

    return node_kinds, edge_kinds


class TestSchemaShape:
    def test_all_declared_kinds_are_namespace_prefixed(self):
        for name in SCHEMA_NODE_KINDS | SCHEMA_EDGE_KINDS:
            assert name.startswith(PREFIX), f"{name} missing the {PREFIX} namespace prefix (v9 rejects it)"

    def test_node_kinds_non_empty(self):
        # The v9 PUT /api/v2/extensions validator rejects an empty node_kinds list.
        assert EXTENSION_SCHEMA["node_kinds"]

    def test_required_top_level_keys_present(self):
        assert set(EXTENSION_SCHEMA) == {
            "schema", "node_kinds", "relationship_kinds", "environments", "relationship_findings"
        }
        assert EXTENSION_SCHEMA["schema"]["namespace"] == NAMESPACE

    def test_declared_kinds_match_constants(self):
        assert {NODE_SCHEDULED_TASK, NODE_WINDOWS_SERVICE} == SCHEMA_NODE_KINDS
        assert {
            EDGE_HAS_TASK, EDGE_HAS_TASK_WITH_CREDS, EDGE_RUNS_AS, EDGE_HAS_SERVICE_WITH_CREDS
        } == SCHEMA_EDGE_KINDS


class TestTraversability:
    def test_traversability_decisions(self):
        flags = {r["name"]: r["is_traversable"] for r in EXTENSION_SCHEMA["relationship_kinds"]}
        # Creds-bearing edges + RunsAs form the real attack path → traversable.
        assert flags[EDGE_HAS_TASK_WITH_CREDS] is True
        assert flags[EDGE_HAS_SERVICE_WITH_CREDS] is True
        assert flags[EDGE_RUNS_AS] is True
        # A bare task definition carries no creds → non-traversable (avoids false paths).
        assert flags[EDGE_HAS_TASK] is False


class TestEmittedKindsMatchSchema:
    """The core guard: kinds the builder actually emits must be declared in the schema."""

    def test_emitted_custom_node_kinds_are_declared(self):
        node_kinds, _ = _emit_kinds()
        custom = {k for k in node_kinds if k.startswith(PREFIX)}
        assert custom == SCHEMA_NODE_KINDS
        # Native kinds stay unprefixed and must NOT leak into the schema.
        assert {"Base", "Computer", "User"} & SCHEMA_NODE_KINDS == set()

    def test_every_emitted_edge_kind_is_declared(self):
        _, edge_kinds = _emit_kinds()
        # The builder emits only custom edges; every one must be a declared traversal kind.
        assert edge_kinds, "no edges emitted — fixture broke"
        assert edge_kinds <= SCHEMA_EDGE_KINDS, f"undeclared edge kinds: {edge_kinds - SCHEMA_EDGE_KINDS}"
        # And all four declared edges are reachable from the builder (no dead declarations).
        assert edge_kinds == SCHEMA_EDGE_KINDS

    def test_no_legacy_unprefixed_kinds_emitted(self):
        node_kinds, edge_kinds = _emit_kinds()
        legacy = {"ScheduledTask", "WindowsService", "HasTask", "HasTaskWithStoredCreds",
                  "RunsAs", "HasServiceWithStoredCreds"}
        assert legacy & (node_kinds | edge_kinds) == set()


class TestBuilderEmissionDetails:
    def test_task_without_creds_emits_bare_has_task(self):
        # Previously untested: a task with no stored creds gets TH_HasTask, not TH_HasTaskWithStoredCreds.
        task = {"host": "DC01.CORP.LOCAL", "path": "\\B", "runas": "svc@CORP.LOCAL"}
        edges, _ = _create_relationship_edges(task, {}, {}, allow_orphans=True)
        kinds = {e.kind for e in edges}
        assert EDGE_HAS_TASK in kinds
        assert EDGE_HAS_TASK_WITH_CREDS not in kinds

    def test_three_kind_cap_respected(self):
        # bhopengraph hard-caps a node at 3 kinds: OpenGraph.add_node auto-appends source_kind
        # and Node.add_kind RAISES ValueError beyond 3. The builder must stay within budget
        # ([TH_<kind>, "Base", "TaskHound"]) so add_node's source_kind stamp is a no-op. Exercise
        # the REAL add_node path (a bare Node ctor does not enforce the cap), so a regression that
        # drops "TaskHound" from the literal and adds a different 3rd kind would raise here.
        from bhopengraph import OpenGraph

        graph = OpenGraph(source_kind="TaskHound")
        task_node = _create_task_node({"host": "DC.LAB", "path": "\\T"})
        svc_node = _create_service_node({"host": "DC.LAB", "service_name": "S"})
        for node, kind in ((task_node, NODE_SCHEDULED_TASK), (svc_node, NODE_WINDOWS_SERVICE)):
            assert kind in node.kinds
            assert "TaskHound" in node.kinds
            graph.add_node(node)  # raises ValueError if source_kind stamping overflows the cap
            assert len(node.kinds) == 3


class TestInstallSchema:
    """_install_schema PUTs the schema and maps the response to a bool (handoff §7 fallback)."""

    @pytest.mark.parametrize("status", [200, 201])
    def test_returns_true_on_success_and_puts_schema(self, status):
        from taskhound.output.bloodhound import _install_schema

        auth = Mock()
        resp = Mock()
        resp.status_code = status
        auth.request.return_value = resp
        assert _install_schema(auth) is True
        auth.request.assert_called_once_with("PUT", "/api/v2/extensions", EXTENSION_SCHEMA)

    def test_returns_false_on_pre_v9_404(self):
        from taskhound.output.bloodhound import _install_schema

        auth = Mock()
        resp = Mock()
        resp.status_code = 404
        resp.text = "not found"
        auth.request.return_value = resp
        assert _install_schema(auth) is False

    def test_returns_false_on_transport_failure(self):
        from taskhound.output.bloodhound import _install_schema

        auth = Mock()
        auth.request.return_value = None  # request() returns None on transport/auth failure
        assert _install_schema(auth) is False
