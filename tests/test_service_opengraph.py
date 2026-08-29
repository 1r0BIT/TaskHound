# Tests for service OpenGraph node/edge builders and file generation.

import json
import os
import tempfile

from taskhound.models.service import ServiceRow
from taskhound.opengraph.builder import (
    _create_service_edges,
    _create_service_node,
    _create_service_object_id,
)


class TestCreateServiceObjectId:
    def test_deterministic(self):
        id1 = _create_service_object_id("DC01.CORP.LOCAL", "MSSQLSERVER")
        id2 = _create_service_object_id("DC01.CORP.LOCAL", "MSSQLSERVER")
        assert id1 == id2

    def test_different_services(self):
        id1 = _create_service_object_id("DC01.CORP.LOCAL", "MSSQLSERVER")
        id2 = _create_service_object_id("DC01.CORP.LOCAL", "AppPool")
        assert id1 != id2

    def test_different_hosts(self):
        id1 = _create_service_object_id("DC01.CORP.LOCAL", "MSSQLSERVER")
        id2 = _create_service_object_id("DC02.CORP.LOCAL", "MSSQLSERVER")
        assert id1 != id2

    def test_format(self):
        oid = _create_service_object_id("dc01.corp.local", "MyService")
        assert "dc01.corp.local" in oid
        assert "MYSERVICE" in oid
        # Should have hash component (hostname_hash_servicename)
        parts = oid.split("_")
        assert len(parts) >= 3


class TestCreateServiceNode:
    def test_basic_node(self):
        svc = {
            "host": "dc01.corp.local",
            "service_name": "MSSQLSERVER",
            "display_name": "SQL Server",
            "start_name": "CORP\\sqladmin",
            "binary_path": "C:\\SQL\\sqlservr.exe",
            "start_type": "Auto",
            "state": "Running",
            "type": "TIER-0",
            "reason": "Domain Admins",
            "is_gmsa": False,
        }
        node = _create_service_node(svc)

        assert "TH_WindowsService" in node.kinds
        assert "Base" in node.kinds
        assert "TaskHound" in node.kinds
        assert node.properties.to_dict()["name"] == "MSSQLSERVER"

    def test_missing_host_raises(self):
        import pytest
        with pytest.raises(ValueError, match="host"):
            _create_service_node({"service_name": "svc"})

    def test_missing_service_name_raises(self):
        import pytest
        with pytest.raises(ValueError, match="service_name"):
            _create_service_node({"host": "dc01"})

    def test_credentials_stored_always_true(self):
        svc = {
            "host": "dc01.corp.local",
            "service_name": "Svc1",
            "start_name": "CORP\\user",
        }
        node = _create_service_node(svc)
        # Access properties dict
        props = node.properties.to_dict()
        assert props["credentialsstored"] is True

    def test_gmsa_property(self):
        svc = {
            "host": "dc01.corp.local",
            "service_name": "Svc1",
            "is_gmsa": True,
        }
        node = _create_service_node(svc)
        props = node.properties.to_dict()
        assert props["isgmsa"] is True


class TestCreateServiceEdges:
    def test_creates_has_service_edge(self):
        svc = {
            "host": "DC01.CORP.LOCAL",
            "service_name": "MSSQLSERVER",
            "start_name": "CORP\\sqladmin",
        }
        computer_map = {"DC01.CORP.LOCAL": ("graph_id", "S-1-5-21-COMP-SID")}
        user_map = {}

        edges, skipped = _create_service_edges(svc, computer_map, user_map)

        has_svc_edges = [e for e in edges if e.kind == "TH_HasServiceWithStoredCreds"]
        assert len(has_svc_edges) == 1
        assert has_svc_edges[0].start_node == "S-1-5-21-COMP-SID"

    def test_creates_runs_as_edge(self):
        svc = {
            "host": "DC01.CORP.LOCAL",
            "service_name": "MSSQLSERVER",
            "start_name": "sqladmin@CORP.LOCAL",
        }
        computer_map = {"DC01.CORP.LOCAL": ("gid", "S-1-5-21-COMP")}
        user_map = {"SQLADMIN@CORP.LOCAL": ("gid", "S-1-5-21-USER")}

        edges, skipped = _create_service_edges(svc, computer_map, user_map)

        runs_as_edges = [e for e in edges if e.kind == "TH_RunsAs"]
        assert len(runs_as_edges) == 1
        assert runs_as_edges[0].end_node == "S-1-5-21-USER"

    def test_skips_when_no_computer(self):
        svc = {
            "host": "DC01.CORP.LOCAL",
            "service_name": "Svc1",
            "start_name": "CORP\\user",
        }
        edges, skipped = _create_service_edges(svc, {}, {})
        assert skipped["computers"] == 1

    def test_orphan_mode(self):
        svc = {
            "host": "DC01.CORP.LOCAL",
            "service_name": "Svc1",
            "start_name": "user@CORP.LOCAL",
        }
        edges, skipped = _create_service_edges(svc, {}, {}, allow_orphans=True)

        # Should create edges even without resolved IDs
        assert len(edges) >= 1
        assert skipped["computers"] == 0


class TestGenerateServiceOpengraphFiles:
    def test_generates_file(self):
        from taskhound.opengraph.writer import generate_service_opengraph_files

        with tempfile.TemporaryDirectory() as tmpdir:
            services = [
                ServiceRow(
                    host="dc01.corp.local",
                    service_name="MSSQLSERVER",
                    start_name="CORP\\sqladmin",
                    type="TIER-0",
                ),
            ]

            result = generate_service_opengraph_files(
                output_dir=tmpdir,
                services=services,
                allow_orphans=True,
            )

            assert result is not None
            assert os.path.exists(result)
            assert "taskhound_services_opengraph.json" in result

            with open(result) as f:
                data = json.load(f)

            # BHCE namespaces custom OpenGraph data by source_kind; it must be set (not null).
            # Task and service graphs share the "TaskHound" source_kind.
            assert data["metadata"]["source_kind"] == "TaskHound"

            # Should have nodes (at least the service node)
            graph = data.get("graph", data)
            nodes = graph.get("nodes", [])
            assert len(nodes) >= 1

            # Find the TH_WindowsService node
            svc_nodes = [n for n in nodes if "TH_WindowsService" in n.get("kinds", [])]
            assert len(svc_nodes) == 1

            # The v9 extension schema is dropped next to the data for manual UI install.
            from taskhound.opengraph.schema import EXTENSION_SCHEMA, SCHEMA_FILENAME

            schema_path = os.path.join(tmpdir, SCHEMA_FILENAME)
            assert os.path.exists(schema_path)
            with open(schema_path) as sf:
                assert json.load(sf) == EXTENSION_SCHEMA

    def test_returns_none_for_empty(self):
        from taskhound.opengraph.writer import generate_service_opengraph_files

        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate_service_opengraph_files(tmpdir, [])
            assert result is None
