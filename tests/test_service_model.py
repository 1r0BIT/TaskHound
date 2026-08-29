# Tests for the ServiceRow data model.

from taskhound.models.service import (
    START_TYPE_MAP,
    STATE_MAP,
    ServiceRow,
    ServiceType,
)


class TestServiceType:
    def test_enum_values(self):
        assert ServiceType.TIER0.value == "TIER-0"
        assert ServiceType.PRIV.value == "PRIV"
        assert ServiceType.SERVICE.value == "SERVICE"
        assert ServiceType.FAILURE.value == "FAILURE"
        assert ServiceType.SKIPPED.value == "SKIPPED"


class TestServiceRow:
    def test_basic_construction(self):
        row = ServiceRow(host="dc01.lab.local", service_name="MyService")
        assert row.host == "dc01.lab.local"
        assert row.service_name == "MyService"
        assert row.type == "SERVICE"
        assert row.is_gmsa is False
        assert row.decrypted_password is None

    def test_to_dict(self):
        row = ServiceRow(
            host="dc01.lab.local",
            service_name="SQLAgent",
            start_name="CORP\\sqladmin",
            binary_path="C:\\SQL\\sqlservr.exe",
        )
        d = row.to_dict()
        assert d["host"] == "dc01.lab.local"
        assert d["service_name"] == "SQLAgent"
        assert d["start_name"] == "CORP\\sqladmin"
        assert d["binary_path"] == "C:\\SQL\\sqlservr.exe"
        assert d["type"] == "SERVICE"

    def test_from_svcctl(self):
        svc = {
            "name": "MSSQLSERVER",
            "display_name": "SQL Server",
            "account": "CORP\\sqladmin",
            "binary_path": "C:\\SQL\\sqlservr.exe",
            "start_type": 0x02,  # Auto
            "service_type": 0x10,  # Win32OwnProcess
            "state": 0x04,  # Running
        }
        row = ServiceRow.from_svcctl(
            host="db01.corp.local",
            svc=svc,
            target_ip="10.0.0.5",
            computer_sid="S-1-5-21-1234",
        )
        assert row.host == "db01.corp.local"
        assert row.service_name == "MSSQLSERVER"
        assert row.display_name == "SQL Server"
        assert row.start_name == "CORP\\sqladmin"
        assert row.binary_path == "C:\\SQL\\sqlservr.exe"
        assert row.start_type == "Auto"
        assert row.service_type == "Win32OwnProcess"
        assert row.state == "Running"
        assert row.target_ip == "10.0.0.5"
        assert row.computer_sid == "S-1-5-21-1234"
        assert row.is_gmsa is False
        assert row.lsa_secret_name == "_SC_MSSQLSERVER"

    def test_from_svcctl_gmsa(self):
        svc = {
            "name": "AppPool",
            "display_name": "App Pool Service",
            "account": "CORP\\webapp$",
            "binary_path": "C:\\app\\svc.exe",
            "start_type": 0x02,
            "service_type": 0x10,
            "state": 0x04,
        }
        row = ServiceRow.from_svcctl(host="web01", svc=svc)
        assert row.is_gmsa is True
        assert row.start_name == "CORP\\webapp$"

    def test_from_svcctl_empty_account(self):
        svc = {
            "name": "SomeService",
            "display_name": "Some",
            "account": "",
            "binary_path": "svc.exe",
            "start_type": 0x02,
            "service_type": 0x10,
            "state": 0x01,
        }
        row = ServiceRow.from_svcctl(host="host", svc=svc)
        assert row.start_name is None

    def test_failure_factory(self):
        row = ServiceRow.failure("host1", "Access denied", target_ip="10.0.0.1")
        assert row.type == "FAILURE"
        assert row.reason == "Access denied"
        assert row.target_ip == "10.0.0.1"
        assert row.service_name == ""

    def test_skipped_factory(self):
        row = ServiceRow.skipped("host1", "duplicate", target_ip="10.0.0.1")
        assert row.type == "SKIPPED"
        assert row.reason == "duplicate"

    def test_start_type_map(self):
        assert START_TYPE_MAP[0x00] == "Boot"
        assert START_TYPE_MAP[0x02] == "Auto"
        assert START_TYPE_MAP[0x04] == "Disabled"

    def test_state_map(self):
        assert STATE_MAP[0x01] == "Stopped"
        assert STATE_MAP[0x04] == "Running"
