# Tests for service output: JSON, CSV, summary, HTML.

import csv
import json
import os
import tempfile

from taskhound.models.service import ServiceRow
from taskhound.output.writer import (
    write_combined_json,
    write_service_csv,
)


def _sample_service_rows():
    return [
        ServiceRow(
            host="dc01.corp.local",
            service_name="MSSQLSERVER",
            display_name="SQL Server",
            start_name="CORP\\sqladmin",
            binary_path="C:\\SQL\\sqlservr.exe",
            start_type="Auto",
            service_type="Win32OwnProcess",
            state="Running",
            type="TIER-0",
            reason="Domain Admins",
            is_gmsa=False,
        ),
        ServiceRow(
            host="dc01.corp.local",
            service_name="AppPool",
            display_name="App Pool",
            start_name="CORP\\webapp$",
            binary_path="C:\\app\\svc.exe",
            start_type="Auto",
            service_type="Win32OwnProcess",
            state="Running",
            type="SERVICE",
            is_gmsa=True,
        ),
    ]


class TestWriteCombinedJson:
    def test_writes_tasks_and_services(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "combined.json")
            task_rows = [{"host": "dc01", "path": "Task1", "type": "TASK"}]
            svc_rows = _sample_service_rows()

            write_combined_json(path, task_rows, svc_rows, silent=True)

            with open(path) as f:
                data = json.load(f)

            assert "tasks" in data
            assert "services" in data
            assert len(data["tasks"]) == 1
            assert len(data["services"]) == 2
            assert data["services"][0]["service_name"] == "MSSQLSERVER"
            assert data["services"][1]["is_gmsa"] is True

    def test_empty_service_rows(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "combined.json")
            write_combined_json(path, [{"host": "h1"}], [], silent=True)

            with open(path) as f:
                data = json.load(f)

            assert data["tasks"] == [{"host": "h1"}]
            assert data["services"] == []


class TestWriteServiceCsv:
    def test_writes_service_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "services.csv")
            svc_rows = _sample_service_rows()

            write_service_csv(path, svc_rows)

            with open(path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 2
            assert rows[0]["service_name"] == "MSSQLSERVER"
            assert rows[0]["start_name"] == "CORP\\sqladmin"
            assert rows[0]["type"] == "TIER-0"
            assert rows[1]["is_gmsa"] == "True"

    def test_empty_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "services.csv")
            write_service_csv(path, [])

            with open(path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 0


class TestSummaryWithServices:
    def test_summary_includes_service_counts(self):
        """Verify summary table function accepts service_rows parameter."""
        from taskhound.output.summary import print_summary_table

        task_rows = [{"host": "dc01", "type": "TASK"}]
        svc_rows = _sample_service_rows()

        # Should not raise
        print_summary_table(
            task_rows,
            has_hv_data=True,
            service_rows=svc_rows,
        )


class TestHtmlReportWithServices:
    def test_html_report_includes_services(self):
        from taskhound.output.html_report import generate_html_report

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.html")
            task_rows = [{"host": "dc01", "type": "TASK", "path": "MyTask",
                          "runas": "CORP\\user", "command": "cmd.exe"}]
            svc_rows = _sample_service_rows()

            generate_html_report(task_rows, path, service_rows=svc_rows)

            with open(path) as f:
                html = f.read()

            # Services appear in unified findings (not a separate section)
            assert "MSSQLSERVER" in html
            assert "CORP\\sqladmin" in html or "CORP&#x5C;sqladmin" in html
            assert "gMSA" in html

    def test_html_report_no_services(self):
        from taskhound.output.html_report import generate_html_report

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.html")
            task_rows = [{"host": "dc01", "type": "TASK", "path": "MyTask",
                          "runas": "CORP\\user", "command": "cmd.exe"}]

            generate_html_report(task_rows, path)

            with open(path) as f:
                html = f.read()

            # With no services, service count shouldn't appear in header
            assert "Services Found" not in html
