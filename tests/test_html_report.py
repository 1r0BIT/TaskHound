"""
Tests for taskhound/output/html_report.py

Tests the HTML audit report generation including:
- Severity calculation for various task configurations
- Statistics aggregation
- HTML generation
- Report file writing
"""

import os
import tempfile

import pytest

from taskhound.output.html_report import (
    AuditStatistics,
    SeverityScore,
    calculate_severity,
    calculate_statistics,
    generate_audit_summary,
    generate_html_report,
)

# ============================================================================
# Test Data Fixtures
# ============================================================================

@pytest.fixture
def tier0_task_stored_creds():
    """A TIER-0 task with stored credentials."""
    return {
        "host": "DC01.DOMAIN.COM",
        "path": "\\AdminBackup",
        "type": "TIER-0",
        "runas": "DOMAIN\\Administrator",
        "credentials_hint": "stored_credentials",
        "enabled": "true",
        "cred_password_valid": True,
        "credential_guard": False,
    }


@pytest.fixture
def priv_task_stored_creds():
    """A PRIV task with stored credentials."""
    return {
        "host": "SRV01.DOMAIN.COM",
        "path": "\\ServiceTask",
        "type": "PRIV",
        "runas": "DOMAIN\\ServiceAccount",
        "credentials_hint": "stored_credentials",
        "enabled": "true",
    }


@pytest.fixture
def normal_task_no_creds():
    """A normal task without stored credentials."""
    return {
        "host": "WS01.DOMAIN.COM",
        "path": "\\UserTask",
        "type": "TASK",
        "runas": "DOMAIN\\User1",
        "credentials_hint": "no_saved_credentials",
        "enabled": "true",
    }


@pytest.fixture
def decrypted_task():
    """A task with decrypted password."""
    return {
        "host": "SRV02.DOMAIN.COM",
        "path": "\\CompromisedTask",
        "type": "TIER-0",
        "runas": "DOMAIN\\DomainAdmin",
        "credentials_hint": "stored_credentials",
        "enabled": "true",
        "decrypted_password": "SuperSecret123!",
    }


@pytest.fixture
def failure_task():
    """A FAILURE type task (should be excluded from stats)."""
    return {
        "host": "OFFLINE.DOMAIN.COM",
        "path": "",
        "type": "FAILURE",
        "reason": "Connection failed",
    }


@pytest.fixture
def sample_rows(tier0_task_stored_creds, priv_task_stored_creds, normal_task_no_creds, decrypted_task, failure_task):
    """Collection of sample tasks for testing."""
    return [
        tier0_task_stored_creds,
        priv_task_stored_creds,
        normal_task_no_creds,
        decrypted_task,
        failure_task,
    ]


# ============================================================================
# Severity Calculation Tests
# ============================================================================

class TestSeverityCalculation:
    """Tests for the calculate_severity function with categorical rules."""

    def test_tier0_stored_creds_valid_is_critical(self, tier0_task_stored_creds):
        """TIER-0 + stored creds + valid password = CRITICAL."""
        severity = calculate_severity(tier0_task_stored_creds)

        assert severity.level == "CRITICAL"
        assert "Tier-0 privileged account" in severity.factors
        assert "Credentials stored (DPAPI)" in severity.factors
        assert "Password confirmed valid" in severity.factors

    def test_tier0_stored_creds_unconfirmed_is_high(self):
        """TIER-0 + stored creds + unconfirmed = HIGH."""
        task = {
            "type": "TIER-0",
            "runas": "DOMAIN\\Administrator",
            "credentials_hint": "stored_credentials",
        }
        severity = calculate_severity(task)

        assert severity.level == "HIGH"
        assert "Tier-0 privileged account" in severity.factors

    def test_tier0_stored_creds_credential_guard_is_high(self):
        """TIER-0 + stored creds + Credential Guard = HIGH."""
        task = {
            "type": "TIER-0",
            "runas": "DOMAIN\\Administrator",
            "credentials_hint": "stored_credentials",
            "credential_guard": True,
        }
        severity = calculate_severity(task)

        assert severity.level == "HIGH"
        assert "Credential Guard enabled" in severity.factors

    def test_tier0_no_stored_creds_is_medium(self):
        """TIER-0 without stored creds = MEDIUM."""
        task = {
            "type": "TIER-0",
            "runas": "DOMAIN\\Administrator",
            "credentials_hint": "no_saved_credentials",
        }
        severity = calculate_severity(task)

        assert severity.level == "MEDIUM"

    def test_priv_stored_creds_valid_is_high(self):
        """PRIV + stored creds + valid password = HIGH."""
        task = {
            "type": "PRIV",
            "runas": "DOMAIN\\ServiceAccount",
            "credentials_hint": "stored_credentials",
            "cred_password_valid": True,
        }
        severity = calculate_severity(task)

        assert severity.level == "HIGH"
        assert "Privileged account" in severity.factors

    def test_priv_stored_creds_unconfirmed_is_medium(self, priv_task_stored_creds):
        """PRIV + stored creds + unconfirmed = MEDIUM."""
        severity = calculate_severity(priv_task_stored_creds)

        assert severity.level == "MEDIUM"
        assert "Privileged account" in severity.factors

    def test_priv_no_stored_creds_is_low(self):
        """PRIV without stored creds = LOW."""
        task = {
            "type": "PRIV",
            "runas": "DOMAIN\\ServiceAccount",
            "credentials_hint": "no_saved_credentials",
        }
        severity = calculate_severity(task)

        assert severity.level == "LOW"

    def test_task_stored_creds_is_low(self):
        """Standard TASK + stored creds = LOW."""
        task = {
            "type": "TASK",
            "runas": "DOMAIN\\User1",
            "credentials_hint": "stored_credentials",
        }
        severity = calculate_severity(task)

        assert severity.level == "LOW"

    def test_task_no_stored_creds_is_info(self, normal_task_no_creds):
        """Standard TASK without stored creds = INFO."""
        severity = calculate_severity(normal_task_no_creds)

        assert severity.level == "INFO"

    def test_failure_is_info(self, failure_task):
        """Connection failures = INFO."""
        severity = calculate_severity(failure_task)

        assert severity.level == "INFO"
        assert "Connection failed" in severity.factors

    def test_outdated_password_factor(self):
        """Tasks with invalid/outdated passwords should note it in factors."""
        task = {
            "type": "PRIV",
            "credentials_hint": "stored_credentials",
            "cred_status": "invalid",
        }
        severity = calculate_severity(task)

        assert "Password outdated/invalid" in severity.factors

    def test_account_disabled_factor(self):
        """Tasks with disabled accounts should note it in factors."""
        task = {
            "type": "TIER-0",
            "credentials_hint": "stored_credentials",
            "cred_password_valid": True,  # Needed for CRITICAL
            "reason": "[ACCOUNT DISABLED] Member of Domain Admins",
        }
        severity = calculate_severity(task)

        assert "Account currently disabled in AD" in severity.factors
        # Severity should remain the same (still CRITICAL with stored creds + valid password)
        assert severity.level == "CRITICAL"

    def test_account_enabled_no_factor(self):
        """Tasks without disabled indicator should not have the factor."""
        task = {
            "type": "TIER-0",
            "credentials_hint": "stored_credentials",
            "reason": "Member of Domain Admins",
        }
        severity = calculate_severity(task)

        assert "Account currently disabled in AD" not in severity.factors


class TestSeverityScore:
    """Tests for the SeverityScore dataclass."""

    def test_css_class_generation(self):
        """CSS class should be lowercase severity level."""
        score = SeverityScore(level="CRITICAL", score=90, factors=[])
        assert score.css_class == "severity-critical"

        score = SeverityScore(level="HIGH", score=70, factors=[])
        assert score.css_class == "severity-high"

    def test_badge_color_mapping(self):
        """Badge colors should map to severity levels."""
        critical = SeverityScore(level="CRITICAL", score=90, factors=[])
        high = SeverityScore(level="HIGH", score=70, factors=[])
        medium = SeverityScore(level="MEDIUM", score=50, factors=[])
        low = SeverityScore(level="LOW", score=25, factors=[])
        info = SeverityScore(level="INFO", score=10, factors=[])

        assert critical.badge_color == "#dc2626"  # Red
        assert high.badge_color == "#ea580c"      # Orange
        assert medium.badge_color == "#ca8a04"    # Yellow
        assert low.badge_color == "#2563eb"       # Blue
        assert info.badge_color == "#6b7280"      # Gray


# ============================================================================
# Statistics Calculation Tests
# ============================================================================

class TestStatisticsCalculation:
    """Tests for the calculate_statistics function."""

    def test_basic_stats_calculation(self, sample_rows):
        """Should correctly count tasks and hosts."""
        stats = calculate_statistics(sample_rows)

        # FAILURE rows should be excluded from task count
        assert stats.total_tasks == 4  # 5 rows - 1 failure
        assert stats.total_hosts == 4  # Unique hosts (excluding failure)

    def test_tier0_counting(self, sample_rows):
        """Should correctly count TIER-0 tasks."""
        stats = calculate_statistics(sample_rows)

        # 2 TIER-0 tasks: tier0_task_stored_creds and decrypted_task
        assert stats.tier0_count == 2

    def test_stored_creds_counting(self, sample_rows):
        """Should correctly count tasks with stored credentials."""
        stats = calculate_statistics(sample_rows)

        # 3 tasks have stored_credentials
        assert stats.stored_creds_count == 3

    def test_decrypted_counting(self, sample_rows):
        """Should correctly count tasks with decrypted passwords."""
        stats = calculate_statistics(sample_rows)

        assert stats.decrypted_count == 1

    def test_unique_accounts(self, sample_rows):
        """Should correctly count unique accounts."""
        stats = calculate_statistics(sample_rows)

        # Administrator, ServiceAccount, User1, DomainAdmin = 4 unique
        assert stats.unique_accounts == 4

    def test_tier0_accounts_list(self, sample_rows):
        """Should track TIER-0 account names."""
        stats = calculate_statistics(sample_rows)

        assert len(stats.tier0_accounts) == 2
        assert "DOMAIN\\Administrator" in stats.tier0_accounts
        assert "DOMAIN\\DomainAdmin" in stats.tier0_accounts

    def test_overall_risk_calculation(self):
        """Should calculate overall risk based on findings."""
        # Critical findings -> CRITICAL risk
        critical_stats = AuditStatistics(
            total_hosts=1, total_tasks=1, hosts_with_findings=1,
            critical_count=1, high_count=0, medium_count=0, low_count=0, info_count=0,
            tier0_count=0, priv_count=0, task_count=1,
            stored_creds_count=0, decrypted_count=0, valid_creds_count=0,
            unique_accounts=1, tier0_accounts=[],
        )
        assert critical_stats.overall_risk == "CRITICAL"

        # Decrypted passwords -> CRITICAL risk
        decrypt_stats = AuditStatistics(
            total_hosts=1, total_tasks=1, hosts_with_findings=1,
            critical_count=0, high_count=0, medium_count=0, low_count=0, info_count=1,
            tier0_count=0, priv_count=0, task_count=1,
            stored_creds_count=0, decrypted_count=1, valid_creds_count=0,
            unique_accounts=1, tier0_accounts=[],
        )
        assert decrypt_stats.overall_risk == "CRITICAL"

        # High findings or TIER-0 -> HIGH risk
        high_stats = AuditStatistics(
            total_hosts=1, total_tasks=1, hosts_with_findings=1,
            critical_count=0, high_count=1, medium_count=0, low_count=0, info_count=0,
            tier0_count=0, priv_count=0, task_count=1,
            stored_creds_count=0, decrypted_count=0, valid_creds_count=0,
            unique_accounts=1, tier0_accounts=[],
        )
        assert high_stats.overall_risk == "HIGH"

        # No significant findings -> INFO
        clean_stats = AuditStatistics(
            total_hosts=1, total_tasks=1, hosts_with_findings=0,
            critical_count=0, high_count=0, medium_count=0, low_count=0, info_count=1,
            tier0_count=0, priv_count=0, task_count=1,
            stored_creds_count=0, decrypted_count=0, valid_creds_count=0,
            unique_accounts=1, tier0_accounts=[],
        )
        assert clean_stats.overall_risk == "INFO"

    def test_empty_rows_handling(self):
        """Should handle empty input gracefully."""
        stats = calculate_statistics([])

        assert stats.total_hosts == 0
        assert stats.total_tasks == 0
        assert stats.overall_risk == "INFO"

    def test_tier0_accounts_deduplication_case_insensitive(self):
        """Should deduplicate tier0 accounts with different cases."""
        rows = [
            {
                "host": "host1",
                "type": "TIER-0",
                "runas": "DOMAIN\\Administrator",
                "credentials_hint": "stored",
            },
            {
                "host": "host2",
                "type": "TIER-0",
                "runas": "domain\\administrator",
                "credentials_hint": "stored",
            },
            {
                "host": "host3",
                "type": "TIER-0",
                "runas": "Administrator",
                "credentials_hint": "stored",
            },
        ]
        stats = calculate_statistics(rows)

        # Should deduplicate to 1 account (preferring the one with domain)
        assert len(stats.tier0_accounts) == 1
        # Should prefer the version with domain prefix
        assert stats.tier0_accounts[0].lower() in ["domain\\administrator"]

    def test_tier0_accounts_deduplication_domain_variations(self):
        """Should deduplicate accounts with and without domain prefix."""
        rows = [
            {
                "host": "host1",
                "type": "TIER-0",
                "runas": "highpriv",
                "credentials_hint": "stored",
            },
            {
                "host": "host2",
                "type": "TIER-0",
                "runas": "BADSUCCESSOR\\highpriv",
                "credentials_hint": "stored",
            },
            {
                "host": "host3",
                "type": "TIER-0",
                "runas": "badsuccessor\\highpriv",
                "credentials_hint": "stored",
            },
        ]
        stats = calculate_statistics(rows)

        # Should deduplicate to 1 account
        assert len(stats.tier0_accounts) == 1
        # Should prefer the version with domain prefix
        assert "\\" in stats.tier0_accounts[0]

    def test_unique_accounts_deduplication(self):
        """Should deduplicate unique accounts with different formats."""
        rows = [
            {
                "host": "host1",
                "type": "TASK",
                "runas": "DOMAIN\\ServiceUser",
            },
            {
                "host": "host2",
                "type": "TASK",
                "runas": "domain\\serviceuser",
            },
            {
                "host": "host3",
                "type": "TASK",
                "runas": "ServiceUser",
            },
        ]
        stats = calculate_statistics(rows)

        # Should deduplicate to 1 unique account
        assert stats.unique_accounts == 1


# ============================================================================
# HTML Generation Tests
# ============================================================================

class TestHtmlReportGeneration:
    """Tests for HTML report generation."""

    def test_generate_report_creates_file(self, sample_rows):
        """Should create an HTML file at the specified path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")

            result = generate_html_report(sample_rows, output_path)

            assert result == output_path
            assert os.path.exists(output_path)

    def test_generate_report_content(self, sample_rows):
        """Generated HTML should contain key sections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")

            generate_html_report(sample_rows, output_path)

            with open(output_path, encoding="utf-8") as f:
                content = f.read()

            # Check for key sections
            assert "TaskHound Security Audit Report" in content
            assert "Summary" in content
            assert "Detailed Findings" in content

            # Check for task data
            assert "DC01.DOMAIN.COM" in content
            assert "DOMAIN\\Administrator" in content

    def test_generate_report_creates_directory(self, sample_rows):
        """Should create output directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "subdir", "nested", "report.html")

            generate_html_report(sample_rows, output_path)

            assert os.path.exists(output_path)

    def test_generate_report_with_custom_timestamp(self, sample_rows):
        """Should use custom timestamp if provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            custom_time = "2025-11-29 12:00:00"

            generate_html_report(sample_rows, output_path, scan_time=custom_time)

            with open(output_path, encoding="utf-8") as f:
                content = f.read()

            assert custom_time in content

    def test_generate_report_empty_rows(self):
        """Should handle empty input gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")

            generate_html_report([], output_path)

            assert os.path.exists(output_path)

            with open(output_path, encoding="utf-8") as f:
                content = f.read()

            assert "No findings to display" in content


class TestAuditSummary:
    """Tests for the generate_audit_summary function."""

    def test_returns_stats_and_findings(self, sample_rows):
        """Should return statistics and sorted findings."""
        stats, findings = generate_audit_summary(sample_rows)

        assert isinstance(stats, AuditStatistics)
        assert isinstance(findings, list)
        assert len(findings) == 4  # Excludes FAILURE row

    def test_findings_sorted_by_severity(self, sample_rows):
        """Findings should be sorted by severity score descending."""
        _, findings = generate_audit_summary(sample_rows)

        scores = [f[0].score for f in findings]
        assert scores == sorted(scores, reverse=True)

    def test_findings_include_severity_and_row(self, sample_rows):
        """Each finding should be a tuple of (SeverityScore, row_dict)."""
        _, findings = generate_audit_summary(sample_rows)

        for severity, row in findings:
            assert isinstance(severity, SeverityScore)
            assert isinstance(row, dict)


# ============================================================================
# Edge Cases and Integration Tests
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_task_with_only_resolved_runas(self):
        """Should handle tasks with only resolved_runas (no runas)."""
        task = {
            "host": "SRV01.DOMAIN.COM",
            "path": "\\TestTask",
            "type": "PRIV",
            "resolved_runas": "DOMAIN\\ResolvedUser",
            "credentials_hint": "stored_credentials",
        }

        stats = calculate_statistics([task])
        assert stats.unique_accounts == 1

    def test_task_with_sid_runas(self):
        """Should handle tasks with SID as runas."""
        task = {
            "host": "SRV01.DOMAIN.COM",
            "path": "\\TestTask",
            "type": "TASK",
            "runas": "S-1-5-21-123456789-987654321-111111111-1001",
            "credentials_hint": "stored_credentials",
        }

        stats = calculate_statistics([task])
        # SID-based runas should not be counted as unique account
        assert stats.unique_accounts == 0

    def test_mixed_taskrow_and_dict(self):
        """Should handle mix of TaskRow objects and dicts."""
        from taskhound.models.task import TaskRow

        task_row = TaskRow(
            host="SRV01.DOMAIN.COM",
            path="\\TestTask",
            type="PRIV",
            runas="DOMAIN\\User1",
            credentials_hint="stored_credentials",
        )
        task_dict = {
            "host": "SRV02.DOMAIN.COM",
            "path": "\\TestTask2",
            "type": "TASK",
            "runas": "DOMAIN\\User2",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")

            # Should not raise
            generate_html_report([task_row, task_dict], output_path)

            assert os.path.exists(output_path)

    def test_very_long_task_path(self):
        """Should handle very long task paths without breaking layout."""
        task = {
            "host": "SRV01.DOMAIN.COM",
            "path": "\\Very\\Long\\Path\\That\\Goes\\On\\And\\On\\And\\Never\\Seems\\To\\End\\TaskName",
            "type": "TASK",
            "runas": "DOMAIN\\User",
            "credentials_hint": "stored_credentials",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")

            generate_html_report([task], output_path)

            with open(output_path, encoding="utf-8") as f:
                content = f.read()

            assert "Never\\Seems\\To\\End" in content

    def test_special_characters_in_password(self):
        """Should properly escape special characters in decrypted passwords."""
        task = {
            "host": "SRV01.DOMAIN.COM",
            "path": "\\TestTask",
            "type": "TIER-0",
            "runas": "DOMAIN\\Admin",
            "credentials_hint": "stored_credentials",
            "decrypted_password": "P@ss<word>&\"'123!",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")

            generate_html_report([task], output_path)

            with open(output_path, encoding="utf-8") as f:
                content = f.read()

            # Password should be escaped but present
            assert "P@ss&lt;word&gt;" in content

    def test_none_values_in_task_fields(self):
        """Should handle None values in task fields without crashing."""
        task = {
            "host": "SRV01.DOMAIN.COM",
            "path": None,  # None path
            "type": None,  # None type
            "runas": None,  # None runas
            "resolved_runas": None,  # None resolved_runas too
            "credentials_hint": "stored_credentials",
            "decrypted_password": None,  # None password
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")

            # Should not raise AttributeError
            generate_html_report([task], output_path)

            with open(output_path, encoding="utf-8") as f:
                content = f.read()

            # Should have fallback values
            assert "N/A" in content or "Unknown" in content
