# Tests for service classification and shared privilege detection.

from unittest.mock import MagicMock

from taskhound.classification import (
    _check_account_disabled,
    _classify_by_privilege,
    classify_service,
)
from taskhound.models.service import ServiceRow


class TestClassifyByPrivilege:
    """Tests for the shared privilege detection helper."""

    def test_tier0_via_bloodhound(self):
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (True, ["Domain Admins"])

        result = _classify_by_privilege("CORP\\admin", hv)
        assert result is not None
        assert result[0] == "TIER-0"
        assert "Domain Admins" in result[1]

    def test_priv_via_bloodhound(self):
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = True

        result = _classify_by_privilege("CORP\\svcadmin", hv)
        assert result is not None
        assert result[0] == "PRIV"

    def test_not_privileged_via_bloodhound(self):
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False

        result = _classify_by_privilege("CORP\\normaluser", hv)
        assert result is None

    def test_tier0_via_ldap_cache(self):
        tier0_cache = {"admin": (True, ["Domain Admins", "Enterprise Admins"])}

        result = _classify_by_privilege("CORP\\admin", hv=None, tier0_cache=tier0_cache)
        assert result is not None
        assert result[0] == "TIER-0"
        assert "Domain Admins" in result[1]

    def test_bare_name_not_matched_against_tier0_cache(self):
        """Bare names (no domain qualifier) should not match tier0_cache."""
        tier0_cache = {"admin": (True, ["Domain Admins"])}

        result = _classify_by_privilege("admin", hv=None, tier0_cache=tier0_cache)
        assert result is None

    def test_sid_with_resolved_account(self):
        tier0_cache = {"admin": (True, ["Domain Admins"])}

        result = _classify_by_privilege(
            "S-1-5-21-1234-500",
            hv=None,
            tier0_cache=tier0_cache,
            resolved_account="CORP\\admin",
        )
        assert result is not None
        assert result[0] == "TIER-0"

    def test_no_hv_no_cache(self):
        result = _classify_by_privilege("CORP\\user", hv=None, tier0_cache=None)
        assert result is None


class TestCheckAccountDisabled:
    def test_disabled_account(self):
        hv = MagicMock()
        hv.loaded = True
        hv.is_account_enabled.return_value = False

        assert _check_account_disabled(hv, "CORP\\old_svc") is True

    def test_enabled_account(self):
        hv = MagicMock()
        hv.loaded = True
        hv.is_account_enabled.return_value = True

        assert _check_account_disabled(hv, "CORP\\active_svc") is False

    def test_no_hv(self):
        assert _check_account_disabled(None, "CORP\\user") is False


class TestClassifyService:
    def _make_row(self, account="CORP\\svcuser", is_gmsa=False):
        return ServiceRow(
            host="dc01.corp.local",
            service_name="TestSvc",
            start_name=account,
            is_gmsa=is_gmsa,
        )

    def test_tier0_classification(self):
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (True, ["Domain Admins"])
        hv.check_highvalue.return_value = False
        hv.is_account_enabled.return_value = True
        hv.analyze_password_age.return_value = ("UNKNOWN", "")

        row = self._make_row("CORP\\admin")
        result = classify_service(row, "CORP\\admin", hv=hv)

        assert result.task_type == "TIER-0"
        assert row.type == "TIER-0"
        assert "Domain Admins" in row.reason

    def test_priv_classification(self):
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = True
        hv.is_account_enabled.return_value = True
        hv.analyze_password_age.return_value = ("UNKNOWN", "")

        row = self._make_row("CORP\\hvuser")
        result = classify_service(row, "CORP\\hvuser", hv=hv)

        assert result.task_type == "PRIV"
        assert row.type == "PRIV"

    def test_service_classification(self):
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False
        hv.is_account_enabled.return_value = True
        hv.analyze_password_age.return_value = ("UNKNOWN", "")

        row = self._make_row("CORP\\normaluser")
        result = classify_service(row, "CORP\\normaluser", hv=hv)

        assert result.task_type == "SERVICE"
        assert row.type == "SERVICE"

    def test_disabled_account_annotation(self):
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (True, ["Domain Admins"])
        hv.is_account_enabled.return_value = False
        hv.analyze_password_age.return_value = ("UNKNOWN", "")

        row = self._make_row("CORP\\old_admin")
        classify_service(row, "CORP\\old_admin", hv=hv)

        assert "[ACCOUNT DISABLED]" in row.reason
        assert row.is_disabled_account is True

    def test_gmsa_annotation_tier0(self):
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (True, ["Domain Admins"])
        hv.is_account_enabled.return_value = True
        hv.analyze_password_age.return_value = ("UNKNOWN", "")

        row = self._make_row("CORP\\gmsa$", is_gmsa=True)
        classify_service(row, "CORP\\gmsa$", hv=hv)

        assert "[gMSA]" in row.reason

    def test_gmsa_annotation_service(self):
        row = self._make_row("CORP\\webapp$", is_gmsa=True)
        result = classify_service(row, "CORP\\webapp$", hv=None)

        assert result.task_type == "SERVICE"
        assert "gMSA" in (row.reason or "")
        assert "NTLM hash extracted from LSA" in (row.reason or "")

    def test_disabled_account_service_level(self):
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False
        hv.is_account_enabled.return_value = False
        hv.analyze_password_age.return_value = ("UNKNOWN", "")

        row = self._make_row("CORP\\oldsvc")
        classify_service(row, "CORP\\oldsvc", hv=hv)

        assert row.type == "SERVICE"
        assert "[ACCOUNT DISABLED]" in (row.reason or "")
        assert row.is_disabled_account is True

    def test_classification_with_tier0_cache(self):
        tier0_cache = {"sqladmin": (True, ["Domain Admins"])}
        row = self._make_row("CORP\\sqladmin")
        result = classify_service(row, "CORP\\sqladmin", hv=None, tier0_cache=tier0_cache)

        assert result.task_type == "TIER-0"
        assert row.type == "TIER-0"

    def test_should_include_always_true(self):
        """Services with domain accounts are always included (unlike tasks with credential hints)."""
        row = self._make_row("CORP\\user")
        result = classify_service(row, "CORP\\user", hv=None)

        assert result.should_include is True

    def test_no_hv_no_cache_defaults_to_service(self):
        row = self._make_row("CORP\\user")
        result = classify_service(row, "CORP\\user", hv=None)

        assert result.task_type == "SERVICE"
        assert row.type == "SERVICE"
