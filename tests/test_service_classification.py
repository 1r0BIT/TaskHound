# Tests for service classification and shared privilege detection.

from unittest.mock import MagicMock, patch

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


class TestServiceEnumerationSIDResolution:
    """Test that perform_service_enumeration passes hv_loader= (not hv=) to format_runas_with_sid_resolution."""

    @patch("taskhound.smb.svcctl.enumerate_services")
    @patch("taskhound.parsers.service_filter.filter_domain_services")
    @patch("taskhound.resolver.format_runas_with_sid_resolution")
    @patch("taskhound.resolver.is_sid", return_value=True)
    @patch("taskhound.classification.classify_service")
    def test_passes_hv_loader_kwarg(
        self, mock_classify, mock_is_sid, mock_format_runas, mock_filter, mock_enum
    ):
        """Verify hv_loader= keyword (not hv=) is passed to format_runas_with_sid_resolution."""
        from taskhound.engine.helpers import perform_service_enumeration

        # Set up mock chain: enumerate -> filter -> one service with a SID account
        mock_enum.return_value = [{"ServiceName": "TestSvc", "StartName": "S-1-5-21-1234-1001"}]
        mock_svc = MagicMock()
        mock_svc.__getitem__ = lambda self, k: {"ServiceName": "TestSvc", "StartName": "S-1-5-21-1234-1001"}[k]
        mock_filter.return_value = [mock_svc]

        # ServiceRow.from_svcctl returns a row with a SID start_name
        mock_row = ServiceRow(host="dc01.corp.local", service_name="TestSvc", start_name="S-1-5-21-1234-1001")

        mock_format_runas.return_value = "CORP\\resolved_user"
        mock_classify.return_value = MagicMock(task_type="SERVICE", should_include=True)

        fake_hv = MagicMock()
        fake_smb = MagicMock()

        with patch("taskhound.models.service.ServiceRow.from_svcctl", return_value=mock_row):
            perform_service_enumeration(
                target="dc01",
                smb=fake_smb,
                host="dc01.corp.local",
                hv=fake_hv,
                domain="corp.local",
            )

        # The critical assertion: format_runas_with_sid_resolution must receive hv_loader=, not hv=
        mock_format_runas.assert_called_once()
        call_kwargs = mock_format_runas.call_args
        assert "hv_loader" in call_kwargs.kwargs, (
            "format_runas_with_sid_resolution should be called with hv_loader= keyword"
        )
        assert call_kwargs.kwargs["hv_loader"] is fake_hv
