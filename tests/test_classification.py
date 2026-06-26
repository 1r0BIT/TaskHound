# Tests for task classification logic.

from unittest.mock import MagicMock, patch

from taskhound.classification import (
    ClassificationResult,
    _analyze_password_age,
    _get_task_date_for_analysis,
    classify_task,
)
from taskhound.models.task import TaskRow, TaskType


class TestGetTaskDateForAnalysis:
    """Tests for _get_task_date_for_analysis helper."""

    def test_prefers_explicit_date(self):
        """Should prefer explicit date over start_boundary."""
        meta = {
            "date": "2024-01-15T10:00:00",
            "start_boundary": "2024-06-01T08:00:00",
        }
        date, is_fallback = _get_task_date_for_analysis(meta)
        assert date == "2024-01-15T10:00:00"
        assert is_fallback is False

    def test_falls_back_to_start_boundary(self):
        """Should use start_boundary when date is not available."""
        meta = {
            "start_boundary": "2024-06-01T08:00:00",
        }
        date, is_fallback = _get_task_date_for_analysis(meta)
        assert date == "2024-06-01T08:00:00"
        assert is_fallback is True

    def test_returns_none_when_no_dates(self):
        """Should return None when neither date is available."""
        meta = {}
        date, is_fallback = _get_task_date_for_analysis(meta)
        assert date is None
        assert is_fallback is False

    def test_empty_date_uses_fallback(self):
        """Should use fallback when date is empty string."""
        meta = {
            "date": "",
            "start_boundary": "2024-06-01T08:00:00",
        }
        date, is_fallback = _get_task_date_for_analysis(meta)
        # Empty string is falsy, so should use fallback
        assert date == "2024-06-01T08:00:00"
        assert is_fallback is True


class TestAnalyzePasswordAge:
    """Tests for _analyze_password_age helper."""

    def test_returns_none_when_hv_is_none(self):
        """Should return None when hv is None."""
        result = _analyze_password_age(None, "user@domain.local", {}, "\\Task")
        assert result is None

    def test_returns_none_when_hv_not_loaded(self):
        """Should return None when hv is not loaded."""
        hv = MagicMock()
        hv.loaded = False
        result = _analyze_password_age(hv, "user@domain.local", {}, "\\Task")
        assert result is None

    def test_returns_analysis_when_risk_known(self):
        """Should return analysis when risk level is known."""
        hv = MagicMock()
        hv.loaded = True
        hv.analyze_password_age.return_value = ("HIGH", "Password 180+ days old")

        meta = {"date": "2024-01-01T00:00:00"}
        result = _analyze_password_age(hv, "user@domain.local", meta, "\\Task")

        assert result == "HIGH: Password 180+ days old"
        hv.analyze_password_age.assert_called_once()

    def test_returns_none_when_risk_unknown(self):
        """Should return None when risk level is UNKNOWN."""
        hv = MagicMock()
        hv.loaded = True
        hv.analyze_password_age.return_value = ("UNKNOWN", None)

        meta = {"date": "2024-01-01T00:00:00"}
        _analyze_password_age(hv, "user@domain.local", meta, "\\Task")

    def test_warns_when_using_fallback_date(self):
        """Should warn when using start_boundary fallback for date."""
        hv = MagicMock()
        hv.loaded = True
        hv.analyze_password_age.return_value = ("HIGH", "Analysis result")

        # meta with only start_boundary (fallback)
        meta = {"start_boundary": "2024-01-01T00:00:00"}

        with patch("taskhound.classification.warn") as mock_warn:
            result = _analyze_password_age(hv, "user@domain.local", meta, "\\TestTask")
            # Should have warned about using fallback
            mock_warn.assert_called_once()
            assert "no explicit creation date" in mock_warn.call_args[0][0]
            assert "TestTask" in mock_warn.call_args[0][0]
            # Should still return the analysis result even with fallback warning
            assert result == "HIGH: Analysis result"


class TestClassifyTask:
    """Tests for classify_task function."""

    def test_tier0_with_stored_credentials(self):
        """Should classify as TIER-0 when tier0 check passes."""
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (True, ["Domain Admin member"])
        hv.analyze_password_age.return_value = ("HIGH", "Password old")

        row = TaskRow(
            host="host1.domain.local",
            path="\\AdminTask",
            runas="admin@domain.local",
            credentials_hint="stored_credentials",
        )
        meta = {"date": "2024-01-01"}

        result = classify_task(
            row=row,
            meta=meta,
            runas="admin@domain.local",
            rel_path="\\AdminTask",
            hv=hv,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.task_type == "TIER-0"
        assert result.reason == "Domain Admin member"
        assert result.password_analysis == "HIGH: Password old"
        assert result.should_include is True
        assert row.type == TaskType.TIER0.value

    def test_tier0_without_saved_credentials(self):
        """Should note when TIER-0 task has no saved credentials."""
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (True, ["Domain Admin"])

        row = TaskRow(
            host="host1.domain.local",
            path="\\AdminTask",
            runas="admin@domain.local",
            credentials_hint="no_saved_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="admin@domain.local",
            rel_path="\\AdminTask",
            hv=hv,
            show_unsaved_creds=True,
            include_local=False,
        )

        assert result.task_type == "TIER-0"
        assert "no saved credentials" in result.reason
        assert "DPAPI dump not applicable" in result.reason

    def test_priv_classification(self):
        """Should classify as PRIV when high-value check passes."""
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = True
        hv.analyze_password_age.return_value = ("MEDIUM", "Password 90 days old")

        row = TaskRow(
            host="host1.domain.local",
            path="\\ServiceTask",
            runas="serviceaccount@domain.local",
            credentials_hint="stored_credentials",
        )
        meta = {"date": "2024-06-01"}

        result = classify_task(
            row=row,
            meta=meta,
            runas="serviceaccount@domain.local",
            rel_path="\\ServiceTask",
            hv=hv,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.task_type == "PRIV"
        assert "High Value match" in result.reason
        assert result.should_include is True
        assert row.type == TaskType.PRIV.value

    def test_priv_without_saved_credentials(self):
        """Should note when PRIV task has no saved credentials."""
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = True

        row = TaskRow(
            host="host1.domain.local",
            path="\\HighValueTask",
            runas="serviceaccount@domain.local",
            credentials_hint="no_saved_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="serviceaccount@domain.local",
            rel_path="\\HighValueTask",
            hv=hv,
            show_unsaved_creds=True,
            include_local=False,
        )

        assert result.task_type == "PRIV"
        assert "no saved credentials" in result.reason
        assert "DPAPI dump not applicable" in result.reason
        assert result.password_analysis is None  # No analysis for tasks without saved creds

    @patch("taskhound.resolver.looks_like_domain_user")
    def test_regular_task_domain_user(self, mock_looks_like):
        """Should include regular domain user tasks."""
        mock_looks_like.return_value = True

        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False
        hv.analyze_password_age.return_value = ("UNKNOWN", None)

        row = TaskRow(
            host="host1.domain.local",
            path="\\UserTask",
            runas="user@domain.local",
            credentials_hint="stored_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="user@domain.local",
            rel_path="\\UserTask",
            hv=hv,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.task_type == "TASK"
        assert result.should_include is True

    @patch("taskhound.classification.looks_like_domain_user")
    def test_excludes_no_saved_creds_by_default(self, mock_looks_like):
        """Should exclude tasks without saved credentials by default."""
        mock_looks_like.return_value = True

        row = TaskRow(
            host="host1.domain.local",
            path="\\Task",
            runas="user@domain.local",
            credentials_hint="no_saved_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="user@domain.local",
            rel_path="\\Task",
            hv=None,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.should_include is False

    @patch("taskhound.classification.looks_like_domain_user")
    def test_includes_no_saved_creds_when_requested(self, mock_looks_like):
        """Should include tasks without saved credentials when show_unsaved_creds=True."""
        mock_looks_like.return_value = True

        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False

        row = TaskRow(
            host="host1.domain.local",
            path="\\Task",
            runas="user@domain.local",
            credentials_hint="no_saved_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="user@domain.local",
            rel_path="\\Task",
            hv=hv,
            show_unsaved_creds=True,
            include_local=False,
        )

        assert result.should_include is True

    @patch("taskhound.classification.looks_like_domain_user")
    def test_includes_local_accounts_when_requested(self, mock_looks_like):
        """Should include local accounts when include_local=True."""
        mock_looks_like.return_value = False  # Not a domain user

        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False
        hv.analyze_password_age.return_value = ("UNKNOWN", None)

        row = TaskRow(
            host="host1.domain.local",
            path="\\LocalTask",
            runas="LocalAdmin",
            credentials_hint="stored_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="LocalAdmin",
            rel_path="\\LocalTask",
            hv=hv,
            show_unsaved_creds=False,
            include_local=True,
        )

        assert result.should_include is True

    @patch("taskhound.classification.looks_like_domain_user")
    def test_excludes_local_accounts_by_default(self, mock_looks_like):
        """Should exclude local accounts by default."""
        mock_looks_like.return_value = False  # Not a domain user

        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False

        row = TaskRow(
            host="host1.domain.local",
            path="\\LocalTask",
            runas="LocalUser",
            credentials_hint=None,
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="LocalUser",
            rel_path="\\LocalTask",
            hv=hv,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.should_include is False

    def test_no_hv_classification(self):
        """Should work without HighValueLoader (no privilege detection)."""
        row = TaskRow(
            host="host1.domain.local",
            path="\\Task",
            runas="user@domain.local",
            credentials_hint="stored_credentials",
        )
        meta = {}

        with patch("taskhound.classification.looks_like_domain_user", return_value=True):
            result = classify_task(
                row=row,
                meta=meta,
                runas="user@domain.local",
                rel_path="\\Task",
                hv=None,
                show_unsaved_creds=False,
                include_local=False,
            )

        assert result.task_type == "TASK"
        assert result.should_include is True


class TestAnalyzePasswordAgeWithPwdCache:
    """Tests for _analyze_password_age with pwd_cache fallback."""

    def test_pwd_cache_fallback_when_no_bloodhound(self):
        """Should use pwd_cache when BloodHound not available."""
        from datetime import datetime

        pwd_cache = {
            "testuser": datetime(2024, 1, 1, 10, 0, 0),
        }
        meta = {"date": "2024-06-01T00:00:00"}

        with patch("taskhound.parsers.highvalue._analyze_password_freshness") as mock_analyze:
            mock_analyze.return_value = ("GOOD", "Password changed after task creation")

            result = _analyze_password_age(
                hv=None,
                runas="DOMAIN\\testuser",
                meta=meta,
                rel_path="\\Task",
                pwd_cache=pwd_cache,
            )

            assert result == "GOOD: Password changed after task creation"
            mock_analyze.assert_called_once()

    def test_pwd_cache_normalizes_domain_username(self):
        """Should normalize DOMAIN\\user to just user for cache lookup."""
        from datetime import datetime

        pwd_cache = {
            "serviceacct": datetime(2024, 3, 15, 12, 0, 0),
        }
        meta = {"date": "2024-01-01T00:00:00"}

        with patch("taskhound.parsers.highvalue._analyze_password_freshness") as mock_analyze:
            mock_analyze.return_value = ("BAD", "Password older than task")

            result = _analyze_password_age(
                hv=None,
                runas="CONTOSO\\ServiceAcct",  # Different case
                meta=meta,
                rel_path="\\Task",
                pwd_cache=pwd_cache,
            )

            assert result == "BAD: Password older than task"

    def test_pwd_cache_handles_simple_username(self):
        """Should handle username without domain prefix."""
        from datetime import datetime

        pwd_cache = {
            "localuser": datetime(2024, 5, 1, 8, 0, 0),
        }
        meta = {"date": "2024-04-01T00:00:00"}

        with patch("taskhound.parsers.highvalue._analyze_password_freshness") as mock_analyze:
            mock_analyze.return_value = ("GOOD", "Password fresh")

            result = _analyze_password_age(
                hv=None,
                runas="localuser",
                meta=meta,
                rel_path="\\Task",
                pwd_cache=pwd_cache,
            )

            assert result == "GOOD: Password fresh"

    def test_pwd_cache_returns_none_when_user_not_found(self):
        """Should return None when user not in pwd_cache."""
        from datetime import datetime

        pwd_cache = {
            "otheruser": datetime(2024, 1, 1, 10, 0, 0),
        }
        meta = {"date": "2024-06-01T00:00:00"}

        result = _analyze_password_age(
            hv=None,
            runas="unknownuser",
            meta=meta,
            rel_path="\\Task",
            pwd_cache=pwd_cache,
        )

        assert result is None

    def test_pwd_cache_returns_none_when_no_task_date(self):
        """Should return None when no task date available."""
        from datetime import datetime

        pwd_cache = {
            "testuser": datetime(2024, 1, 1, 10, 0, 0),
        }
        meta = {}  # No date

        result = _analyze_password_age(
            hv=None,
            runas="testuser",
            meta=meta,
            rel_path="\\Task",
            pwd_cache=pwd_cache,
        )

        assert result is None

    def test_pwd_cache_returns_none_when_cache_is_none(self):
        """Should return None when pwd_cache is None."""
        meta = {"date": "2024-06-01T00:00:00"}

        result = _analyze_password_age(
            hv=None,
            runas="testuser",
            meta=meta,
            rel_path="\\Task",
            pwd_cache=None,
        )

        assert result is None

    def test_pwd_cache_handles_exception_gracefully(self):
        """Should handle exceptions and return None."""
        from datetime import datetime

        pwd_cache = {
            "testuser": datetime(2024, 1, 1, 10, 0, 0),
        }
        meta = {"date": "2024-06-01T00:00:00"}

        with patch("taskhound.parsers.highvalue._analyze_password_freshness") as mock_analyze:
            mock_analyze.side_effect = Exception("Analysis failed")

            result = _analyze_password_age(
                hv=None,
                runas="testuser",
                meta=meta,
                rel_path="\\Task",
                pwd_cache=pwd_cache,
            )

            assert result is None

    def test_pwd_cache_skipped_when_bloodhound_has_data(self):
        """Should not use pwd_cache when BloodHound returns valid analysis."""
        from datetime import datetime

        hv = MagicMock()
        hv.loaded = True
        hv.analyze_password_age.return_value = ("HIGH", "BloodHound analysis")

        pwd_cache = {
            "testuser": datetime(2024, 1, 1, 10, 0, 0),
        }
        meta = {"date": "2024-06-01T00:00:00"}

        result = _analyze_password_age(
            hv=hv,
            runas="testuser",
            meta=meta,
            rel_path="\\Task",
            pwd_cache=pwd_cache,
        )

        # Should use BloodHound result, not pwd_cache
        assert result == "HIGH: BloodHound analysis"

    def test_pwd_cache_used_when_bloodhound_returns_unknown(self):
        """Should fall back to pwd_cache when BloodHound returns UNKNOWN."""
        from datetime import datetime

        hv = MagicMock()
        hv.loaded = True
        hv.analyze_password_age.return_value = ("UNKNOWN", None)

        pwd_cache = {
            "testuser": datetime(2024, 1, 1, 10, 0, 0),
        }
        meta = {"date": "2024-06-01T00:00:00"}

        with patch("taskhound.parsers.highvalue._analyze_password_freshness") as mock_analyze:
            mock_analyze.return_value = ("GOOD", "Cache-based analysis")

            result = _analyze_password_age(
                hv=hv,
                runas="testuser",
                meta=meta,
                rel_path="\\Task",
                pwd_cache=pwd_cache,
            )

            assert result == "GOOD: Cache-based analysis"


class TestClassifyTaskWithPwdCache:
    """Tests for classify_task with pwd_cache parameter."""

    def test_pwd_cache_passed_to_password_analysis(self):
        """Should pass pwd_cache to password analysis for regular tasks."""
        from datetime import datetime

        pwd_cache = {
            "regularuser": datetime(2024, 1, 1, 10, 0, 0),
        }

        row = TaskRow(
            host="host1.domain.local",
            path="\\RegularTask",
            runas="regularuser",
            credentials_hint="stored_credentials",
        )
        meta = {"date": "2024-06-01T00:00:00"}

        with patch("taskhound.classification._analyze_password_age") as mock_analyze:
            mock_analyze.return_value = "Password analysis result"

            classify_task(
                row=row,
                meta=meta,
                runas="regularuser",
                rel_path="\\RegularTask",
                hv=None,
                show_unsaved_creds=False,
                include_local=False,
                pwd_cache=pwd_cache,
            )

            # Verify pwd_cache was passed
            mock_analyze.assert_called_once()
            call_kwargs = mock_analyze.call_args
            assert call_kwargs[1].get("pwd_cache") == pwd_cache or call_kwargs[0][-1] == pwd_cache


class TestClassificationResult:
    """Tests for ClassificationResult dataclass."""

    def test_default_values(self):
        """Should have sensible defaults."""
        result = ClassificationResult(task_type="TASK")
        assert result.task_type == "TASK"
        assert result.reason is None
        assert result.password_analysis is None
        assert result.should_include is True

    def test_all_values(self):
        """Should store all provided values."""
        result = ClassificationResult(
            task_type="TIER-0",
            reason="Domain Admin",
            password_analysis="Old password",
            should_include=True,
        )
        assert result.task_type == "TIER-0"
        assert result.reason == "Domain Admin"
        assert result.password_analysis == "Old password"
        assert result.should_include is True


class TestClassifyTaskBareName:
    """Bare-username RunAs handling (no DOMAIN\\ prefix, no UPN @).

    A scheduled task's <UserId> is sometimes a bare sAMAccountName. The same domain
    account stored domain-qualified on one host and bare on another must classify the
    same. The primary path resolves the bare name to a domain SID upstream (online +
    LDAP); the opt-in --match-bare-runas flag covers offline / --opsec / --no-ldap.
    """

    SID = "S-1-5-21-1234-5678-9012-1107"

    def _hv(self):
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False
        hv.check_tier0_bare.return_value = (False, [])
        hv.check_highvalue_bare.return_value = False
        hv.analyze_password_age.return_value = ("UNKNOWN", None)
        hv.is_account_enabled.return_value = True
        return hv

    def _row(self, runas="svc_x"):
        return TaskRow(host="h.domain.local", path="\\T", runas=runas, credentials_hint="stored_credentials")

    def test_bloodhound_resolved_sid_is_tier0(self):
        """A bare runas resolved to a domain SID is matched via the SID (check_tier0)."""
        hv = self._hv()
        hv.check_tier0.side_effect = lambda v: (
            (True, ["TIER0 Group Membership", "AdminSDHolder"]) if v == self.SID else (False, [])
        )

        result = classify_task(
            row=self._row(), meta={}, runas="svc_x", rel_path="\\T", hv=hv,
            show_unsaved_creds=False, include_local=False, resolved_runas_sid=self.SID,
        )

        assert result.task_type == "TIER-0"
        assert "TIER0 Group Membership" in result.reason
        assert "matched by bare username" not in result.reason  # SID match needs no caveat
        hv.check_tier0.assert_any_call(self.SID)  # matched by SID, not the bare name

    def test_bare_no_resolution_no_flag_is_task(self):
        """Without a resolved SID and without the flag, a bare runas stays TASK."""
        hv = self._hv()
        result = classify_task(
            row=self._row(), meta={}, runas="svc_x", rel_path="\\T", hv=hv,
            show_unsaved_creds=False, include_local=False,
        )
        assert result.task_type == "TASK"
        hv.check_tier0.assert_called_once_with("svc_x")  # falls back to the bare name
        hv.check_tier0_bare.assert_not_called()

    def test_match_bare_flag_tier0_annotated(self):
        """--match-bare-runas matches a non-local bare name and annotates the reason."""
        hv = self._hv()
        hv.check_tier0_bare.return_value = (True, ["TIER0 Group Membership"])

        result = classify_task(
            row=self._row(), meta={}, runas="svc_x", rel_path="\\T", hv=hv,
            show_unsaved_creds=False, include_local=False, match_bare_runas=True,
        )

        assert result.task_type == "TIER-0"
        assert "matched by bare username" in result.reason
        hv.check_tier0_bare.assert_called_once_with("svc_x")

    def test_match_bare_flag_skips_local_account(self):
        """--match-bare-runas must not match a known local account name (e.g. Administrator)."""
        hv = self._hv()
        hv.check_tier0_bare.return_value = (True, ["TIER0 Group Membership"])  # would match if called

        result = classify_task(
            row=self._row(runas="Administrator"), meta={}, runas="Administrator", rel_path="\\T", hv=hv,
            show_unsaved_creds=False, include_local=False, match_bare_runas=True,
        )

        assert result.task_type == "TASK"
        hv.check_tier0_bare.assert_not_called()

    def test_ldap_path_resolved_sid_is_tier0(self):
        """LDAP tier0_cache: a bare name proven a domain account (resolved SID) → TIER-0, no caveat."""
        result = classify_task(
            row=self._row(), meta={}, runas="svc_x", rel_path="\\T", hv=None,
            show_unsaved_creds=False, include_local=False,
            tier0_cache={"svc_x": (True, ["Domain Admins"])}, resolved_runas_sid=self.SID,
        )
        assert result.task_type == "TIER-0"
        assert result.reason.startswith("Tier-0 via LDAP")
        assert "matched by bare username" not in result.reason

    def test_ldap_path_match_bare_flag_annotated(self):
        """LDAP tier0_cache: opt-in flag matches a bare name with a verification annotation."""
        result = classify_task(
            row=self._row(), meta={}, runas="svc_x", rel_path="\\T", hv=None,
            show_unsaved_creds=False, include_local=False,
            tier0_cache={"svc_x": (True, ["Domain Admins"])}, match_bare_runas=True,
        )
        assert result.task_type == "TIER-0"
        assert "matched by bare username" in result.reason

    def test_ldap_path_bare_no_flag_no_sid_is_task(self):
        """LDAP tier0_cache: an unproven bare name without the flag stays TASK."""
        result = classify_task(
            row=self._row(), meta={}, runas="svc_x", rel_path="\\T", hv=None,
            show_unsaved_creds=False, include_local=False,
            tier0_cache={"svc_x": (True, ["Domain Admins"])},
        )
        assert result.task_type == "TASK"
