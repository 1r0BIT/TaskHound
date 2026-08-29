"""
Tests for taskhound/engine/online.py

Focus areas:
- _match_decrypted_password() credential matching logic
- process_target() parameter handling (mocked SMB)
"""

from dataclasses import dataclass

from taskhound.engine.online import _match_decrypted_password


# Mock credential class to simulate ScheduledTaskCredential
@dataclass
class MockCredential:
    """Mock credential object for testing."""
    username: str | None
    password: str
    task_name: str = "TestTask"
    blob_path: str = "/path/to/blob"
    target: str | None = None


class TestMatchDecryptedPassword:
    """Tests for _match_decrypted_password() function."""

    def test_returns_none_for_empty_creds(self):
        """Should return None when decrypted_creds is empty."""
        result = _match_decrypted_password("highpriv", [])
        assert result is None

    def test_returns_none_for_none_creds(self):
        """Should return None when decrypted_creds is None."""
        result = _match_decrypted_password("highpriv", None)
        assert result is None

    def test_returns_none_for_empty_runas(self):
        """Should return None when runas is empty."""
        creds = [MockCredential(username="highpriv", password="secret")]
        result = _match_decrypted_password("", creds)
        assert result is None

    def test_returns_none_for_none_runas(self):
        """Should return None when runas is None."""
        creds = [MockCredential(username="highpriv", password="secret")]
        result = _match_decrypted_password(None, creds)
        assert result is None

    def test_exact_match_simple_username(self):
        """Should match exact simple username."""
        creds = [MockCredential(username="highpriv", password="P@ssw0rd")]
        result = _match_decrypted_password("highpriv", creds)
        assert result == "P@ssw0rd"

    def test_case_insensitive_match(self):
        """Should match case-insensitively."""
        creds = [MockCredential(username="HighPriv", password="P@ssw0rd")]
        result = _match_decrypted_password("highpriv", creds)
        assert result == "P@ssw0rd"

    def test_domain_user_exact_match(self):
        """Should match domain\\user format exactly."""
        creds = [MockCredential(username="DOMAIN\\highpriv", password="P@ssw0rd")]
        result = _match_decrypted_password("DOMAIN\\highpriv", creds)
        assert result == "P@ssw0rd"

    def test_cred_has_domain_runas_doesnt(self):
        """Should match when cred has domain but runas doesn't."""
        creds = [MockCredential(username="DOMAIN\\highpriv", password="P@ssw0rd")]
        result = _match_decrypted_password("highpriv", creds)
        assert result == "P@ssw0rd"

    def test_runas_has_domain_cred_doesnt(self):
        """Should match when runas has domain but cred doesn't."""
        creds = [MockCredential(username="highpriv", password="P@ssw0rd")]
        result = _match_decrypted_password("DOMAIN\\highpriv", creds)
        assert result == "P@ssw0rd"

    def test_no_match_different_users(self):
        """Should not match different usernames."""
        creds = [MockCredential(username="otheruser", password="P@ssw0rd")]
        result = _match_decrypted_password("highpriv", creds)
        assert result is None

    def test_skip_cred_with_none_username(self):
        """Should skip credentials with None username."""
        creds = [
            MockCredential(username=None, password="ignored"),
            MockCredential(username="highpriv", password="P@ssw0rd"),
        ]
        result = _match_decrypted_password("highpriv", creds)
        assert result == "P@ssw0rd"

    def test_first_match_wins(self):
        """Should return first matching credential's password."""
        creds = [
            MockCredential(username="highpriv", password="FirstPassword"),
            MockCredential(username="highpriv", password="SecondPassword"),
        ]
        result = _match_decrypted_password("highpriv", creds)
        assert result == "FirstPassword"

    def test_multiple_creds_finds_correct_one(self):
        """Should find correct match among multiple credentials."""
        creds = [
            MockCredential(username="admin", password="AdminPass"),
            MockCredential(username="highpriv", password="HighPrivPass"),
            MockCredential(username="lowpriv", password="LowPrivPass"),
        ]
        result = _match_decrypted_password("highpriv", creds)
        assert result == "HighPrivPass"


class TestMatchDecryptedPasswordWithSID:
    """Tests for _match_decrypted_password() with SID resolution."""

    def test_sid_without_resolved_runas_returns_none(self):
        """Should return None when runas is SID and no resolved_runas provided."""
        creds = [MockCredential(username="highpriv", password="P@ssw0rd")]
        # Raw SID with no resolution
        result = _match_decrypted_password(
            "S-1-5-21-3211413907-14631080-1147255650-1102",
            creds,
            resolved_runas=None
        )
        assert result is None

    def test_sid_with_resolved_runas_matches(self):
        """Should match when SID is resolved via resolved_runas."""
        creds = [MockCredential(username="highpriv", password="P@ssw0rd")]
        result = _match_decrypted_password(
            "S-1-5-21-3211413907-14631080-1147255650-1102",
            creds,
            resolved_runas="highpriv"
        )
        assert result == "P@ssw0rd"

    def test_sid_with_domain_resolved_runas_matches(self):
        """Should match when resolved_runas includes domain."""
        creds = [MockCredential(username="DOMAIN\\highpriv", password="P@ssw0rd")]
        result = _match_decrypted_password(
            "S-1-5-21-3211413907-14631080-1147255650-1102",
            creds,
            resolved_runas="DOMAIN\\highpriv"
        )
        assert result == "P@ssw0rd"

    def test_sid_resolved_matches_cred_without_domain(self):
        """Should match resolved domain\\user against cred without domain."""
        creds = [MockCredential(username="highpriv", password="P@ssw0rd")]
        result = _match_decrypted_password(
            "S-1-5-21-3211413907-14631080-1147255650-1102",
            creds,
            resolved_runas="DOMAIN\\highpriv"
        )
        assert result == "P@ssw0rd"

    def test_resolved_runas_takes_precedence(self):
        """resolved_runas should be tried first for matching."""
        creds = [
            MockCredential(username="resolveduser", password="ResolvedPass"),
            MockCredential(username="rawuser", password="RawPass"),
        ]
        # Non-SID runas with resolved_runas should try resolved first
        result = _match_decrypted_password(
            "rawuser",
            creds,
            resolved_runas="resolveduser"
        )
        assert result == "ResolvedPass"

    def test_non_sid_runas_still_tried_if_resolved_fails(self):
        """Should fall back to runas if resolved_runas doesn't match."""
        creds = [MockCredential(username="rawuser", password="RawPass")]
        result = _match_decrypted_password(
            "rawuser",
            creds,
            resolved_runas="nomatch"
        )
        assert result == "RawPass"


class TestMatchDecryptedPasswordEdgeCases:
    """Edge case tests for _match_decrypted_password()."""

    def test_empty_username_in_cred(self):
        """Should skip credentials with empty username string."""
        creds = [
            MockCredential(username="", password="ignored"),
            MockCredential(username="highpriv", password="P@ssw0rd"),
        ]
        result = _match_decrypted_password("highpriv", creds)
        assert result == "P@ssw0rd"

    def test_backslash_only_domain(self):
        """Should handle edge case of backslash at start."""
        creds = [MockCredential(username="\\highpriv", password="P@ssw0rd")]
        result = _match_decrypted_password("highpriv", creds)
        assert result == "P@ssw0rd"

    def test_multiple_backslashes(self):
        """Should handle multiple backslashes (split on last)."""
        # Domain\subdomain\user - split gets 'user' part
        creds = [MockCredential(username="DOMAIN\\SUB\\user", password="P@ssw0rd")]
        result = _match_decrypted_password("user", creds)
        assert result == "P@ssw0rd"

    def test_special_characters_in_username(self):
        """Should match usernames with special characters."""
        creds = [MockCredential(username="high-priv_user$", password="P@ssw0rd")]
        result = _match_decrypted_password("high-priv_user$", creds)
        assert result == "P@ssw0rd"

    def test_unicode_username(self):
        """Should handle unicode characters in usernames."""
        creds = [MockCredential(username="用户名", password="P@ssw0rd")]
        result = _match_decrypted_password("用户名", creds)
        assert result == "P@ssw0rd"

    def test_whitespace_in_username(self):
        """Should match usernames with whitespace."""
        creds = [MockCredential(username="John Doe", password="P@ssw0rd")]
        result = _match_decrypted_password("John Doe", creds)
        assert result == "P@ssw0rd"


class TestMatchDecryptedPasswordRealWorldScenarios:
    """Real-world scenario tests based on actual TaskHound usage."""

    def test_badsuccessor_domain_format(self):
        """Test format seen in badsuccessor.lab environment."""
        creds = [MockCredential(username="badsuccessor\\highpriv", password="P@ssw0rd1339.")]
        result = _match_decrypted_password("BADSUCCESSOR\\highpriv", creds)
        assert result == "P@ssw0rd1339."

    def test_simple_highpriv_match(self):
        """Test simple highpriv match without domain."""
        creds = [MockCredential(username="highpriv", password="P@ssw0rd1339.")]
        result = _match_decrypted_password("highpriv", creds)
        assert result == "P@ssw0rd1339."

    def test_administrator_match(self):
        """Test Administrator account match."""
        creds = [MockCredential(username="Administrator", password="P@ssw0rd1337.")]
        result = _match_decrypted_password("Administrator", creds)
        assert result == "P@ssw0rd1337."

    def test_sid_to_highpriv_resolution(self):
        """Test SID-1102 resolving to highpriv."""
        creds = [MockCredential(username="highpriv", password="P@ssw0rd1339.")]
        result = _match_decrypted_password(
            "S-1-5-21-3211413907-14631080-1147255650-1102",
            creds,
            resolved_runas="highpriv"
        )
        assert result == "P@ssw0rd1339."

    def test_lowpriv_domain_match(self):
        """Test lowpriv user with domain prefix."""
        creds = [MockCredential(username="BADSUCCESSOR\\lowpriv", password="P@ssw0rd1337.")]
        result = _match_decrypted_password("BADSUCCESSOR\\lowpriv", creds)
        assert result == "P@ssw0rd1337."

    def test_multiple_accounts_correct_selection(self):
        """Test selecting correct account from multiple credentials."""
        creds = [
            MockCredential(username="BADSUCCESSOR\\lowpriv", password="LowPrivPass"),
            MockCredential(username="BADSUCCESSOR\\highpriv", password="HighPrivPass"),
            MockCredential(username="Administrator", password="AdminPass"),
        ]

        assert _match_decrypted_password("lowpriv", creds) == "LowPrivPass"
        assert _match_decrypted_password("highpriv", creds) == "HighPrivPass"
        assert _match_decrypted_password("Administrator", creds) == "AdminPass"
