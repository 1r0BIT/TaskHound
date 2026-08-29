# Tests for AuthContext dataclass.


from taskhound.auth import AuthContext


class TestAuthContext:
    """Test AuthContext dataclass functionality."""

    def test_basic_creation(self):
        """Test basic AuthContext creation with minimal params."""
        auth = AuthContext(username="admin", domain="CORP")
        assert auth.username == "admin"
        assert auth.domain == "CORP"
        assert auth.password is None
        assert auth.hashes is None
        assert auth.kerberos is False

    def test_full_creation(self):
        """Test AuthContext creation with all params."""
        auth = AuthContext(
            username="admin",
            password="secret",
            domain="CORP",
            hashes=None,
            kerberos=False,
            dc_ip="192.168.1.1",
            timeout=30,
            ldap_domain="LDAP.CORP",
            ldap_user="ldap_admin",
            ldap_password="ldap_secret",
            ldap_hashes=None,
        )
        assert auth.username == "admin"
        assert auth.password == "secret"
        assert auth.domain == "CORP"
        assert auth.dc_ip == "192.168.1.1"
        assert auth.timeout == 30
        assert auth.ldap_domain == "LDAP.CORP"
        assert auth.ldap_user == "ldap_admin"
        assert auth.ldap_password == "ldap_secret"

    def test_repr_hides_credentials(self):
        """Test repr doesn't expose actual credentials."""
        auth = AuthContext(
            username="admin",
            password="supersecret",
            hashes="aad3b435b51404ee:8846f7eaee8fb117",
            domain="CORP",
        )
        repr_str = repr(auth)
        assert "supersecret" not in repr_str
        assert "8846f7eaee8fb117" not in repr_str
        assert "has_password=True" in repr_str
        assert "has_hashes=True" in repr_str
        assert "admin" in repr_str
        assert "CORP" in repr_str

    def test_default_timeout(self):
        """Test default timeout value."""
        auth = AuthContext()
        assert auth.timeout == 60
