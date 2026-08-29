from unittest.mock import mock_open, patch

import pytest

from taskhound.config import build_parser, load_config, validate_args


@pytest.fixture
def mock_tomllib():
    with patch("taskhound.config.tomllib") as mock:
        yield mock


def test_load_output_config(mock_tomllib):
    toml_content = {
        "output": {
            "formats": ["plain", "json", "csv"],
            "dir": "./out",
            "no_backup": False,
            "no_summary": True,
            "debug": True,
        }
    }

    mock_tomllib.load.return_value = toml_content

    with patch("builtins.open", mock_open(read_data=b"mock data")), patch("os.path.exists", return_value=True):
        config = load_config()

    assert config["output"] == "plain,json,csv"
    assert config["output_dir"] == "./out"
    assert config["no_backup"] is False
    assert config["no_summary"] is True
    assert config["debug"] is True


class TestLoadConfigAuthentication:
    """Tests for authentication config loading."""

    def test_load_auth_username(self, mock_tomllib):
        """Test loading authentication username."""
        mock_tomllib.load.return_value = {
            "authentication": {"username": "admin"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["username"] == "admin"

    def test_load_auth_password(self, mock_tomllib):
        """Test loading authentication password."""
        mock_tomllib.load.return_value = {
            "authentication": {"password": "secret123"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["password"] == "secret123"

    def test_load_auth_domain(self, mock_tomllib):
        """Test loading authentication domain."""
        mock_tomllib.load.return_value = {
            "authentication": {"domain": "CORP.LOCAL"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["domain"] == "CORP.LOCAL"

    def test_load_auth_hashes(self, mock_tomllib):
        """Test loading NTLM hashes."""
        mock_tomllib.load.return_value = {
            "authentication": {"hashes": "aad3b435b51404eeaad3b435b51404ee:hash"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert "hash" in config["hashes"]

    def test_load_auth_kerberos(self, mock_tomllib):
        """Test loading Kerberos flag."""
        mock_tomllib.load.return_value = {
            "authentication": {"kerberos": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["kerberos"] is True


class TestLoadConfigTarget:
    """Tests for target config loading."""

    def test_load_dc_ip(self, mock_tomllib):
        """Test loading DC IP."""
        mock_tomllib.load.return_value = {
            "target": {"dc_ip": "192.168.1.1"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["dc_ip"] == "192.168.1.1"

    def test_load_timeout(self, mock_tomllib):
        """Test loading timeout."""
        mock_tomllib.load.return_value = {
            "target": {"timeout": 30}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["timeout"] == 30

    def test_load_target(self, mock_tomllib):
        """Test loading target."""
        mock_tomllib.load.return_value = {
            "target": {"target": "dc01.corp.local"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["target"] == "dc01.corp.local"

    def test_load_jitter(self, mock_tomllib):
        """Test loading jitter."""
        mock_tomllib.load.return_value = {
            "target": {"jitter": 5.0}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["jitter"] == 5.0


class TestLoadConfigScanning:
    """Tests for scanning config loading."""

    def test_load_offline(self, mock_tomllib):
        """Test loading offline mode."""
        mock_tomllib.load.return_value = {
            "scanning": {"offline": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["offline"] is True

    def test_load_include_local(self, mock_tomllib):
        """Test loading include_local flag."""
        mock_tomllib.load.return_value = {
            "scanning": {"include_local": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["include_local"] is True

    def test_load_opsec(self, mock_tomllib):
        """Test loading opsec mode."""
        mock_tomllib.load.return_value = {
            "scanning": {"opsec": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["opsec"] is True

    def test_load_bh_data(self, mock_tomllib):
        """Test loading BloodHound data path."""
        mock_tomllib.load.return_value = {
            "scanning": {"bh_data": "/path/to/bh.json"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["bh_data"] == "/path/to/bh.json"


class TestLoadConfigCache:
    """Tests for cache config loading."""

    def test_load_cache_ttl(self, mock_tomllib):
        """Test loading cache TTL."""
        mock_tomllib.load.return_value = {
            "cache": {"ttl": 24}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["cache_ttl"] == 24

    def test_load_cache_disabled(self, mock_tomllib):
        """Test loading cache disabled state."""
        mock_tomllib.load.return_value = {
            "cache": {"enabled": False}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["no_cache"] is True

    def test_load_cache_file(self, mock_tomllib):
        """Test loading cache file path."""
        mock_tomllib.load.return_value = {
            "cache": {"file": "/tmp/cache.db"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["cache_file"] == "/tmp/cache.db"


class TestLoadConfigBloodHound:
    """Tests for BloodHound config loading."""

    def test_load_bh_live(self, mock_tomllib):
        """Test loading BH live mode."""
        mock_tomllib.load.return_value = {
            "bloodhound": {"live": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["bh_live"] is True

    def test_load_bh_connector(self, mock_tomllib):
        """Test loading BH connector."""
        mock_tomllib.load.return_value = {
            "bloodhound": {"connector": "https://localhost:8080"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert "localhost" in config["bh_connector"]

    def test_load_bh_type_bhce(self, mock_tomllib):
        """Test loading BH type BHCE."""
        mock_tomllib.load.return_value = {
            "bloodhound": {"type": "bhce"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["bhce"] is True

    def test_load_bh_type_legacy(self, mock_tomllib):
        """Test loading BH type legacy."""
        mock_tomllib.load.return_value = {
            "bloodhound": {"type": "legacy"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["legacy"] is True


class TestLoadConfigLDAP:
    """Tests for LDAP config loading."""

    def test_load_ldap_disabled(self, mock_tomllib):
        """Test loading no_ldap flag."""
        mock_tomllib.load.return_value = {
            "ldap": {"no_ldap": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["no_ldap"] is True

    def test_load_ldap_user(self, mock_tomllib):
        """Test loading LDAP user."""
        mock_tomllib.load.return_value = {
            "ldap": {"user": "ldap_admin"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["ldap_user"] == "ldap_admin"


class TestLoadConfigNoFile:
    """Tests when no config file exists."""

    def test_no_config_file(self, mock_tomllib):
        """Test that empty dict is returned when no config file."""
        with patch("os.path.exists", return_value=False):
            config = load_config()
        assert config == {}

class TestBuildParser:
    """Tests for build_parser function."""

    def test_parser_creation(self):
        """Test that parser is created successfully."""
        parser = build_parser()
        assert parser is not None
        assert parser.prog == "taskhound"

    def test_parser_has_auth_options(self):
        """Test that parser has authentication arguments."""
        parser = build_parser()
        # Parse with offline mode (doesn't need username/password)
        args = parser.parse_args(["--offline", "/some/path"])
        assert args.offline == "/some/path"

    def test_parser_offline_mode(self):
        """Test offline mode argument."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path/to/xml"])
        assert args.offline == "/path/to/xml"

    def test_parser_bh_data(self):
        """Test bh-data argument."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "--bh-data", "/path/to/bh.json"])
        assert args.bh_data == "/path/to/bh.json"


class TestValidateArgs:
    """Tests for validate_args function."""

    # Note: validate_args() performs many checks and may exit, so we only test
    # cases that should pass validation cleanly

    @patch("taskhound.config.sys.exit")
    def test_validate_laps_without_dc_ip(self, mock_exit):
        """Test validation catches LAPS without DC IP."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "--laps", "-d", "corp.local"])
        validate_args(args)
        # Should have called sys.exit because LAPS needs --dc-ip
        mock_exit.assert_called()

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_no_validate_creds_flag(self, mock_exists, mock_isdir):
        """Test that --no-validate-creds disables credential validation."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--no-validate-creds",
        ])
        validate_args(args)
        # validate_creds should be False
        assert args.validate_creds is False

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_opsec_disables_credguard_detect(self, mock_exists, mock_isdir):
        """Test that --opsec disables credguard detection."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--opsec",
        ])
        validate_args(args)
        # credguard_detect should be set to False via --opsec
        assert args.credguard_detect is False

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_opsec_without_validate_creds_passes(self, mock_exists, mock_isdir):
        """Test that --opsec without --validate-creds passes validation."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--opsec",
        ])
        # Should not raise or exit
        validate_args(args)
        assert args.opsec is True

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_validate_creds_default_enabled(self, mock_exists, mock_isdir):
        """Test that credential validation is enabled by default."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
        ])
        validate_args(args)
        assert args.validate_creds is True

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_no_rpc_flag_exists(self, mock_exists, mock_isdir):
        """Test that --no-rpc flag is recognized."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--no-rpc",
        ])
        validate_args(args)
        assert args.no_rpc is True

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_opsec_sets_all_disable_flags(self, mock_exists, mock_isdir):
        """Test that --opsec sets all noise-reducing flags."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--opsec",
        ])
        validate_args(args)
        assert args.opsec is True
        assert args.no_ldap is True
        assert args.no_rpc is True
        assert args.loot is False
        assert args.credguard_detect is False
        assert args.validate_creds is False
        assert args.threads == 1  # OPSEC forces sequential scanning

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_no_rpc_disables_credguard_and_validate(self, mock_exists, mock_isdir):
        """Test that --no-rpc disables credguard and validation (they require RPC)."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--no-rpc",
        ])
        validate_args(args)
        # credguard_detect and validate_creds should be disabled
        assert args.credguard_detect is False
        assert args.validate_creds is False
        # But loot should still be enabled
        assert args.loot is True

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_no_ldap_alone_without_no_rpc(self, mock_exists, mock_isdir):
        """Test that --no-ldap alone doesn't set --no-rpc."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--no-ldap",
        ])
        validate_args(args)
        assert args.no_ldap is True
        assert args.no_rpc is False

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_no_rpc_alone_without_no_ldap(self, mock_exists, mock_isdir):
        """Test that --no-rpc alone doesn't set --no-ldap."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--no-rpc",
        ])
        validate_args(args)
        assert args.no_rpc is True
        assert args.no_ldap is False


class TestOutputFlags:
    """Tests for --output flag system."""

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_default_output_plain(self, mock_exists, mock_isdir):
        """Test that default output is plain."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path"])
        validate_args(args)
        assert args.output_formats == {"plain"}

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_output_single_format(self, mock_exists, mock_isdir):
        """Test single output format."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "-o", "json"])
        validate_args(args)
        assert args.output_formats == {"json"}

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_output_multiple_formats(self, mock_exists, mock_isdir):
        """Test multiple output formats (comma-separated)."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "-o", "plain,json,csv"])
        validate_args(args)
        assert args.output_formats == {"plain", "json", "csv"}

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_output_all_formats(self, mock_exists, mock_isdir):
        """Test all output formats."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "-o", "plain,json,csv,html"])
        validate_args(args)
        assert args.output_formats == {"plain", "json", "csv", "html"}

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_output_with_spaces_trimmed(self, mock_exists, mock_isdir):
        """Test that spaces in format list are trimmed."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "-o", "plain, json, csv"])
        validate_args(args)
        assert args.output_formats == {"plain", "json", "csv"}

    @patch("taskhound.config.sys.exit")
    def test_output_invalid_format(self, mock_exit):
        """Test that invalid output format causes exit."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "-o", "invalid"])
        validate_args(args)
        mock_exit.assert_called()

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_output_dir_default(self, mock_exists, mock_isdir):
        """Test default output directory."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path"])
        validate_args(args)
        assert args.output_dir == "./output"

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_output_dir_custom(self, mock_exists, mock_isdir):
        """Test custom output directory."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "--output-dir", "/custom/out"])
        validate_args(args)
        assert args.output_dir == "/custom/out"

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_backup_enabled_by_default(self, mock_exists, mock_isdir):
        """Test that backup is enabled by default."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path"])
        validate_args(args)
        assert args.backup is True

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_no_backup_flag(self, mock_exists, mock_isdir):
        """Test --no-backup disables backup."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "--no-backup"])
        validate_args(args)
        assert args.backup is False
