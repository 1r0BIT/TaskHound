"""
Test suite for BloodHoundConfig configuration model.

Tests cover:
- BloodHoundConfig initialization
- from_args_and_config class method
- has_credentials method
- is_bhce and is_legacy methods
"""

from argparse import Namespace

import pytest

from taskhound.config_model import BloodHoundConfig

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_args_minimal():
    """Create minimal mock args with required fields"""
    args = Namespace(
        bh_opengraph=False,
        bh_no_upload=False,
        bh_connector=None,
        bh_user=None,
        bh_password=None,
        bh_api_key=None,
        bh_api_key_id=None,
        bh_live=False,
        bh_save=None,
        bhce=False,
        legacy=False,
    )
    return args


@pytest.fixture
def mock_args_with_creds():
    """Create mock args with username/password credentials"""
    args = Namespace(
        bh_opengraph=True,
        bh_no_upload=False,
        bh_connector="http://localhost:8080",
        bh_user="admin",
        bh_password="password123",
        bh_api_key=None,
        bh_api_key_id=None,
        bh_live=True,
        bh_save="./data.json",
        bhce=True,
        legacy=False,
    )
    return args


@pytest.fixture
def mock_args_with_api_key():
    """Create mock args with API key credentials"""
    args = Namespace(
        bh_opengraph=True,
        bh_no_upload=True,
        bh_connector="http://localhost:8080",
        bh_user=None,
        bh_password=None,
        bh_api_key="api_key_123",
        bh_api_key_id="key_id_456",
        bh_live=False,
        bh_save=None,
        bhce=True,
        legacy=False,
    )
    return args


# ============================================================================
# Unit Tests: BloodHoundConfig Initialization
# ============================================================================


class TestBloodHoundConfigInit:
    """Tests for BloodHoundConfig initialization with defaults"""

    def test_default_values(self):
        """Should have sensible defaults"""
        config = BloodHoundConfig()

        assert config.bh_opengraph is False
        assert config.bh_no_upload is False
        assert config.bh_connector is None
        assert config.bh_username is None
        assert config.bh_password is None
        assert config.bh_api_key is None
        assert config.bh_api_key_id is None
        assert config.bh_type is None
        assert config.bh_live is False
        assert config.bh_save is None

    def test_custom_initialization(self):
        """Should accept custom values"""
        config = BloodHoundConfig(
            bh_opengraph=True,
            bh_connector="http://localhost:8080",
            bh_type="bhce"
        )

        assert config.bh_opengraph is True
        assert config.bh_connector == "http://localhost:8080"
        assert config.bh_type == "bhce"


# ============================================================================
# Unit Tests: from_args_and_config
# ============================================================================


class TestFromArgsAndConfig:
    """Tests for from_args_and_config class method"""

    def test_minimal_args(self, mock_args_minimal):
        """Should create config from minimal args"""
        config = BloodHoundConfig.from_args_and_config(mock_args_minimal)

        assert config.bh_opengraph is False
        assert config.bh_type == "bhce"  # Default when neither bhce nor legacy set

    def test_with_credentials(self, mock_args_with_creds):
        """Should create config with credentials"""
        config = BloodHoundConfig.from_args_and_config(mock_args_with_creds)

        assert config.bh_opengraph is True
        assert config.bh_connector == "http://localhost:8080"
        assert config.bh_username == "admin"
        assert config.bh_password == "password123"
        assert config.bh_type == "bhce"

    def test_with_api_key(self, mock_args_with_api_key):
        """Should create config with API key credentials"""
        config = BloodHoundConfig.from_args_and_config(mock_args_with_api_key)

        assert config.bh_api_key == "api_key_123"
        assert config.bh_api_key_id == "key_id_456"

    def test_bhce_flag_sets_type(self, mock_args_minimal):
        """bhce flag should set bh_type to 'bhce'"""
        mock_args_minimal.bhce = True
        config = BloodHoundConfig.from_args_and_config(mock_args_minimal)

        assert config.bh_type == "bhce"

    def test_legacy_flag_sets_type(self, mock_args_minimal):
        """legacy flag should set bh_type to 'legacy'"""
        mock_args_minimal.legacy = True
        config = BloodHoundConfig.from_args_and_config(mock_args_minimal)

        assert config.bh_type == "legacy"

    def test_default_type_is_bhce(self, mock_args_minimal):
        """Default type should be 'bhce' when neither flag is set"""
        config = BloodHoundConfig.from_args_and_config(mock_args_minimal)

        assert config.bh_type == "bhce"

    def test_live_settings(self, mock_args_with_creds):
        """Should copy live mode settings"""
        config = BloodHoundConfig.from_args_and_config(mock_args_with_creds)

        assert config.bh_live is True
        assert config.bh_save == "./data.json"


# ============================================================================
# Unit Tests: has_credentials
# ============================================================================


class TestHasCredentials:
    """Tests for has_credentials method"""

    def test_no_credentials_returns_false(self):
        """Should return False when no credentials"""
        config = BloodHoundConfig()

        assert config.has_credentials() is False

    def test_username_only_returns_false(self):
        """Should return False with only username"""
        config = BloodHoundConfig(bh_username="admin")

        assert config.has_credentials() is False

    def test_password_only_returns_false(self):
        """Should return False with only password"""
        config = BloodHoundConfig(bh_password="secret")

        assert config.has_credentials() is False

    def test_username_and_password_returns_true(self):
        """Should return True with username and password"""
        config = BloodHoundConfig(bh_username="admin", bh_password="secret")

        assert config.has_credentials() is True

    def test_api_key_only_returns_false(self):
        """Should return False with only api_key"""
        config = BloodHoundConfig(bh_api_key="key123")

        assert config.has_credentials() is False

    def test_api_key_id_only_returns_false(self):
        """Should return False with only api_key_id"""
        config = BloodHoundConfig(bh_api_key_id="id456")

        assert config.has_credentials() is False

    def test_api_key_and_id_returns_true(self):
        """Should return True with both api_key and api_key_id"""
        config = BloodHoundConfig(bh_api_key="key123", bh_api_key_id="id456")

        assert config.has_credentials() is True

    def test_api_key_takes_priority(self):
        """API key + ID pair should work even without username/password"""
        config = BloodHoundConfig(
            bh_api_key="key123",
            bh_api_key_id="id456",
            bh_username=None,
            bh_password=None
        )

        assert config.has_credentials() is True


# ============================================================================
# Unit Tests: is_bhce and is_legacy
# ============================================================================


class TestTypeChecks:
    """Tests for is_bhce and is_legacy methods"""

    def test_is_bhce_true(self):
        """Should return True for bhce type"""
        config = BloodHoundConfig(bh_type="bhce")

        assert config.is_bhce() is True
        assert config.is_legacy() is False

    def test_is_legacy_true(self):
        """Should return True for legacy type"""
        config = BloodHoundConfig(bh_type="legacy")

        assert config.is_legacy() is True
        assert config.is_bhce() is False

    def test_no_type_set(self):
        """Should return False for both when type is None"""
        config = BloodHoundConfig(bh_type=None)

        assert config.is_bhce() is False
        assert config.is_legacy() is False

    def test_invalid_type(self):
        """Should return False for invalid type"""
        config = BloodHoundConfig(bh_type="invalid")

        assert config.is_bhce() is False
        assert config.is_legacy() is False
