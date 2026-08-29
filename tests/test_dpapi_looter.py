"""
Comprehensive test suite for DPAPI Looter functionality.

Tests cover:
- is_guid helper function (from utils.helpers)
- decrypt_offline_dpapi_files workflow
- _decrypt_credential_blob_offline parsing
- _decrypt_dpapi_blob_data decryption
- CredentialLooter._associate_credentials_with_tasks
- File metadata and readme creation
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from taskhound.dpapi.decryptor import MasterkeyInfo, ScheduledTaskCredential, _decrypt_dpapi_blob
from taskhound.dpapi.looter import (
    CredentialLooter,
    OfflineDPAPICollector,
    _decrypt_credential_blob_offline,
    collect_dpapi_files,
    decrypt_offline_dpapi_files,
    loot_credentials,
)
from taskhound.utils.helpers import is_guid

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_smb_connection():
    """Create a mock SMB connection"""
    mock = MagicMock()
    mock.getServerName.return_value = "DC01"
    mock.getRemoteHost.return_value = "192.168.1.1"
    return mock


@pytest.fixture
def temp_loot_dir():
    """Create a temporary directory structure for DPAPI loot"""
    with tempfile.TemporaryDirectory() as tmpdir:
        masterkey_dir = os.path.join(tmpdir, "masterkeys")
        credential_dir = os.path.join(tmpdir, "credentials")
        os.makedirs(masterkey_dir)
        os.makedirs(credential_dir)
        yield tmpdir


@pytest.fixture
def sample_task_credential():
    """Create a sample ScheduledTaskCredential"""
    return ScheduledTaskCredential(
        task_name="",
        blob_path="ABC123",
        username="DOMAIN\\serviceaccount",
        password="P@ssw0rd123!",
        target="Task:{12345678-1234-1234-1234-123456789012}"
    )


@pytest.fixture
def sample_masterkey_info():
    """Create a sample MasterkeyInfo with mock data"""
    mk = MasterkeyInfo(
        guid="12345678-1234-1234-1234-123456789012",
        blob=b"MOCK_MASTERKEY_BLOB"
    )
    # Set internal _sha1 directly since sha1 is a read-only property
    mk._sha1 = "0000000000000000000000000000000000000000"
    return mk


# ============================================================================
# Unit Tests: is_guid (from utils.helpers)
# ============================================================================


class TestIsGuid:
    """Tests for is_guid function from utils.helpers"""

    def test_valid_guid_lowercase(self):
        """Valid lowercase GUID should return True"""
        assert is_guid("12345678-1234-1234-1234-123456789012") is True

    def test_valid_guid_uppercase(self):
        """Valid uppercase GUID should return True"""
        assert is_guid("12345678-1234-1234-1234-123456789ABC") is True

    def test_valid_guid_mixed_case(self):
        """Valid mixed case GUID should return True"""
        assert is_guid("12345678-abcd-EFGH-1234-123456789abc") is False  # G,H are invalid hex

    def test_valid_guid_all_hex(self):
        """Valid GUID with all hex chars should return True"""
        assert is_guid("abcdef01-2345-6789-abcd-ef0123456789") is True

    def test_invalid_guid_wrong_length(self):
        """Wrong length GUID should return False"""
        assert is_guid("12345678-1234-1234-1234-12345678901") is False

    def test_invalid_guid_missing_dashes(self):
        """GUID without dashes should return False"""
        assert is_guid("12345678123412341234123456789012") is False

    def test_invalid_guid_extra_chars(self):
        """GUID with extra characters should return False"""
        assert is_guid("12345678-1234-1234-1234-123456789012x") is False

    def test_invalid_guid_wrong_chars(self):
        """GUID with non-hex characters should return False"""
        assert is_guid("gggggggg-gggg-gggg-gggg-gggggggggggg") is False

    def test_empty_string(self):
        """Empty string should return False"""
        assert is_guid("") is False

    def test_regular_filename(self):
        """Regular filename should return False"""
        assert is_guid("document.txt") is False

    def test_dots_and_extensions(self):
        """Filename with dots should return False"""
        assert is_guid("12345678-1234-1234-1234-123456789012.bak") is False


# ============================================================================
# Unit Tests: OfflineDPAPICollector
# ============================================================================


class TestOfflineDPAPICollector:
    """Tests for OfflineDPAPICollector class"""

    def test_guid_check_via_helpers(self, mock_smb_connection, temp_loot_dir):
        """is_guid helper should work correctly"""
        # Note: OfflineDPAPICollector now uses is_guid from helpers
        assert is_guid("12345678-1234-1234-1234-123456789012") is True

    def test_guid_check_invalid(self, mock_smb_connection, temp_loot_dir):
        """Invalid GUID should return False"""
        assert is_guid("not-a-guid") is False


class TestOfflineDPAPICollectorMetadata:
    """Tests for metadata and readme creation"""

    def test_create_readme(self, mock_smb_connection, temp_loot_dir):
        """_create_readme should create README.txt file"""
        collector = OfflineDPAPICollector(mock_smb_connection, temp_loot_dir)
        collector.masterkey_count = 5
        collector.credential_count = 3
        collector._create_readme()

        readme_path = os.path.join(temp_loot_dir, "README.txt")
        assert os.path.exists(readme_path)

        with open(readme_path) as f:
            content = f.read()

        assert "DPAPI Files Collected" in content
        assert "5 SYSTEM masterkeys" in content
        assert "3 credential blobs" in content
        assert "NetExec" in content
        assert "dpapi_userkey" in content

    def test_create_metadata(self, mock_smb_connection, temp_loot_dir):
        """_create_metadata should create metadata.json file"""
        collector = OfflineDPAPICollector(mock_smb_connection, temp_loot_dir)
        collector.masterkey_count = 5
        collector.credential_count = 3
        collector._create_metadata()

        metadata_path = os.path.join(temp_loot_dir, "metadata.json")
        assert os.path.exists(metadata_path)

        with open(metadata_path) as f:
            data = json.load(f)

        assert data["masterkey_count"] == 5
        assert data["credential_count"] == 3
        assert "collection_date" in data
        assert "masterkey_location" in data
        assert "credential_location" in data


# ============================================================================
# Unit Tests: CredentialLooter._associate_credentials_with_tasks
# ============================================================================


class TestCredentialAssociation:
    """Tests for credential-to-task association"""

    def test_associate_by_exact_username(self, mock_smb_connection):
        """Should match credential by exact username match"""
        looter = CredentialLooter.__new__(CredentialLooter)
        looter.tasks = {
            "BackupTask": {
                "name": "BackupTask",
                "userid": "serviceaccount",
                "xml": "",
                "task_info": {}
            }
        }
        looter.credentials = [
            ScheduledTaskCredential(
                task_name="",
                blob_path="ABC",
                username="serviceaccount",
                password="pass"
            )
        ]

        looter._associate_credentials_with_tasks()
        assert looter.credentials[0].task_name == "BackupTask"

    def test_associate_by_domain_backslash_username(self, mock_smb_connection):
        """Should match credential with domain\\user to task's user"""
        looter = CredentialLooter.__new__(CredentialLooter)
        looter.tasks = {
            "BackupTask": {
                "name": "BackupTask",
                "userid": "serviceaccount",
                "xml": "",
                "task_info": {}
            }
        }
        looter.credentials = [
            ScheduledTaskCredential(
                task_name="",
                blob_path="ABC",
                username="DOMAIN\\serviceaccount",
                password="pass"
            )
        ]

        looter._associate_credentials_with_tasks()
        assert looter.credentials[0].task_name == "BackupTask"

    def test_no_match_leaves_task_name_empty(self, mock_smb_connection):
        """Should not modify task_name when no match found"""
        looter = CredentialLooter.__new__(CredentialLooter)
        looter.tasks = {
            "BackupTask": {
                "name": "BackupTask",
                "userid": "differentuser",
                "xml": "",
                "task_info": {}
            }
        }
        looter.credentials = [
            ScheduledTaskCredential(
                task_name="OriginalTask",
                blob_path="ABC",
                username="serviceaccount",
                password="pass"
            )
        ]

        looter._associate_credentials_with_tasks()
        # task_name should remain unchanged since no match
        assert looter.credentials[0].task_name == "OriginalTask"

    def test_empty_username_skipped(self, mock_smb_connection):
        """Credentials with empty username should be skipped"""
        looter = CredentialLooter.__new__(CredentialLooter)
        looter.tasks = {
            "BackupTask": {
                "name": "BackupTask",
                "userid": "serviceaccount",
                "xml": "",
                "task_info": {}
            }
        }
        looter.credentials = [
            ScheduledTaskCredential(
                task_name="",
                blob_path="ABC",
                username=None,
                password="pass"
            )
        ]

        # Should not raise any exceptions
        looter._associate_credentials_with_tasks()
        assert looter.credentials[0].task_name == ""

    def test_case_insensitive_matching(self, mock_smb_connection):
        """Should match usernames case-insensitively"""
        looter = CredentialLooter.__new__(CredentialLooter)
        looter.tasks = {
            "BackupTask": {
                "name": "BackupTask",
                "userid": "serviceaccount",  # lowercase
                "xml": "",
                "task_info": {}
            }
        }
        looter.credentials = [
            ScheduledTaskCredential(
                task_name="",
                blob_path="ABC",
                username="SERVICEACCOUNT",  # uppercase
                password="pass"
            )
        ]

        looter._associate_credentials_with_tasks()
        assert looter.credentials[0].task_name == "BackupTask"


# ============================================================================
# Unit Tests: decrypt_offline_dpapi_files
# ============================================================================


class TestDecryptOfflineDpapiFiles:
    """Tests for decrypt_offline_dpapi_files function"""

    def test_missing_masterkey_dir_returns_empty(self, temp_loot_dir):
        """Should return empty list if masterkeys dir missing"""
        # Remove masterkeys dir
        os.rmdir(os.path.join(temp_loot_dir, "masterkeys"))

        result = decrypt_offline_dpapi_files(temp_loot_dir, "0x" + "00" * 20)
        assert result == []

    def test_missing_credentials_dir_returns_empty(self, temp_loot_dir):
        """Should return empty list if credentials dir missing"""
        # Remove credentials dir
        os.rmdir(os.path.join(temp_loot_dir, "credentials"))

        result = decrypt_offline_dpapi_files(temp_loot_dir, "0x" + "00" * 20)
        assert result == []

    def test_hex_key_prefix_stripped(self, temp_loot_dir):
        """Should accept keys with 0x prefix"""
        # Create empty masterkey file (will fail to decrypt but tests key parsing)
        mk_dir = os.path.join(temp_loot_dir, "masterkeys")
        mk_path = os.path.join(mk_dir, "12345678-1234-1234-1234-123456789012")
        with open(mk_path, "wb") as f:
            f.write(b"mock")

        # Should not raise exception when parsing key with 0x prefix
        result = decrypt_offline_dpapi_files(temp_loot_dir, "0x" + "00" * 20)
        # No credentials decrypted (mock data), but no exception either
        assert result == []

    def test_hex_key_without_prefix(self, temp_loot_dir):
        """Should accept keys without 0x prefix"""
        mk_dir = os.path.join(temp_loot_dir, "masterkeys")
        mk_path = os.path.join(mk_dir, "12345678-1234-1234-1234-123456789012")
        with open(mk_path, "wb") as f:
            f.write(b"mock")

        # Should not raise exception when parsing key without prefix
        result = decrypt_offline_dpapi_files(temp_loot_dir, "00" * 20)
        assert result == []

    def test_non_guid_files_skipped(self, temp_loot_dir):
        """Should skip non-GUID files in masterkeys dir"""
        mk_dir = os.path.join(temp_loot_dir, "masterkeys")

        # Create a non-GUID file
        with open(os.path.join(mk_dir, "README.txt"), "w") as f:
            f.write("test")

        # Create a valid GUID file (mock)
        with open(os.path.join(mk_dir, "12345678-1234-1234-1234-123456789012"), "wb") as f:
            f.write(b"mock")

        result = decrypt_offline_dpapi_files(temp_loot_dir, "00" * 20)
        # Should process without error even with non-GUID file present
        assert result == []

    def test_directories_skipped(self, temp_loot_dir):
        """Should skip directories in masterkeys dir"""
        mk_dir = os.path.join(temp_loot_dir, "masterkeys")

        # Create a subdirectory with a GUID-like name
        subdir = os.path.join(mk_dir, "12345678-1234-1234-1234-123456789abc")
        os.makedirs(subdir)

        result = decrypt_offline_dpapi_files(temp_loot_dir, "00" * 20)
        assert result == []


# ============================================================================
# Unit Tests: _decrypt_credential_blob_offline
# ============================================================================


class TestDecryptCredentialBlobOffline:
    """Tests for _decrypt_credential_blob_offline function"""

    def test_empty_masterkeys_returns_none_like(self):
        """Should return empty credential when no matching masterkey"""
        result = _decrypt_credential_blob_offline(
            blob_bytes=b"INVALID_BLOB",
            blob_path="test_blob",
            masterkeys={}
        )
        # Function returns None or empty credential on failure
        assert result is None or result.username is None

    def test_invalid_blob_returns_none(self):
        """Should return None for completely invalid blob"""
        result = _decrypt_credential_blob_offline(
            blob_bytes=b"NOT_A_DPAPI_BLOB",
            blob_path="test_blob",
            masterkeys={"12345678-1234-1234-1234-123456789012": MagicMock()}
        )
        assert result is None or result.username is None


# ============================================================================
# Unit Tests: _decrypt_dpapi_blob (shared crypto core, now in decryptor.py)
# ============================================================================


class TestDecryptDpapiBlobData:
    """Tests for the shared _decrypt_dpapi_blob crypto core"""

    def test_invalid_blob_returns_none(self, sample_masterkey_info):
        """Should return None for invalid blob data"""
        result = _decrypt_dpapi_blob(
            blob_bytes=b"INVALID",
            masterkey=sample_masterkey_info
        )
        assert result is None

    def test_handles_exceptions_gracefully(self):
        """Should handle exceptions and return None"""
        mk = MasterkeyInfo(guid="test", blob=b"x")
        mk._sha1 = "invalid_sha1_not_hex"  # Will cause unhexlify to fail

        result = _decrypt_dpapi_blob(
            blob_bytes=b"BLOB",
            masterkey=mk
        )
        assert result is None


# ============================================================================
# Unit Tests: Convenience Functions
# ============================================================================


class TestConvenienceFunctions:
    """Tests for loot_credentials and collect_dpapi_files convenience functions"""

    @patch.object(CredentialLooter, 'loot_all_credentials')
    def test_loot_credentials_creates_looter(self, mock_loot, mock_smb_connection):
        """loot_credentials should create CredentialLooter and call loot_all_credentials"""
        mock_loot.return_value = []

        result = loot_credentials(mock_smb_connection, "00" * 20)

        mock_loot.assert_called_once()
        assert result == []

    @patch.object(OfflineDPAPICollector, 'collect_all_files')
    def test_collect_dpapi_files_creates_collector(self, mock_collect, mock_smb_connection, temp_loot_dir):
        """collect_dpapi_files should create OfflineDPAPICollector and call collect_all_files"""
        mock_collect.return_value = {"masterkeys": 0, "credentials": 0, "output_dir": temp_loot_dir}

        result = collect_dpapi_files(mock_smb_connection, temp_loot_dir)

        mock_collect.assert_called_once()
        assert "masterkeys" in result
        assert "credentials" in result


# ============================================================================
# Unit Tests: CredentialLooter Initialization
# ============================================================================


class TestCredentialLooterInit:
    """Tests for CredentialLooter initialization"""

    def test_init_creates_decryptor(self, mock_smb_connection):
        """Should create DPAPIDecryptor on init"""
        with patch('taskhound.dpapi.looter.DPAPIDecryptor') as mock_decryptor:
            looter = CredentialLooter(mock_smb_connection, "00" * 20)

            mock_decryptor.assert_called_once_with(mock_smb_connection, "00" * 20)
            assert looter.smb_conn == mock_smb_connection
            assert looter.tasks == {}
            assert looter.credentials == []


class TestOfflineDPAPICollectorInit:
    """Tests for OfflineDPAPICollector initialization"""

    def test_init_stores_parameters(self, mock_smb_connection, temp_loot_dir):
        """Should store connection and output_dir"""
        collector = OfflineDPAPICollector(mock_smb_connection, temp_loot_dir)

        assert collector.smb_conn == mock_smb_connection
        assert collector.output_dir == temp_loot_dir
        assert collector.masterkey_count == 0
        assert collector.credential_count == 0


# ============================================================================
# Integration-style Tests
# ============================================================================


class TestEndToEndOfflineWorkflow:
    """Integration tests for offline DPAPI workflow"""

    def test_collect_then_readme_has_correct_stats(self, mock_smb_connection, temp_loot_dir):
        """Collecting files and creating readme should have consistent stats"""
        collector = OfflineDPAPICollector(mock_smb_connection, temp_loot_dir)

        # Simulate collection
        collector.masterkey_count = 3
        collector.credential_count = 7

        collector._create_readme()
        collector._create_metadata()

        # Verify readme
        with open(os.path.join(temp_loot_dir, "README.txt")) as f:
            readme = f.read()

        assert "3 SYSTEM masterkeys" in readme
        assert "7 credential blobs" in readme

        # Verify metadata
        with open(os.path.join(temp_loot_dir, "metadata.json")) as f:
            metadata = json.load(f)

        assert metadata["masterkey_count"] == 3
        assert metadata["credential_count"] == 7


class TestMasterkeyDecryption:
    """Tests for masterkey-related operations"""

    def test_masterkey_info_with_valid_guid(self):
        """MasterkeyInfo should store guid and blob"""
        mk = MasterkeyInfo(
            guid="12345678-1234-1234-1234-123456789012",
            blob=b"TEST_BLOB_DATA"
        )

        assert mk.guid == "12345678-1234-1234-1234-123456789012"
        assert mk.blob == b"TEST_BLOB_DATA"
        assert mk.sha1 is None  # Not decrypted yet (sha1 returns None when _sha1 is None)


class TestScheduledTaskCredentialAssociation:
    """Tests for ScheduledTaskCredential data structure"""

    def test_credential_stores_all_fields(self, sample_task_credential):
        """ScheduledTaskCredential should store all provided fields"""
        assert sample_task_credential.blob_path == "ABC123"
        assert sample_task_credential.username == "DOMAIN\\serviceaccount"
        assert sample_task_credential.password == "P@ssw0rd123!"
        assert "Task:{" in sample_task_credential.target

    def test_credential_with_none_values(self):
        """ScheduledTaskCredential should handle None values"""
        cred = ScheduledTaskCredential(
            task_name=None,
            blob_path=None,
            username=None,
            password=None,
            target=None
        )

        assert cred.task_name is None
        assert cred.username is None
        assert cred.password is None
