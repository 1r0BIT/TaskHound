"""Tests for taskhound/dpapi/decryptor.py - DPAPI decryption classes."""

from unittest.mock import MagicMock, patch

from taskhound.dpapi.decryptor import (
    DPAPIDecryptor,
    MasterkeyInfo,
    ScheduledTaskCredential,
    _parse_credential_blob,
)
from taskhound.utils.helpers import is_guid


class TestMasterkeyInfo:
    """Tests for MasterkeyInfo class."""

    def test_init_basic(self):
        """MasterkeyInfo initializes with guid and blob."""
        mk = MasterkeyInfo(guid="12345678-1234-1234-1234-123456789012", blob=b"test_blob")
        assert mk.guid == "12345678-1234-1234-1234-123456789012"
        assert mk.blob == b"test_blob"

    def test_guid_normalized_to_lowercase(self):
        """GUID is normalized to lowercase."""
        mk = MasterkeyInfo(guid="ABCD1234-ABCD-ABCD-ABCD-ABCD1234ABCD", blob=b"test")
        assert mk.guid == "abcd1234-abcd-abcd-abcd-abcd1234abcd"

    def test_key_initially_none(self):
        """Key is None before decryption."""
        mk = MasterkeyInfo(guid="test-guid", blob=b"test")
        assert mk.key is None

    def test_sha1_none_before_decrypt(self):
        """SHA1 property returns None before decryption."""
        mk = MasterkeyInfo(guid="test-guid", blob=b"test")
        assert mk.sha1 is None

    def test_str_representation_encrypted(self):
        """String representation shows ENCRYPTED when key not decrypted."""
        mk = MasterkeyInfo(guid="test-guid", blob=b"test")
        assert "ENCRYPTED" in str(mk)
        assert "test-guid" in str(mk)

    def test_str_representation_decrypted(self):
        """String representation shows SHA1 when key is decrypted."""
        mk = MasterkeyInfo(guid="test-guid", blob=b"test")
        mk.key = b"decrypted_key"
        mk._sha1 = "abcdef1234567890"
        assert "abcdef1234567890" in str(mk)
        assert "test-guid" in str(mk)


class TestScheduledTaskCredential:
    """Tests for ScheduledTaskCredential class."""

    def test_init_basic(self):
        """Basic initialization with required fields."""
        cred = ScheduledTaskCredential(task_name="TestTask", blob_path="/path/to/blob")
        assert cred.task_name == "TestTask"
        assert cred.blob_path == "/path/to/blob"
        assert cred.username is None
        assert cred.password is None
        assert cred.target is None

    def test_init_full(self):
        """Full initialization with all fields."""
        cred = ScheduledTaskCredential(
            task_name="TestTask",
            blob_path="/path/to/blob",
            username="DOMAIN\\admin",
            password="P@ssw0rd",
            target="{12345678-1234-1234-1234-123456789012}",
        )
        assert cred.username == "DOMAIN\\admin"
        assert cred.password == "P@ssw0rd"
        assert cred.target == "{12345678-1234-1234-1234-123456789012}"

class TestDPAPIDecryptorInit:
    """Tests for DPAPIDecryptor initialization."""

    def test_init_with_hex_prefix(self):
        """Initializes correctly with 0x prefixed dpapi_userkey."""
        mock_conn = MagicMock()
        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "0x" + "a1" * 20)
        assert decryptor.smb_conn == mock_conn
        assert len(decryptor.dpapi_userkey) == 20  # 40 hex chars = 20 bytes

    def test_init_without_hex_prefix(self):
        """Initializes correctly without 0x prefix."""
        mock_conn = MagicMock()
        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "a1" * 20)
        assert len(decryptor.dpapi_userkey) == 20

    def test_init_empty_masterkeys(self):
        """Masterkeys dict is empty after initialization."""
        mock_conn = MagicMock()
        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "a1" * 20)
        assert decryptor.masterkeys == {}


class TestDPAPIDecryptorPathConstants:
    """Tests for DPAPIDecryptor path constants."""

    def test_system_masterkey_path(self):
        """SYSTEM_MASTERKEY_PATH is correctly defined."""
        assert "Microsoft\\Protect\\S-1-5-18" in DPAPIDecryptor.SYSTEM_MASTERKEY_PATH

    def test_system_credentials_path(self):
        """SYSTEM_CREDENTIALS_PATH is correctly defined."""
        assert "systemprofile" in DPAPIDecryptor.SYSTEM_CREDENTIALS_PATH
        assert "Credentials" in DPAPIDecryptor.SYSTEM_CREDENTIALS_PATH


class TestMasterkeyDecryption:
    """Tests for masterkey decryption."""

    def test_decrypt_invalid_blob_returns_false(self):
        """Decryption with invalid blob returns False."""
        mk = MasterkeyInfo(guid="test-guid", blob=b"invalid_blob")
        result = mk.decrypt(b"fake_dpapi_userkey_")
        assert result is False
        assert mk.key is None


class TestIsGuid:
    """Tests for is_guid helper function (moved to utils.helpers)."""

    def test_valid_guid(self):
        """Valid GUID returns True."""
        assert is_guid("12345678-1234-1234-1234-123456789012") is True

    def test_valid_guid_lowercase(self):
        """Lowercase GUID returns True."""
        assert is_guid("abcdef12-abcd-abcd-abcd-abcdef123456") is True

    def test_valid_guid_uppercase(self):
        """Uppercase GUID returns True."""
        assert is_guid("ABCDEF12-ABCD-ABCD-ABCD-ABCDEF123456") is True

    def test_invalid_length(self):
        """String with wrong length returns False."""
        assert is_guid("12345678") is False
        assert is_guid("12345678-1234-1234-1234-12345678901") is False
        assert is_guid("12345678-1234-1234-1234-1234567890123") is False

    def test_wrong_part_count(self):
        """GUID with wrong number of dashes returns False."""
        assert is_guid("12345678123412341234123456789012") is False

    def test_wrong_part_lengths(self):
        """GUID with wrong part lengths returns False."""
        assert is_guid("1234567-12345-1234-1234-123456789012") is False

    def test_non_hex_characters(self):
        """GUID with non-hex characters returns False."""
        assert is_guid("GHIJKLMN-1234-1234-1234-123456789012") is False


class TestReadFile:
    """Tests for _read_file method."""

    def test_read_file_success(self):
        """_read_file returns data on success."""
        mock_conn = MagicMock()
        def mock_get_file(share, path, callback):
            callback(b"file_contents")
        mock_conn.getFile = mock_get_file

        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "0x" + "aa" * 20)
        result = decryptor._read_file("C$", "path\\to\\file")
        assert result == b"file_contents"

    def test_read_file_exception(self):
        """_read_file returns None on exception."""
        mock_conn = MagicMock()
        mock_conn.getFile.side_effect = Exception("Access denied")

        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "0x" + "aa" * 20)
        result = decryptor._read_file("C$", "path\\to\\file")
        assert result is None


class TestTriageSystemMasterkeys:
    """Tests for triage_system_masterkeys method."""

    def test_triage_empty_directory(self):
        """Returns empty list for empty directory."""
        mock_conn = MagicMock()
        mock_conn.listPath.return_value = []

        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "0x" + "aa" * 20)
        result = decryptor.triage_system_masterkeys()
        assert result == []

    def test_triage_skips_dots(self):
        """Skips . and .. directories."""
        mock_conn = MagicMock()
        dot = MagicMock()
        dot.get_longname.return_value = "."
        dotdot = MagicMock()
        dotdot.get_longname.return_value = ".."
        mock_conn.listPath.return_value = [dot, dotdot]

        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "0x" + "aa" * 20)
        result = decryptor.triage_system_masterkeys()
        assert result == []

    def test_triage_skips_non_guid_files(self):
        """Skips files that are not GUIDs."""
        mock_conn = MagicMock()
        non_guid = MagicMock()
        non_guid.get_longname.return_value = "Preferred"
        mock_conn.listPath.return_value = [non_guid]

        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "0x" + "aa" * 20)
        result = decryptor.triage_system_masterkeys()
        assert result == []

    def test_triage_handles_exception(self):
        """Handles exception during listPath."""
        mock_conn = MagicMock()
        mock_conn.listPath.side_effect = Exception("Network error")

        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "0x" + "aa" * 20)
        result = decryptor.triage_system_masterkeys()
        assert result == []


class TestDecryptCredentialBlob:
    """Tests for decrypt_credential_blob method."""

    def test_returns_credential_on_exception(self):
        """Returns partial credential object on exception."""
        mock_conn = MagicMock()
        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "0x" + "aa" * 20)

        with patch("taskhound.dpapi.decryptor.CredentialFile") as mock_cf:
            mock_cf.side_effect = Exception("Parse error")
            result = decryptor.decrypt_credential_blob(
                blob_bytes=b"bad_data",
                task_name="TestTask",
                blob_path="C:\\path",
            )
            assert result is not None
            assert result.task_name == "TestTask"
            assert result.blob_path == "C:\\path"

    def test_returns_credential_when_masterkey_not_found(self):
        """Returns partial credential when masterkey not found."""
        mock_conn = MagicMock()
        with patch("taskhound.dpapi.decryptor.logging"):
            decryptor = DPAPIDecryptor(mock_conn, "0x" + "aa" * 20)

        with patch("taskhound.dpapi.decryptor.CredentialFile") as mock_cf, \
             patch("taskhound.dpapi.decryptor.DPAPI_BLOB") as mock_blob, \
             patch("taskhound.dpapi.decryptor.bin_to_string") as mock_bin:
            mock_cf.return_value = {"Data": b"inner"}
            mock_blob.return_value = {"GuidMasterKey": b"guid"}
            mock_bin.return_value = "missing-guid-1234-1234-123456789012"

            result = decryptor.decrypt_credential_blob(
                blob_bytes=b"data",
                task_name="Task",
                blob_path="path",
            )
            assert result is not None
            assert result.username is None


class TestParseCredentialBlob:
    """Tests for the shared _parse_credential_blob field extractor.

    Online and offline both route decrypted bytes through this function; these
    cover the positive extraction path the wrapper tests skip.
    """

    @staticmethod
    def _build_credential_blob(target: str, username: str, password: str) -> bytes:
        """Lay out a CREDENTIAL_BLOB as raw bytes (the production parse path).

        Hand-built because impacket's CREDENTIAL_BLOB has a duplicate 'Unknown3'
        field name that breaks fresh getData() packing.
        """
        import struct

        def u16(s: str) -> bytes:
            return s.encode("utf-16-le") + b"\x00\x00"

        tgt, usr, pwd = u16(target), u16(username), u16(password)
        return b"".join([
            struct.pack("<L", 0),  # Flags
            struct.pack("<L", 0),  # Size
            struct.pack("<L", 0),  # Unknown0
            struct.pack("<L", 0),  # Type
            struct.pack("<L", 0),  # Flags2
            struct.pack("<Q", 0),  # LastWritten
            struct.pack("<L", 0),  # Unknown2
            struct.pack("<L", 0),  # Persist
            struct.pack("<L", 0),  # AttrCount
            struct.pack("<Q", 0),  # Unknown3 (the <Q field, not the password)
            struct.pack("<L", len(tgt)), tgt,
            struct.pack("<L", 0),  # TargetAlias
            struct.pack("<L", 0),  # Description
            struct.pack("<L", 0),  # Unknown
            struct.pack("<L", len(usr)), usr,
            struct.pack("<L", len(pwd)), pwd,
        ])

    def test_extracts_username_password_and_task_guid(self):
        """Extracts username, password, and the task GUID from the Target field."""
        raw = self._build_credential_blob(
            "Domain:batch=TaskScheduler:Task:{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "LUDUS\\svc_backup",
            "Sup3rS3cret!",
        )
        cred = _parse_credential_blob(raw, blob_path="ABC123")
        assert cred.username == "LUDUS\\svc_backup"
        assert cred.password == "Sup3rS3cret!"
        assert cred.task_name == "Task:{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
        assert cred.blob_path == "ABC123"
        assert cred.target == "Domain:batch=TaskScheduler:Task:{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"

    def test_provided_task_name_is_preserved(self):
        """An explicit task_name is not overwritten by the Target GUID."""
        raw = self._build_credential_blob(
            "Domain:batch=TaskScheduler:Task:{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "user",
            "pass",
        )
        cred = _parse_credential_blob(raw, blob_path="x", task_name="ExplicitTask")
        assert cred.task_name == "ExplicitTask"
