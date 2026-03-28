# Tests for LSA secret extraction and offline service enumeration.

from unittest.mock import MagicMock, patch

from taskhound.lsa.extractor import (
    LSAExtractionResult,
    ServiceCredential,
    extract_lsa_secrets,
    extract_service_credentials,
)
from taskhound.models.service import ServiceRow


class TestServiceCredential:
    def test_dataclass(self):
        cred = ServiceCredential(
            service_name="MSSQLSERVER",
            account="CORP\\sqladmin",
            password="P@ssw0rd!",
            lsa_secret_name="_SC_MSSQLSERVER",
        )
        assert cred.service_name == "MSSQLSERVER"
        assert cred.account == "CORP\\sqladmin"
        assert cred.password == "P@ssw0rd!"


class TestLSAExtractionResult:
    def test_defaults(self):
        result = LSAExtractionResult()
        assert result.service_credentials == []
        assert result.dpapi_userkey is None
        assert result.dpapi_machinekey is None
        assert result.raw_secrets == []


class TestExtractLsaSecrets:
    @patch("impacket.examples.regsecrets.LSASecrets")
    @patch("impacket.examples.regsecrets.RemoteOperations")
    def test_basic_extraction(self, mock_remote_cls, mock_lsa_cls):
        """Test extraction via regsecrets (registry-only)."""
        smb = MagicMock()

        mock_remote = MagicMock()
        mock_remote_cls.return_value = mock_remote
        mock_remote.getBootKey.return_value = b"\x00" * 16

        mock_lsa = MagicMock()
        captured_callback = None

        def capture_init(*args, **kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("perSecretCallback")
            return mock_lsa

        mock_lsa_cls.side_effect = capture_init

        def fake_dump():
            if captured_callback:
                # Service credential
                captured_callback("LSA", "CORP\\sqladmin:P@ssw0rd!")
                # DPAPI system key
                captured_callback("LSA", "dpapi_machinekey:0xaabbcc\ndpapi_userkey:0xddeeff")

        mock_lsa.dumpSecrets.side_effect = fake_dump

        result = extract_lsa_secrets(smb, "dc01.corp.local")

        # Verify registry-only lifecycle (no saveSECURITY)
        mock_remote.enableRegistry.assert_called_once()
        mock_remote.getBootKey.assert_called_once()
        mock_remote.finish.assert_called_once()
        mock_lsa.finish.assert_called_once()

        # Service credentials captured
        assert len(result.service_credentials) >= 1
        assert result.service_credentials[0].password == "P@ssw0rd!"

        # DPAPI keys captured
        assert result.dpapi_userkey == "0xddeeff"
        assert result.dpapi_machinekey == "0xaabbcc"

    @patch("impacket.examples.regsecrets.LSASecrets")
    @patch("impacket.examples.regsecrets.RemoteOperations")
    def test_dpapi_key_only(self, mock_remote_cls, mock_lsa_cls):
        """Test extraction when only DPAPI key is available (no service creds)."""
        smb = MagicMock()
        mock_remote = MagicMock()
        mock_remote_cls.return_value = mock_remote
        mock_remote.getBootKey.return_value = b"\x00" * 16

        mock_lsa = MagicMock()
        captured_callback = None

        def capture_init(*args, **kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("perSecretCallback")
            return mock_lsa

        mock_lsa_cls.side_effect = capture_init

        def fake_dump():
            if captured_callback:
                captured_callback("LSA", "dpapi_machinekey:0x1234\ndpapi_userkey:0x5678")

        mock_lsa.dumpSecrets.side_effect = fake_dump

        result = extract_lsa_secrets(smb, "host1")

        assert result.dpapi_userkey == "0x5678"
        assert result.service_credentials == []

    @patch("impacket.examples.regsecrets.RemoteOperations")
    def test_handles_failure_gracefully(self, mock_remote_cls):
        """Test that extraction failure returns empty result."""
        smb = MagicMock()
        mock_remote_cls.return_value.enableRegistry.side_effect = Exception("Access denied")

        result = extract_lsa_secrets(smb, "host1")
        assert result.service_credentials == []
        assert result.dpapi_userkey is None

    @patch("impacket.examples.regsecrets.LSASecrets")
    @patch("impacket.examples.regsecrets.RemoteOperations")
    def test_cleanup_on_error(self, mock_remote_cls, mock_lsa_cls):
        """Verify cleanup happens even on extraction error."""
        smb = MagicMock()
        mock_remote = MagicMock()
        mock_remote_cls.return_value = mock_remote
        mock_remote.getBootKey.side_effect = Exception("boot key failed")

        extract_lsa_secrets(smb, "host1")

        mock_remote.finish.assert_called_once()


class TestExtractServiceCredentialsLegacy:
    """Test the legacy wrapper function."""

    @patch("impacket.examples.regsecrets.LSASecrets")
    @patch("impacket.examples.regsecrets.RemoteOperations")
    def test_returns_credentials_list(self, mock_remote_cls, mock_lsa_cls):
        smb = MagicMock()
        mock_remote = MagicMock()
        mock_remote_cls.return_value = mock_remote
        mock_remote.getBootKey.return_value = b"\x00" * 16

        mock_lsa = MagicMock()
        captured_callback = None

        def capture_init(*args, **kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("perSecretCallback")
            return mock_lsa

        mock_lsa_cls.side_effect = capture_init
        mock_lsa.dumpSecrets.side_effect = lambda: captured_callback("LSA", "user:pass") if captured_callback else None

        result = extract_service_credentials(smb, "host1")
        assert isinstance(result, list)


class TestMapLsaCredsToServiceRows:
    def test_maps_by_service_name(self):
        from taskhound.engine.helpers import _map_lsa_creds_to_service_rows

        rows = [
            ServiceRow(host="dc01", service_name="MSSQLSERVER", start_name="CORP\\sqladmin"),
        ]
        creds = [
            ServiceCredential(service_name="MSSQLSERVER", account="CORP\\sqladmin",
                              password="Secret123!", lsa_secret_name="_SC_MSSQLSERVER"),
        ]

        _map_lsa_creds_to_service_rows(rows, creds, "dc01")
        assert rows[0].decrypted_password == "Secret123!"

    def test_maps_by_account_fallback(self):
        from taskhound.engine.helpers import _map_lsa_creds_to_service_rows

        rows = [
            ServiceRow(host="dc01", service_name="WebApp", start_name="CORP\\websvc"),
        ]
        creds = [
            ServiceCredential(service_name="", account="CORP\\websvc",
                              password="WebPass!", lsa_secret_name=""),
        ]

        _map_lsa_creds_to_service_rows(rows, creds, "dc01")
        assert rows[0].decrypted_password == "WebPass!"

    def test_skips_gmsa(self):
        from taskhound.engine.helpers import _map_lsa_creds_to_service_rows

        rows = [
            ServiceRow(host="dc01", service_name="Svc1", start_name="CORP\\gmsa$", is_gmsa=True),
        ]
        creds = [
            ServiceCredential(service_name="Svc1", account="CORP\\gmsa$",
                              password="ShouldNotMatch", lsa_secret_name=""),
        ]

        _map_lsa_creds_to_service_rows(rows, creds, "dc01")
        assert rows[0].decrypted_password is None


class TestPerformLsaServiceLooting:
    """Test legacy perform_lsa_service_looting (still used by tests)."""

    def test_maps_credentials_to_rows(self):
        from taskhound.engine.helpers import perform_lsa_service_looting

        rows = [
            ServiceRow(host="dc01", service_name="MSSQLSERVER", start_name="CORP\\sqladmin"),
            ServiceRow(host="dc01", service_name="AppPool", start_name="CORP\\webapp"),
        ]

        mock_creds = [
            ServiceCredential(
                service_name="MSSQLSERVER",
                account="CORP\\sqladmin",
                password="Secret123!",
                lsa_secret_name="_SC_MSSQLSERVER",
            ),
        ]

        with patch("taskhound.lsa.extractor.extract_service_credentials", return_value=mock_creds):
            perform_lsa_service_looting("dc01", MagicMock(), "dc01.corp.local", rows)

        assert rows[0].decrypted_password == "Secret123!"
        assert rows[1].decrypted_password is None


class TestOfflineServiceEnumeration:
    @patch("impacket.winregistry.Registry")
    def test_enumerate_services_from_hive(self, mock_registry_cls):
        """Test offline service enumeration from SYSTEM hive."""
        from taskhound.lsa.offline import enumerate_services_from_hive

        mock_reg = MagicMock()
        mock_registry_cls.return_value = mock_reg

        mock_reg.findKey.side_effect = lambda path: f"key_{path}"
        mock_reg.getValue.side_effect = lambda name, key: {
            ("Current", "key_Select"): (1, 1),
            ("Type", "key_ControlSet001\\Services\\MSSQLSERVER"): (1, 0x10),
            ("ObjectName", "key_ControlSet001\\Services\\MSSQLSERVER"): (1, "CORP\\sqladmin\x00"),
            ("ImagePath", "key_ControlSet001\\Services\\MSSQLSERVER"): (1, "C:\\SQL\\sqlservr.exe\x00"),
            ("Start", "key_ControlSet001\\Services\\MSSQLSERVER"): (1, 2),
            ("DisplayName", "key_ControlSet001\\Services\\MSSQLSERVER"): (1, "SQL Server\x00"),
        }.get((name, key))

        mock_reg.enumKey.return_value = ["MSSQLSERVER"]

        services = enumerate_services_from_hive("/tmp/SYSTEM", hostname="DC01")

        assert len(services) == 1
        assert services[0]["name"] == "MSSQLSERVER"
        assert services[0]["account"] == "CORP\\sqladmin"
        mock_reg.close.assert_called_once()

    @patch("impacket.winregistry.Registry")
    def test_skips_drivers(self, mock_registry_cls):
        """Test that kernel drivers are filtered out."""
        from taskhound.lsa.offline import enumerate_services_from_hive

        mock_reg = MagicMock()
        mock_registry_cls.return_value = mock_reg

        mock_reg.findKey.side_effect = lambda path: f"key_{path}"
        mock_reg.getValue.side_effect = lambda name, key: {
            ("Current", "key_Select"): (1, 1),
            ("Type", "key_ControlSet001\\Services\\SomeDriver"): (1, 0x01),
        }.get((name, key))

        mock_reg.enumKey.return_value = ["SomeDriver"]

        services = enumerate_services_from_hive("/tmp/SYSTEM")
        assert len(services) == 0

    def test_handles_missing_hive(self):
        """Test graceful handling of missing hive file."""
        from taskhound.lsa.offline import enumerate_services_from_hive

        result = enumerate_services_from_hive("/nonexistent/SYSTEM")
        assert result == []
