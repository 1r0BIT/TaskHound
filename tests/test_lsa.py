# Tests for LSA secret extraction and offline service enumeration.

from unittest.mock import MagicMock, patch

from taskhound.lsa.extractor import ServiceCredential, extract_service_credentials
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


class TestExtractServiceCredentials:
    @patch("impacket.examples.secretsdump.LSASecrets")
    @patch("impacket.examples.secretsdump.RemoteOperations")
    def test_basic_extraction(self, mock_remote_cls, mock_lsa_cls):
        """Test the extraction workflow calls impacket correctly."""
        smb = MagicMock()

        # Mock RemoteOperations
        mock_remote = MagicMock()
        mock_remote_cls.return_value = mock_remote
        mock_remote.getBootKey.return_value = b"\x00" * 16
        mock_remote.getSecurityHive.return_value = "/tmp/fake_security"

        # Mock LSASecrets — capture the callback
        mock_lsa = MagicMock()
        captured_callback = None

        def capture_init(*args, **kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("perSecretCallback")
            return mock_lsa

        mock_lsa_cls.side_effect = capture_init

        # Make dumpSecrets call the callback with a _SC_ secret
        def fake_dump():
            if captured_callback:
                captured_callback("LSA", "CORP\\sqladmin:P@ssw0rd!")

        mock_lsa.dumpSecrets.side_effect = fake_dump

        result = extract_service_credentials(
            smb, "dc01.corp.local",
            service_names={"MSSQLSERVER"},
        )

        # Verify RemoteOperations lifecycle
        mock_remote.enableRegistry.assert_called_once()
        mock_remote.getBootKey.assert_called_once()
        mock_remote.saveSECURITY.assert_called_once()
        mock_remote.finish.assert_called_once()
        mock_lsa.finish.assert_called_once()

        # Should have captured credentials
        assert len(result) >= 1

    @patch("impacket.examples.secretsdump.RemoteOperations")
    def test_handles_failure_gracefully(self, mock_remote_cls):
        """Test that extraction failure returns empty list."""
        smb = MagicMock()
        mock_remote_cls.return_value.enableRegistry.side_effect = Exception("Access denied")

        result = extract_service_credentials(smb, "host1")
        assert result == []

    @patch("impacket.examples.secretsdump.LSASecrets")
    @patch("impacket.examples.secretsdump.RemoteOperations")
    def test_cleanup_on_error(self, mock_remote_cls, mock_lsa_cls):
        """Verify cleanup happens even on extraction error."""
        smb = MagicMock()
        mock_remote = MagicMock()
        mock_remote_cls.return_value = mock_remote
        mock_remote.getBootKey.side_effect = Exception("boot key failed")

        extract_service_credentials(smb, "host1")

        # Cleanup should still be called
        mock_remote.finish.assert_called_once()


class TestPerformLsaServiceLooting:
    def test_maps_credentials_to_rows(self):
        """Test that perform_lsa_service_looting maps creds back to ServiceRow."""
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

    def test_fallback_account_matching(self):
        """Test credential matching falls back to account name."""
        from taskhound.engine.helpers import perform_lsa_service_looting

        rows = [
            ServiceRow(host="dc01", service_name="WebApp", start_name="CORP\\websvc"),
        ]

        mock_creds = [
            ServiceCredential(
                service_name="",
                account="CORP\\websvc",
                password="WebPass!",
                lsa_secret_name="",
            ),
        ]

        with patch("taskhound.lsa.extractor.extract_service_credentials", return_value=mock_creds):
            perform_lsa_service_looting("dc01", MagicMock(), "dc01.corp.local", rows)

        assert rows[0].decrypted_password == "WebPass!"


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
