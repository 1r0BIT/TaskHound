"""
Unit tests for taskhound/smb/local_users.py — SAMR local user enumeration.
"""
from unittest.mock import MagicMock, patch

import pytest

from taskhound.utils.cache_manager import init_cache


@pytest.fixture(autouse=True)
def initialized_cache(tmp_path):
    """Provide an initialized cache for each test."""
    cache = init_cache(ttl_hours=1, enabled=True, cache_file=tmp_path / "test_cache.db")
    yield cache


class TestEnumerateLocalUsers:
    def test_returns_empty_dict_on_samr_failure(self):
        """Any exception during SAMR enumeration returns {} silently."""
        from taskhound.smb.local_users import enumerate_local_users

        smb = MagicMock()
        smb.getRemoteName.return_value = "DC01"
        smb.getRemoteHost.return_value = "10.0.0.1"
        smb.getServerName.return_value = "DC01"

        with patch("taskhound.smb.local_users.transport") as mock_transport:
            mock_transport.SMBTransport.side_effect = Exception("Connection refused")

            result = enumerate_local_users(smb, "DC01.DOMAIN.LAB")

        assert result == {}

    def test_returns_cached_result_without_rpc(self):
        """Cache hit must return immediately without making any RPC calls."""
        from taskhound.smb.local_users import enumerate_local_users
        from taskhound.utils.cache_manager import get_cache

        cached_data = {"administrator": 500, "guest": 501}
        get_cache().set("local_users", "DC01.DOMAIN.LAB", cached_data)

        smb = MagicMock()

        with patch("taskhound.smb.local_users.transport") as mock_transport:
            result = enumerate_local_users(smb, "DC01.DOMAIN.LAB")
            # Transport should never be called — cache hit path exits early
            mock_transport.SMBTransport.assert_not_called()

        assert result == cached_data

    def test_caches_enumeration_result(self):
        """Successful SAMR enumeration stores result in cache."""
        from taskhound.smb.local_users import enumerate_local_users
        from taskhound.utils.cache_manager import get_cache

        class FakeEntry:
            def __getitem__(self, key):
                if key == "Name":
                    return "localadmin"
                if key == "RelativeId":
                    return 500
                raise KeyError(key)

            def __str__(self):
                return "localadmin"

        fake_enum_resp = {
            "Buffer": {"Buffer": [FakeEntry()]},
            "EnumerationContext": 0,
        }

        smb = MagicMock()
        smb.getRemoteName.return_value = "TARGET01"
        smb.getRemoteHost.return_value = "10.0.0.5"
        smb.getServerName.return_value = "TARGET01"

        with patch("taskhound.smb.local_users.transport") as mock_transport, \
             patch("taskhound.smb.local_users.samr") as mock_samr:

            mock_dce = MagicMock()
            mock_transport.SMBTransport.return_value.get_dce_rpc.return_value = mock_dce

            mock_samr.MSRPC_UUID_SAMR = "fake-uuid"
            mock_samr.USER_NORMAL_ACCOUNT = 0x10
            mock_samr.hSamrConnect5.return_value = {"ServerHandle": MagicMock()}
            mock_samr.hSamrLookupDomainInSamServer.return_value = {"DomainId": MagicMock()}
            mock_samr.hSamrOpenDomain.return_value = {"DomainHandle": MagicMock()}
            mock_samr.hSamrEnumerateUsersInDomain.return_value = fake_enum_resp
            mock_samr.hSamrCloseHandle.return_value = None

            result = enumerate_local_users(smb, "TARGET01.DOMAIN.LAB")

        assert result == {"localadmin": 500}
        cached = get_cache().get("local_users", "TARGET01.DOMAIN.LAB")
        assert cached == {"localadmin": 500}
