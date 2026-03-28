# Tests for the service account filter.

import pytest

from taskhound.parsers.service_filter import (
    filter_domain_services,
    is_builtin_account,
    is_domain_account,
)


class TestIsBuiltinAccount:
    @pytest.mark.parametrize("account", [
        "LocalSystem",
        "localsystem",
        "NT AUTHORITY\\SYSTEM",
        "NT AUTHORITY\\LocalService",
        "NT AUTHORITY\\NetworkService",
        "NT AUTHORITY\\Network Service",
        "NT AUTHORITY\\Local Service",
        ".\\LocalSystem",
        "SYSTEM",
        "NetworkService",
        "LocalService",
        "Network Service",
        "Local Service",
    ])
    def test_builtin_accounts_detected(self, account):
        assert is_builtin_account(account) is True

    @pytest.mark.parametrize("account", [
        "",
        "   ",
        None,
    ])
    def test_empty_is_builtin(self, account):
        # Empty/null start_name defaults to LocalSystem
        assert is_builtin_account(account or "") is True

    @pytest.mark.parametrize("account", [
        "NT SERVICE\\MSSQLSERVER",
        "NT SERVICE\\W3SVC",
        "NT AUTHORITY\\SomeOther",
    ])
    def test_virtual_service_accounts(self, account):
        assert is_builtin_account(account) is True

    @pytest.mark.parametrize("account", [
        "CORP\\sqladmin",
        "sqladmin@corp.local",
        "sqladmin",
        "DOMAIN\\svc_account$",
    ])
    def test_domain_accounts_not_builtin(self, account):
        assert is_builtin_account(account) is False


class TestIsDomainAccount:
    def test_domain_backslash(self):
        assert is_domain_account("CORP\\admin") is True

    def test_upn_format(self):
        assert is_domain_account("admin@corp.local") is True

    def test_bare_name(self):
        # Bare names are treated as potentially domain accounts
        assert is_domain_account("sqladmin") is True

    def test_empty(self):
        assert is_domain_account("") is False
        assert is_domain_account(None) is False


class TestFilterDomainServices:
    def _svc(self, account):
        return {"name": "TestSvc", "account": account, "binary_path": "svc.exe",
                "start_type": 2, "service_type": 0x10, "state": 4}

    def test_filters_builtin(self):
        services = [
            self._svc("LocalSystem"),
            self._svc("CORP\\admin"),
            self._svc("NT AUTHORITY\\NetworkService"),
        ]
        result = filter_domain_services(services)
        assert len(result) == 1
        assert result[0]["account"] == "CORP\\admin"

    def test_filters_local_accounts(self):
        services = [
            self._svc("Administrator"),
            self._svc("CORP\\admin"),
        ]
        local = {"administrator"}
        result = filter_domain_services(services, local_accounts=local)
        assert len(result) == 1
        assert result[0]["account"] == "CORP\\admin"

    def test_keeps_domain_prefix_even_if_in_local(self):
        """DOMAIN\\Administrator should NOT be filtered by local accounts."""
        services = [self._svc("CORP\\Administrator")]
        local = {"administrator"}
        result = filter_domain_services(services, local_accounts=local)
        assert len(result) == 1

    def test_empty_list(self):
        assert filter_domain_services([]) == []

    def test_all_builtin(self):
        services = [
            self._svc("LocalSystem"),
            self._svc("NT AUTHORITY\\SYSTEM"),
        ]
        assert filter_domain_services(services) == []

    def test_dot_prefix_local(self):
        """.\\Administrator is a local account reference."""
        services = [self._svc(".\\Administrator")]
        local = {"administrator"}
        result = filter_domain_services(services, local_accounts=local)
        assert len(result) == 0
