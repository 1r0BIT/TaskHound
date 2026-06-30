"""
Tests for BloodHound connector module.
"""
from unittest.mock import MagicMock, patch

import pytest

from taskhound.connectors.bloodhound import (
    BloodHoundConnector,
    _safe_get_sam,
)
from taskhound.output.bloodhound import _get_alternate_protocol_uri


class TestSafeGetSam:
    """Tests for _safe_get_sam helper function"""

    def test_returns_lowercase_value(self):
        """Should return lowercase SAM account name"""
        data = {"SamAccountName": "ADMIN"}
        result = _safe_get_sam(data, "SamAccountName")

        assert result == "admin"

    def test_handles_none_value(self):
        """Should return empty string for None value"""
        data = {"SamAccountName": None}
        result = _safe_get_sam(data, "SamAccountName")

        assert result == ""

    def test_handles_missing_key(self):
        """Should return empty string for missing key"""
        data = {}
        result = _safe_get_sam(data, "SamAccountName")

        assert result == ""

    def test_handles_non_string_value(self):
        """Should convert non-string to lowercase string"""
        data = {"SamAccountName": 123}
        result = _safe_get_sam(data, "SamAccountName")

        assert result == "123"

    def test_handles_already_lowercase(self):
        """Should keep already lowercase value"""
        data = {"samaccountname": "user"}
        result = _safe_get_sam(data, "samaccountname")

        assert result == "user"

    def test_handles_empty_string(self):
        """Should return empty string for empty string value"""
        data = {"SamAccountName": ""}
        result = _safe_get_sam(data, "SamAccountName")

        assert result == ""


class TestBloodHoundConnectorInit:
    """Tests for BloodHoundConnector initialization"""

    def test_init_bhce(self):
        """Should initialize BHCE connector"""
        connector = BloodHoundConnector(
            bh_type="bhce",
            ip="192.168.1.1",
            username="admin",
            password="password"
        )

        assert connector.bh_type == "bhce"
        assert connector.ip == "192.168.1.1"
        assert connector.username == "admin"

    def test_init_legacy(self):
        """Should initialize legacy connector"""
        connector = BloodHoundConnector(
            bh_type="legacy",
            ip="192.168.1.1",
            username="neo4j",
            password="neo4jpassword"
        )

        assert connector.bh_type == "legacy"

    def test_init_with_api_key(self):
        """Should initialize with API key"""
        connector = BloodHoundConnector(
            bh_type="bhce",
            ip="192.168.1.1",
            api_key="test_api_key",
            api_key_id="test_key_id"
        )

        assert connector.api_key == "test_api_key"
        assert connector.api_key_id == "test_key_id"

    def test_init_with_custom_timeout(self):
        """Should set custom timeout"""
        connector = BloodHoundConnector(
            bh_type="bhce",
            ip="192.168.1.1",
            timeout=300
        )

        assert connector.timeout == 300

    def test_init_default_timeout(self):
        """Should set default timeout of 120"""
        connector = BloodHoundConnector(
            bh_type="bhce",
            ip="192.168.1.1",
        )

        assert connector.timeout == 120

    def test_init_with_url_scheme(self):
        """Should handle URL with scheme"""
        connector = BloodHoundConnector(
            bh_type="bhce",
            ip="https://bloodhound.domain.lab",
            username="admin",
            password="password"
        )

        assert "bloodhound.domain.lab" in connector.ip


class TestBloodHoundConnectorRunCypherQuery:
    """Tests for run_cypher_query method"""

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_routes_to_bhce(self):
        """Should route BHCE to REST API method"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.authenticator = MagicMock()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"nodes": []}}
        connector.authenticator.request.return_value = mock_response

        result = connector.run_cypher_query("MATCH (n) RETURN n")

        assert result == {"data": {"nodes": []}}
        connector.authenticator.request.assert_called_once()

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch('taskhound.connectors.bloodhound.GraphDatabase')
    def test_legacy_driver_closes_on_success(self, mock_graph_db):
        """_legacy_driver yields the bolt-URI/auth driver and closes it on exit (U-40)."""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.ip = "10.0.0.1"
        connector.username = "neo4j"
        connector.password = "pw"
        mock_driver = MagicMock()
        mock_graph_db.driver.return_value = mock_driver

        with connector._legacy_driver() as driver:
            assert driver is mock_driver

        mock_graph_db.driver.assert_called_once_with("bolt://10.0.0.1:7687", auth=("neo4j", "pw"))
        mock_driver.close.assert_called_once()

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch('taskhound.connectors.bloodhound.GraphDatabase')
    def test_legacy_driver_closes_on_exception(self, mock_graph_db):
        """Driver is closed even when the body raises — the leak fix that motivated U-40."""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.ip = "10.0.0.1"
        connector.username = "neo4j"
        connector.password = "pw"
        mock_driver = MagicMock()
        mock_graph_db.driver.return_value = mock_driver

        with pytest.raises(RuntimeError):
            with connector._legacy_driver():
                raise RuntimeError("boom")

        mock_driver.close.assert_called_once()

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch('taskhound.connectors.bloodhound.GraphDatabase')
    def test_routes_to_legacy(self, mock_graph_db):
        """Should route Legacy to Neo4j Bolt method"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "legacy"
        connector.ip = "192.168.1.1"
        connector.username = "neo4j"
        connector.password = "password"

        # Mock Neo4j driver and session
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.__iter__ = lambda x: iter([{"name": "ADMIN@CORP.LOCAL"}])
        mock_session.run.return_value = mock_result
        mock_driver.session.return_value.__enter__ = lambda x: mock_session
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_graph_db.driver.return_value = mock_driver

        result = connector.run_cypher_query("MATCH (n) RETURN n.name AS name")

        assert result == {"data": {"data": [{"name": "ADMIN@CORP.LOCAL"}]}}
        mock_graph_db.driver.assert_called_once_with(
            "bolt://192.168.1.1:7687",
            auth=("neo4j", "password")
        )

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_successful_query(self):
        """Should execute successful cypher query"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.authenticator = MagicMock()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"nodes": []}}
        connector.authenticator.request.return_value = mock_response

        result = connector.run_cypher_query("MATCH (n) RETURN n")

        assert result == {"data": {"nodes": []}}

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_failed_query_returns_none(self):
        """Should return None on failed query"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.authenticator = MagicMock()

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        connector.authenticator.request.return_value = mock_response

        result = connector.run_cypher_query("INVALID QUERY")

        assert result is None

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_handles_request_exception(self):
        """Should handle request exceptions gracefully"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.authenticator = MagicMock()
        connector.authenticator.request.side_effect = Exception("Connection failed")

        result = connector.run_cypher_query("MATCH (n) RETURN n")

        assert result is None


class TestBloodHoundConnectorRunCypherQueryLegacy:
    """Tests for Legacy BloodHound Cypher query support"""

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch('taskhound.connectors.bloodhound.GraphDatabase')
    def test_successful_legacy_query(self, mock_graph_db):
        """Should execute successful Cypher query against Neo4j"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "legacy"
        connector.ip = "192.168.1.1"
        connector.username = "neo4j"
        connector.password = "password"

        # Mock Neo4j response with user data
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.__iter__ = lambda x: iter([
            {"name": "ADMIN@CORP.LOCAL", "objectid": "S-1-5-21-123-456-789-500"}
        ])
        mock_session.run.return_value = mock_result
        mock_driver.session.return_value.__enter__ = lambda x: mock_session
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_graph_db.driver.return_value = mock_driver

        result = connector._run_cypher_query_legacy(
            'MATCH (n) WHERE n.objectid = "S-1-5-21-123-456-789-500" RETURN n.name AS name'
        )

        assert result is not None
        assert "data" in result
        assert "data" in result["data"]
        assert len(result["data"]["data"]) == 1
        assert result["data"]["data"][0]["name"] == "ADMIN@CORP.LOCAL"

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch('taskhound.connectors.bloodhound.GraphDatabase')
    def test_legacy_query_multiple_results(self, mock_graph_db):
        """Should handle multiple results from Neo4j"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "legacy"
        connector.ip = "192.168.1.1"
        connector.username = "neo4j"
        connector.password = "password"

        # Mock multiple users
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.__iter__ = lambda x: iter([
            {"name": "ADMIN@CORP.LOCAL"},
            {"name": "USER1@CORP.LOCAL"},
            {"name": "USER2@CORP.LOCAL"},
        ])
        mock_session.run.return_value = mock_result
        mock_driver.session.return_value.__enter__ = lambda x: mock_session
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_graph_db.driver.return_value = mock_driver

        result = connector._run_cypher_query_legacy("MATCH (u:User) RETURN u.name AS name")

        assert len(result["data"]["data"]) == 3

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch('taskhound.connectors.bloodhound.GraphDatabase')
    def test_legacy_query_empty_results(self, mock_graph_db):
        """Should handle empty results from Neo4j"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "legacy"
        connector.ip = "192.168.1.1"
        connector.username = "neo4j"
        connector.password = "password"

        # Mock empty result
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.__iter__ = lambda x: iter([])
        mock_session.run.return_value = mock_result
        mock_driver.session.return_value.__enter__ = lambda x: mock_session
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_graph_db.driver.return_value = mock_driver

        result = connector._run_cypher_query_legacy("MATCH (n:NonExistent) RETURN n")

        assert result == {"data": {"data": []}}

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch('taskhound.connectors.bloodhound.GraphDatabase')
    def test_legacy_query_connection_failure(self, mock_graph_db):
        """Should handle Neo4j connection failure"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "legacy"
        connector.ip = "192.168.1.1"
        connector.username = "neo4j"
        connector.password = "password"

        # Mock connection failure
        mock_graph_db.driver.side_effect = Exception("Connection refused")

        result = connector._run_cypher_query_legacy("MATCH (n) RETURN n")

        assert result is None

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch('taskhound.connectors.bloodhound.GraphDatabase', None)
    def test_legacy_query_no_neo4j_library(self):
        """Should return None when neo4j library not installed"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "legacy"
        connector.ip = "192.168.1.1"
        connector.username = "neo4j"
        connector.password = "password"

        result = connector._run_cypher_query_legacy("MATCH (n) RETURN n")

        assert result is None

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch('taskhound.connectors.bloodhound.GraphDatabase')
    def test_legacy_sid_resolution_query(self, mock_graph_db):
        """Should support SID resolution query pattern used by sid_resolver"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "legacy"
        connector.ip = "192.168.1.1"
        connector.username = "neo4j"
        connector.password = "password"

        # Mock the exact query pattern from resolve_sid_via_bloodhound_api
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.__iter__ = lambda x: iter([{"name": "SERVICEACCOUNT@CORP.LOCAL"}])
        mock_session.run.return_value = mock_result
        mock_driver.session.return_value.__enter__ = lambda x: mock_session
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_graph_db.driver.return_value = mock_driver

        # This is the exact query pattern from sid_resolver.py
        sid = "S-1-5-21-123-456-789-1001"
        query = f'MATCH (n) WHERE n.objectid = "{sid}" RETURN n.name AS name LIMIT 1'
        result = connector.run_cypher_query(query)

        # Verify format matches what resolve_sid_via_bloodhound_api expects
        assert result is not None
        assert "data" in result
        assert "data" in result["data"]
        assert len(result["data"]["data"]) > 0
        assert result["data"]["data"][0]["name"] == "SERVICEACCOUNT@CORP.LOCAL"


class TestBloodHoundConnectorConnectAndQuery:
    """Tests for connect_and_query method"""

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, '_query_bhce')
    def test_routes_to_bhce(self, mock_query_bhce):
        """Should route to BHCE query method"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        mock_query_bhce.return_value = True

        result = connector.connect_and_query()

        assert result is True
        mock_query_bhce.assert_called_once()

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, '_query_legacy')
    def test_routes_to_legacy(self, mock_query_legacy):
        """Should route to legacy query method"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "legacy"
        mock_query_legacy.return_value = True

        result = connector.connect_and_query()

        assert result is True
        mock_query_legacy.assert_called_once()

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_rejects_unknown_type(self):
        """Should return False for unknown bh_type"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "unknown"

        result = connector.connect_and_query()

        assert result is False

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, '_query_bhce')
    def test_handles_exception(self, mock_query_bhce):
        """Should handle exceptions gracefully"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        mock_query_bhce.side_effect = Exception("Connection failed")

        result = connector.connect_and_query()

        assert result is False


class TestBloodHoundConnectorQueryBHCE:
    """Tests for _query_bhce method"""

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_connection_refused(self):
        """Should handle connection refused"""
        import requests

        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.ip = "192.168.1.1"
        connector.authenticator = MagicMock()
        connector.authenticator.request.side_effect = requests.exceptions.ConnectionError()

        result = connector._query_bhce()

        assert result is False

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_timeout_error(self):
        """Should handle timeout"""
        import requests

        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.ip = "192.168.1.1"
        connector.authenticator = MagicMock()
        connector.authenticator.request.side_effect = requests.exceptions.Timeout()

        result = connector._query_bhce()

        assert result is False

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_version_check_failure(self):
        """Should return False if version check fails"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.ip = "192.168.1.1"
        connector.authenticator = MagicMock()

        # First call for version check returns error
        mock_response = MagicMock()
        mock_response.status_code = 401
        connector.authenticator.request.return_value = mock_response

        result = connector._query_bhce()

        assert result is False


class TestBloodHoundConnectorGetUsersData:
    """Tests for get_users_data method"""

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_returns_users_data(self):
        """Should return users data dict"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.users_data = {"admin": {"sid": "S-1-5-21-xxx"}}

        result = connector.get_users_data()

        assert result == {"admin": {"sid": "S-1-5-21-xxx"}}

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_returns_empty_dict_when_no_data(self):
        """Should return empty dict when no data"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.users_data = {}

        result = connector.get_users_data()

        assert result == {}


class TestGetAlternateProtocolUri:
    """Tests for _get_alternate_protocol_uri helper function"""

    def test_http_to_https_keeps_port(self):
        """Should convert http to https keeping the same port"""
        result = _get_alternate_protocol_uri("http://localhost:8080")
        assert result == "https://localhost:8080"

    def test_https_to_http_keeps_port(self):
        """Should convert https to http keeping the same port"""
        result = _get_alternate_protocol_uri("https://localhost:8080")
        assert result == "http://localhost:8080"

    def test_http_custom_port_preserved(self):
        """Should preserve custom ports when converting http to https"""
        result = _get_alternate_protocol_uri("http://localhost:9090")
        assert result == "https://localhost:9090"

    def test_https_custom_port_preserved(self):
        """Should preserve custom ports when converting https to http"""
        result = _get_alternate_protocol_uri("https://localhost:9443")
        assert result == "http://localhost:9443"

    def test_with_fqdn(self):
        """Should handle fully qualified domain names"""
        result = _get_alternate_protocol_uri("http://bloodhound.domain.lab:8080")
        assert result == "https://bloodhound.domain.lab:8080"

    def test_with_ip_address(self):
        """Should handle IP addresses"""
        result = _get_alternate_protocol_uri("https://192.168.1.100:443")
        assert result == "http://192.168.1.100:443"

    def test_bolt_returns_none(self):
        """Should return None for bolt:// scheme (Legacy BloodHound)"""
        result = _get_alternate_protocol_uri("bolt://localhost:7687")
        assert result is None

    def test_unknown_scheme_returns_none(self):
        """Should return None for unknown schemes"""
        result = _get_alternate_protocol_uri("ftp://localhost:21")
        assert result is None


class TestBloodHoundConnectorGetUserProperties:
    """Tests for get_user_properties method - SID-first lookups."""

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, 'run_cypher_query')
    def test_query_by_sid_preferred(self, mock_query):
        """Should query by SID (objectid) when provided."""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"

        mock_query.return_value = {
            "data": {
                "nodes": {
                    "n1": {
                        "objectId": "S-1-5-21-123-456-789-1001",
                        "properties": {
                            "samaccountname": "adminuser",
                            "pwdlastset": 1735689600,
                            "lastlogon": 1735776000,
                            "admincount": True,
                            "enabled": True,
                            "domain": "CORP.LOCAL",
                        }
                    }
                }
            }
        }

        result = connector.get_user_properties("S-1-5-21-123-456-789-1001")

        assert result is not None
        assert result["sid"] == "S-1-5-21-123-456-789-1001"
        assert result["samaccountname"] == "adminuser"
        assert result["admincount"] is True
        # Verify SID query was used
        call_args = mock_query.call_args[0][0]
        assert "objectid" in call_args.lower()
        assert "S-1-5-21-123-456-789-1001" in call_args.upper()

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, 'run_cypher_query')
    def test_query_by_upn(self, mock_query):
        """Should query by UPN when @ is present."""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"

        mock_query.return_value = {
            "data": {
                "nodes": {
                    "n1": {
                        "objectId": "S-1-5-21-123-456-789-1001",
                        "properties": {
                            "samaccountname": "admin",
                            "pwdlastset": 1735689600,
                            "domain": "CORP.LOCAL",
                        }
                    }
                }
            }
        }

        result = connector.get_user_properties("admin@corp.local")

        assert result is not None
        # Verify UPN query was used (toLower(u.name))
        call_args = mock_query.call_args[0][0]
        assert "u.name" in call_args.lower()

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, 'run_cypher_query')
    def test_query_by_domain_user(self, mock_query):
        """Should query by domain+sam when DOMAIN\\user format."""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"

        mock_query.return_value = {
            "data": {
                "nodes": {
                    "n1": {
                        "objectId": "S-1-5-21-123-456-789-1001",
                        "properties": {
                            "samaccountname": "admin",
                            "pwdlastset": 1735689600,
                            "domain": "CORP.LOCAL",
                        }
                    }
                }
            }
        }

        result = connector.get_user_properties("CORP\\admin")

        assert result is not None
        # Verify both domain and sam are in query
        call_args = mock_query.call_args[0][0]
        assert "samaccountname" in call_args.lower()
        assert "domain" in call_args.lower()
        assert "CORP" in call_args.upper()

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, 'run_cypher_query')
    def test_plain_username_uses_limit(self, mock_query):
        """Plain username query should use LIMIT 1 due to cross-domain risk."""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"

        mock_query.return_value = {"data": {"nodes": {}}}

        connector.get_user_properties("admin")

        # Verify LIMIT 1 is used for plain username (ambiguous)
        call_args = mock_query.call_args[0][0]
        assert "LIMIT 1" in call_args

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, 'run_cypher_query')
    def test_returns_none_when_not_found(self, mock_query):
        """Should return None when user not found."""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"

        mock_query.return_value = {"data": {"nodes": {}}}

        result = connector.get_user_properties("S-1-5-21-123-456-789-9999")

        assert result is None

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, 'run_cypher_query')
    def test_handles_exception(self, mock_query):
        """Should handle exceptions gracefully."""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"

        mock_query.side_effect = Exception("Connection error")

        result = connector.get_user_properties("S-1-5-21-123-456-789-1001")

        assert result is None
