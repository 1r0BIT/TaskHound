"""
Test suite for BloodHound API utility functions.

Tests cover:
- bhce_signed_request function
- get_bloodhound_token function
"""

import base64
from unittest.mock import MagicMock, patch

import pytest

from taskhound.utils.bh_api import (
    bhce_signed_request,
    get_bloodhound_token,
)

# ============================================================================
# Test: bhce_signed_request
# ============================================================================


class TestBhceSignedRequest:
    """Tests for bhce_signed_request function"""

    @patch('taskhound.utils.bh_api.requests.request')
    @patch('taskhound.utils.bh_api.datetime.datetime')
    def test_basic_get_request(self, mock_datetime, mock_request):
        """Should make a signed GET request"""
        mock_now = MagicMock()
        mock_now.isoformat.return_value = "2024-01-15T10:30:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        mock_response = MagicMock()
        mock_request.return_value = mock_response

        result = bhce_signed_request(
            method="GET",
            uri="/api/version",
            base_url="https://bloodhound.example.com",
            api_key="secret_api_key",
            api_key_id="key_id_123"
        )

        assert result == mock_response
        mock_request.assert_called_once()
        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["method"] == "GET"
        assert call_kwargs["url"] == "https://bloodhound.example.com/api/version"
        assert "bhesignature key_id_123" in call_kwargs["headers"]["Authorization"]

    @patch('taskhound.utils.bh_api.requests.request')
    @patch('taskhound.utils.bh_api.datetime.datetime')
    def test_post_with_body(self, mock_datetime, mock_request):
        """Should sign POST request with body"""
        mock_now = MagicMock()
        mock_now.isoformat.return_value = "2024-01-15T10:30:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        mock_response = MagicMock()
        mock_request.return_value = mock_response

        body = b'{"query": "test"}'
        result = bhce_signed_request(
            method="POST",
            uri="/api/cypher",
            base_url="https://bloodhound.example.com",
            api_key="secret_api_key",
            api_key_id="key_id_123",
            body=body
        )

        assert result == mock_response
        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["data"] == body

    @patch('taskhound.utils.bh_api.requests.request')
    @patch('taskhound.utils.bh_api.datetime.datetime')
    def test_correct_headers_set(self, mock_datetime, mock_request):
        """Should set correct headers for HMAC auth"""
        mock_now = MagicMock()
        mock_now.isoformat.return_value = "2024-01-15T10:30:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        mock_request.return_value = MagicMock()

        bhce_signed_request(
            method="GET",
            uri="/api/version",
            base_url="https://bh.local",
            api_key="test_key",
            api_key_id="test_id"
        )

        call_kwargs = mock_request.call_args[1]
        headers = call_kwargs["headers"]

        assert headers["Authorization"] == "bhesignature test_id"
        assert headers["RequestDate"] == "2024-01-15T10:30:00+00:00"
        assert "Signature" in headers
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"

    @patch('taskhound.utils.bh_api.requests.request')
    @patch('taskhound.utils.bh_api.datetime.datetime')
    def test_custom_timeout(self, mock_datetime, mock_request):
        """Should use custom timeout"""
        mock_now = MagicMock()
        mock_now.isoformat.return_value = "2024-01-15T10:30:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        mock_request.return_value = MagicMock()

        bhce_signed_request(
            method="GET",
            uri="/api/version",
            base_url="https://bh.local",
            api_key="test_key",
            api_key_id="test_id",
            timeout=60
        )

        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["timeout"] == 60

    @patch('taskhound.utils.bh_api.requests.request')
    @patch('taskhound.utils.bh_api.datetime.datetime')
    def test_signature_is_base64_encoded(self, mock_datetime, mock_request):
        """Should produce base64 encoded signature"""
        mock_now = MagicMock()
        mock_now.isoformat.return_value = "2024-01-15T10:30:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        mock_request.return_value = MagicMock()

        bhce_signed_request(
            method="GET",
            uri="/api/version",
            base_url="https://bh.local",
            api_key="test_key",
            api_key_id="test_id"
        )

        call_kwargs = mock_request.call_args[1]
        signature = call_kwargs["headers"]["Signature"]

        # Should be valid base64
        try:
            decoded = base64.b64decode(signature)
            assert len(decoded) == 32  # SHA256 produces 32 bytes
        except Exception:
            pytest.fail("Signature is not valid base64")


# ============================================================================
# Test: get_bloodhound_token
# ============================================================================


class TestGetBloodhoundToken:
    """Tests for get_bloodhound_token function"""

    @patch('taskhound.utils.bh_api.requests.post')
    def test_successful_login(self, mock_post):
        """Should return session token on successful login"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "session_token": "token123abc"
            }
        }
        mock_post.return_value = mock_response

        result = get_bloodhound_token(
            base_url="https://bh.local",
            username="admin",
            password="password123"
        )

        assert result == "token123abc"
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://bh.local/api/v2/login"

    @patch('taskhound.utils.bh_api.requests.post')
    def test_correct_login_payload(self, mock_post):
        """Should send correct login payload"""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"session_token": "tok"}}
        mock_post.return_value = mock_response

        get_bloodhound_token(
            base_url="https://bh.local",
            username="testuser",
            password="testpass"
        )

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["json"]["login_method"] == "secret"
        assert call_kwargs["json"]["username"] == "testuser"
        assert call_kwargs["json"]["secret"] == "testpass"

    @patch('taskhound.utils.bh_api.requests.post')
    def test_raises_on_http_error(self, mock_post):
        """Should raise on HTTP error"""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = Exception("401 Unauthorized")
        mock_post.return_value = mock_response

        with pytest.raises(Exception) as exc_info:
            get_bloodhound_token(
                base_url="https://bh.local",
                username="admin",
                password="wrong"
            )

        assert "401" in str(exc_info.value)

    @patch('taskhound.utils.bh_api.requests.post')
    def test_raises_on_invalid_response_missing_data(self, mock_post):
        """Should raise ValueError on invalid response format"""
        mock_response = MagicMock()
        mock_response.json.return_value = {"error": "something"}
        mock_post.return_value = mock_response

        with pytest.raises(ValueError) as exc_info:
            get_bloodhound_token(
                base_url="https://bh.local",
                username="admin",
                password="pass"
            )

        assert "missing session_token" in str(exc_info.value)

    @patch('taskhound.utils.bh_api.requests.post')
    def test_raises_on_invalid_response_missing_token(self, mock_post):
        """Should raise ValueError when session_token missing"""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"other": "value"}}
        mock_post.return_value = mock_response

        with pytest.raises(ValueError) as exc_info:
            get_bloodhound_token(
                base_url="https://bh.local",
                username="admin",
                password="pass"
            )

        assert "missing session_token" in str(exc_info.value)

    @patch('taskhound.utils.bh_api.requests.post')
    def test_custom_timeout(self, mock_post):
        """Should use custom timeout"""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"session_token": "tok"}}
        mock_post.return_value = mock_response

        get_bloodhound_token(
            base_url="https://bh.local",
            username="admin",
            password="pass",
            timeout=120
        )

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["timeout"] == 120


# ============================================================================
# Test: enumerate_computers_from_bloodhound
# ============================================================================


class TestEnumerateComputersFromBloodhound:
    """Tests for enumerate_computers_from_bloodhound function"""

    @patch('taskhound.utils.bh_api.requests.post')
    def test_basic_enumeration(self, mock_post):
        """Should enumerate computers with include_properties=true"""
        from taskhound.utils.bh_api import enumerate_computers_from_bloodhound

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "nodes": {
                    "1": {
                        "properties": {
                            "name": "SERVER01.DOMAIN.COM",
                            "objectid": "S-1-5-21-1234-5678",
                            "enabled": True,
                            "pwdlastset": 1734567890,
                            "operatingsystem": "WINDOWS SERVER 2019",
                            "lastlogontimestamp": 1734500000,
                            "lastseen": "2024-12-18T14:27:00Z",
                            "lastcollected": "2024-12-18T14:27:00Z",
                            "distinguishedname": "CN=SERVER01,OU=Servers,DC=domain,DC=com",
                            "samaccountname": "SERVER01$",
                        }
                    },
                    "2": {
                        "properties": {
                            "name": "WORKSTATION01.DOMAIN.COM",
                            "objectid": "S-1-5-21-1234-5679",
                            "enabled": False,
                            "pwdlastset": 1704567890,
                            "operatingsystem": "WINDOWS 11",
                        }
                    }
                }
            }
        }
        mock_post.return_value = mock_response

        computers = enumerate_computers_from_bloodhound(
            base_url="http://localhost:8080",
            token="test_token",
        )

        assert len(computers) == 2
        assert computers[0]["name"] == "SERVER01.DOMAIN.COM"
        assert computers[0]["enabled"] is True
        assert computers[0]["pwdlastset"] == 1734567890
        assert computers[1]["enabled"] is False

        # Verify the API call
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["json"]["query"] == "MATCH (c:Computer) RETURN c"
        assert call_kwargs["json"]["include_properties"] is True

    @patch('taskhound.utils.bh_api.requests.post')
    def test_empty_result(self, mock_post):
        """Should handle empty result"""
        from taskhound.utils.bh_api import enumerate_computers_from_bloodhound

        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"nodes": {}}}
        mock_post.return_value = mock_response

        computers = enumerate_computers_from_bloodhound(
            base_url="http://localhost:8080",
            token="test_token",
        )

        assert computers == []

    @patch('taskhound.utils.bh_api.requests.post')
    def test_raises_on_invalid_response(self, mock_post):
        """Should raise ValueError on invalid response"""
        from taskhound.utils.bh_api import enumerate_computers_from_bloodhound

        mock_response = MagicMock()
        mock_response.json.return_value = {"error": "invalid query"}
        mock_post.return_value = mock_response

        with pytest.raises(ValueError) as exc_info:
            enumerate_computers_from_bloodhound(
                base_url="http://localhost:8080",
                token="test_token",
            )

        assert "missing nodes" in str(exc_info.value)


# ============================================================================
# Test: get_bloodhound_data_age
# ============================================================================


class TestGetBloodhoundDataAge:
    """Tests for get_bloodhound_data_age function"""

    def test_calculates_age_from_lastseen(self):
        """Should calculate age from lastseen timestamp"""
        from datetime import datetime, timedelta, timezone

        from taskhound.utils.bh_api import get_bloodhound_data_age

        # Create a timestamp from 5 days ago
        now = datetime.now(timezone.utc)
        five_days_ago = now - timedelta(days=5)
        ts_str = five_days_ago.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        computers = [
            {"lastseen": ts_str, "lastcollected": ""},
        ]

        age_days, newest = get_bloodhound_data_age(computers)
        # Allow for small variations due to test timing
        assert 4 <= age_days <= 6
        assert newest == ts_str

    def test_handles_empty_list(self):
        """Should return 0 for empty list"""
        from taskhound.utils.bh_api import get_bloodhound_data_age

        age_days, newest = get_bloodhound_data_age([])
        assert age_days == 0
        assert newest == ""

    def test_handles_missing_timestamps(self):
        """Should handle computers without timestamps"""
        from taskhound.utils.bh_api import get_bloodhound_data_age

        computers = [
            {"name": "SERVER01", "lastseen": "", "lastcollected": None},
            {"name": "SERVER02"},
        ]

        age_days, newest = get_bloodhound_data_age(computers)
        assert age_days == 0
        assert newest == ""

    def test_handles_nanosecond_timestamps(self):
        """Should handle nanosecond precision in timestamps"""
        from taskhound.utils.bh_api import get_bloodhound_data_age

        # BloodHound uses nanosecond precision
        computers = [
            {"lastseen": "2024-12-18T14:27:00.320042793Z"},
        ]

        age_days, newest = get_bloodhound_data_age(computers)
        # Just verify it doesn't crash and returns a reasonable value
        assert age_days >= 0
        assert newest == "2024-12-18T14:27:00.320042793Z"
