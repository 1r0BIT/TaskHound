import json

import requests

from .bh_api import bhce_signed_request, get_bloodhound_token
from .logging import debug, warn


class BloodHoundAuthenticator:
    """
    Helper class to handle BloodHound CE authentication and requests.
    Supports both API Key (HMAC) and Username/Password (Bearer Token) authentication.
    """

    def __init__(
        self,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
        api_key_id: str | None = None,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.timeout = timeout
        self._token: str | None = None

    def get_token(self) -> str | None:
        """
        Get a session token using username/password.
        Returns None if authentication fails or if using API key.
        """
        if self.api_key and self.api_key_id:
            return None  # API key doesn't use session tokens

        if self._token:
            return self._token

        if not self.username or not self.password:
            warn("Missing credentials for BloodHound authentication")
            return None

        try:
            self._token = get_bloodhound_token(self.base_url, self.username, self.password, self.timeout)
            debug(f"Successfully authenticated to BloodHound at {self.base_url}")
            return self._token
        except requests.Timeout:
            warn("Timeout authenticating to BloodHound")
        except requests.RequestException as e:
            warn(f"Network error during authentication: {e}")
        except (KeyError, ValueError) as e:
            warn(f"Invalid authentication response from BloodHound: {e}")
        except Exception as e:
            warn(f"Unexpected authentication error: {e}")

        return None

    def request(
        self, method: str, endpoint: str, body: dict | bytes | None = None, headers: dict | None = None
    ) -> requests.Response | None:
        """
        Make an authenticated request to BloodHound CE.
        Automatically handles API Key signing or Bearer Token injection.
        """
        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"

        # Prepare body
        body_bytes = None
        if isinstance(body, dict):
            body_bytes = json.dumps(body, separators=(",", ":")).encode()
        elif isinstance(body, bytes):
            body_bytes = body
        elif isinstance(body, str):
            body_bytes = body.encode()

        try:
            # Strategy 1: API Key (HMAC)
            if self.api_key and self.api_key_id:
                return bhce_signed_request(
                    method, endpoint, self.base_url, self.api_key, self.api_key_id, body_bytes, self.timeout
                )

            # Strategy 2: Username/Password (Bearer Token)
            token = self.get_token()
            if not token:
                return None

            final_headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            if headers:
                final_headers.update(headers)

            return requests.request(
                method=method,
                url=f"{self.base_url}{endpoint}",
                headers=final_headers,
                data=body_bytes,
                timeout=self.timeout,
            )

        except Exception as e:
            warn(f"Error during BloodHound request to {endpoint}: {e}")
            return None
