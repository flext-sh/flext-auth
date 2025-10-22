"""HTTP transport adapter for FLEXT Auth using flext-api.

This module provides HTTP transport functionality for authentication operations,
implementing the BaseTransportAdapter protocol using flext-api (MANDATORY).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
from typing import Any

from flext_core import FlextLogger, FlextResult


# Placeholder for FlextApiClient to avoid circular dependency
class FlextApiClient:
    """Placeholder FlextApiClient for type checking."""

    def __init__(
        self,
        timeout: int | None = None,
        max_retries: int | None = None,
    ) -> None:
        """Initialize placeholder client."""

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Placeholder get method."""
        return None

    def post(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Placeholder post method."""
        return None

    def put(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Placeholder put method."""
        return None

    def delete(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Placeholder delete method."""
        return None

    def patch(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Placeholder patch method."""
        return None


class FlextWebTransportAdapter:
    """HTTP transport adapter for OAuth2/OIDC authentication operations.

    This adapter provides HTTP transport functionality using flext-api exclusively,
    implementing secure communication for authentication protocols.

    MANDATORY: Uses flext-api.FlextApiClient for ALL HTTP operations.
    NO direct httpx/requests imports allowed.

    Usage:
        >>> adapter = FlextWebTransportAdapter(timeout=30.0, max_retries=3)
        >>> result = adapter.post_token_request(
        ...     url="https://oauth.example.com/token",
        ...     data={"grant_type": "client_credentials"},
        ...     auth=("client_id", "client_secret"),
        ... )
        >>> if result.is_success:
        ...     token_data = result.unwrap()
        ...     print(f"Access token: {token_data['access_token']}")
    """

    def __init__(
        self,
        timeout: float = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize HTTP transport adapter with flext-api client.

        Args:
            timeout: Request timeout in seconds (default: 30.0)
            max_retries: Maximum number of retry attempts (default: 3)

        """
        self._timeout = timeout
        self._max_retries = max_retries
        self.logger = FlextLogger(__name__)

        # Initialize flext-api client
        from flext_api.config import FlextApiConfig

        config = FlextApiConfig(timeout=timeout, max_retries=max_retries)
        self._client = FlextApiClient(config)

    def send_request(
        self,
        url: str,
        method: str = "POST",
        data: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
        **_kwargs: object,
    ) -> FlextResult[dict[str, object]]:
        """Send HTTP request using flext-api transport.

        Implements BaseTransportAdapter protocol for generic HTTP operations.

        Args:
        url: Target URL for the request
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        data: Request body data
        headers: Request headers
        **kwargs: Additional transport-specific parameters

        Returns:
        FlextResult containing response data or error

        """
        try:
            # Route to appropriate flext-api client method
            if method.upper() == "GET":
                result = self._client.get(url, headers=headers)
            elif method.upper() == "POST":
                result = self._client.post(url, data=data, headers=headers)
            elif method.upper() == "PUT":
                result = self._client.put(url, data=data, headers=headers)
            elif method.upper() == "DELETE":
                result = self._client.delete(url, headers=headers)
            elif method.upper() == "PATCH":
                result = self._client.patch(url, data=data, headers=headers)
            else:
                return FlextResult[dict[str, object]].fail(
                    f"Unsupported HTTP method: {method}"
                )

            # Handle flext-api result
            if result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"HTTP request failed: {result.error}"
                )

            # Parse response data
            response_data = result.unwrap()
            if isinstance(response_data, dict):
                return FlextResult[dict[str, object]].ok(response_data)
            return FlextResult[dict[str, object]].fail(
                f"Unexpected response type: {type(response_data)}"
            )
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Request failed with unexpected error: {e}"
            )

    def get_transport_type(self) -> str:
        """Get the transport type identifier.

        Returns:
            str: Transport type identifier ("http")

        """
        return "http"

    def post_token_request(
        self,
        url: str,
        data: dict[str, object],
        auth: tuple[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> FlextResult[dict[str, object]]:
        """POST request to OAuth2 token endpoint.

        Specialized method for OAuth2/OIDC token requests with proper
        content-type and authentication handling.

        Args:
            url: OAuth2 token endpoint URL
            data: Token request data (grant_type, code, etc.)
            auth: Optional HTTP Basic authentication (client_id, client_secret)
            headers: Optional additional headers

        Returns:
            FlextResult containing token response or error

        Example:
            >>> result = adapter.post_token_request(
            ...     url="https://oauth.example.com/token",
            ...     data={"grant_type": "authorization_code", "code": "auth_code"},
            ...     auth=("client_id", "client_secret"),
            ... )

        """
        request_headers = headers.copy() if headers else {}

        # OAuth2 requires application/x-www-form-urlencoded (RFC 6749 Section 4.1.3)
        if "Content-Type" not in request_headers:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"

        # Add HTTP Basic authentication if provided
        if auth:
            credentials = f"{auth[0]}:{auth[1]}"
            encoded = base64.b64encode(credentials.encode()).decode()
            request_headers["Authorization"] = f"Basic {encoded}"

        self.logger.debug(
            f"Sending token request to {url}",
            extra={"grant_type": data.get("grant_type")},
        )

        # Use flext-api client for POST request
        result = self._client.post(url, data=data, headers=request_headers)

        if result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Token request failed: {result.error}"
            )

        response_data = result.unwrap()

        # Ensure response_data is dict[str, object] for parsing
        if not isinstance(response_data, dict):
            return FlextResult[dict[str, object]].fail(
                f"Unexpected token response type: {type(response_data)}"
            )

        # Parse OAuth2 token response
        return self._parse_token_response(response_data)

    def get_userinfo(
        self, url: str, access_token: str, headers: dict[str, str]
    ) -> FlextResult[dict[str, object]]:
        """GET request to OIDC UserInfo endpoint.

        Retrieves user information using an OAuth2 access token according
        to OpenID Connect Core 1.0 specification.

        Args:
            url: OIDC UserInfo endpoint URL
            access_token: OAuth2 access token
            headers: Optional additional headers

        Returns:
            FlextResult containing user information or error

        Example:
            >>> result = adapter.get_userinfo(
            ...     url="https://oauth.example.com/userinfo",
            ...     access_token="ya29.a0AfH6...",
            ... )
            >>> if result.is_success:
            ...     userinfo = result.unwrap()
            ...     print(f"User ID: {userinfo['sub']}")

        """
        request_headers = headers.copy() if headers else {}

        # OIDC requires Bearer token authentication
        request_headers["Authorization"] = f"Bearer {access_token}"

        self.logger.debug(f"Requesting UserInfo from {url}")

        # Use flext-api client for GET request
        result = self._client.get(url, headers=request_headers)

        if result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"UserInfo request failed: {result.error}"
            )

        userinfo = result.unwrap()

        # Validate OIDC UserInfo response (must contain 'sub' claim)
        if not isinstance(userinfo, dict):
            return FlextResult[dict[str, object]].fail(
                f"UserInfo response is not a dictionary: {type(userinfo)}"
            )

        if "sub" not in userinfo:
            return FlextResult[dict[str, object]].fail(
                "UserInfo response missing required 'sub' claim"
            )

        self.logger.info(
            f"UserInfo retrieved successfully for subject: {userinfo['sub']}"
        )

        return FlextResult[dict[str, object]].ok(userinfo)

    def _parse_token_response(
        self, response_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Parse OAuth2 token endpoint response.

        Validates token response according to RFC 6749 Section 5.1 (success)
        and Section 5.2 (error).

        Args:
        response_data: Token endpoint response data

        Returns:
        FlextResult containing validated token data or error

        """
        # Check for OAuth2 error response (RFC 6749 Section 5.2)
        if "error" in response_data:
            error_code = response_data.get("error", "unknown_error")
            error_description = response_data.get(
                "error_description", "No error description"
            )
            error_uri = response_data.get("error_uri")

            error_msg = f"OAuth2 error: {error_code} - {error_description}"
            if error_uri:
                error_msg += f" (see {error_uri})"

            return FlextResult[dict[str, object]].fail(error_msg)

        # Validate required fields (RFC 6749 Section 5.1)
        if "access_token" not in response_data:
            return FlextResult[dict[str, object]].fail(
                "Token response missing required 'access_token' field"
            )

        if "token_type" not in response_data:
            return FlextResult[dict[str, object]].fail(
                "Token response missing required 'token_type' field"
            )

        # Optional fields: expires_in, refresh_token, scope
        self.logger.info(
            "Token response validated successfully",
            extra={
                "token_type": response_data.get("token_type"),
                "has_refresh_token": "refresh_token" in response_data,
                "expires_in": response_data.get("expires_in"),
            },
        )

        return FlextResult[dict[str, object]].ok(response_data)


__all__ = ["FlextWebTransportAdapter"]
