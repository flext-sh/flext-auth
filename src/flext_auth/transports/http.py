"""HTTP transport adapter for FLEXT Auth using flext-api.

This module provides HTTP transport functionality for authentication operations,
implementing the BaseTransportAdapter protocol using flext-api (MANDATORY).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
import json
from urllib.parse import urlencode

from flext_api import FlextApiClient, FlextApiModels, FlextApiSettings
from flext_api.typings import FlextApiTypes as t_api
from flext_core import r
from flext_core.loggings import FlextLogger


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
        ...     token_data = result.value
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

        config = FlextApiSettings(timeout=timeout, max_retries=max_retries)
        self._client = FlextApiClient(config)

    def send_request(
        self,
        url: str,
        method: str = "POST",
        data: t_api.Api.RequestBody | None = None,
        headers: dict[str, str] | None = None,
        query: t_api.Api.WebParams | None = None,
        timeout: float | None = None,
    ) -> r[t_api.Api.ResponseDict]:
        """Send HTTP request using flext-api transport.

        Implements BaseTransportAdapter protocol for generic HTTP operations.

        Args:
        url: Target URL for the request
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        data: Request body data
        headers: Request headers

        Returns:
        FlextResult containing response data or error

        """
        request_headers = headers if headers is not None else {}
        request_timeout = timeout if timeout is not None else self._timeout
        return self._execute_request(
            FlextApiModels.HttpRequest(
                method=method.upper(),
                url=url,
                headers=request_headers,
                body=self._resolve_body(method, data),
                query_params=self._resolve_query(method, data, query),
                timeout=request_timeout,
            ),
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
    ) -> r[dict[str, object]]:
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
            "Sending token request to %s",
            url,
            extra={"grant_type": data.get("grant_type")},
        )

        # Use flext-api client for POST request
        request_body = urlencode(data, doseq=True)
        response = self._execute_request(
            FlextApiModels.HttpRequest(
                method="POST",
                url=url,
                headers=request_headers,
                body=request_body,
                timeout=self._timeout,
            ),
        )

        return response.flat_map(self._parse_token_response)

    def get_userinfo(
        self,
        url: str,
        access_token: str,
        headers: dict[str, str],
    ) -> r[t_api.Api.ResponseDict]:
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
            ...     userinfo = result.value
            ...     print(f"User ID: {userinfo['sub']}")

        """
        request_headers = headers.copy() if headers else {}

        # OIDC requires Bearer token authentication
        request_headers["Authorization"] = f"Bearer {access_token}"

        self.logger.debug("Requesting UserInfo from %s", url)

        # Use flext-api client for GET request
        return self._execute_request(
            FlextApiModels.HttpRequest(
                method="GET",
                url=url,
                headers=request_headers,
                timeout=self._timeout,
            ),
        ).flat_map(self._validate_userinfo_response)

    def _parse_token_response(
        self,
        response_data: t_api.Api.ResponseDict,
    ) -> r[t_api.Api.ResponseDict]:
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
            error_code_value = response_data.get("error")
            if not isinstance(error_code_value, str) or not error_code_value:
                error_code = "unknown_error"
            else:
                error_code = error_code_value

            error_description_value = response_data.get("error_description")
            if (
                not isinstance(error_description_value, str)
                or not error_description_value
            ):
                error_description = "No error description"
            else:
                error_description = error_description_value

            error_uri = response_data.get("error_uri")

            error_msg = f"OAuth2 error: {error_code} - {error_description}"
            if error_uri:
                error_msg += f" (see {error_uri})"

            return r[dict[str, object]].fail(error_msg)

        # Validate required fields (RFC 6749 Section 5.1)
        if "access_token" not in response_data:
            return r[dict[str, object]].fail(
                "Token response missing required 'access_token' field",
            )

        if "token_type" not in response_data:
            return r[dict[str, object]].fail(
                "Token response missing required 'token_type' field",
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

        return r[t_api.Api.ResponseDict].ok(response_data)

    def _execute_request(
        self,
        request: FlextApiModels.HttpRequest,
    ) -> r[t_api.Api.ResponseDict]:
        response = self._client.request(request)
        if response.is_failure:
            return r[t_api.Api.ResponseDict].fail(response.error)

        http_response = response.value
        body = http_response.body

        if body is None:
            return r[t_api.Api.ResponseDict].ok({})

        if isinstance(body, dict):
            return r[t_api.Api.ResponseDict].ok(self._normalize_response_dict(body))

        if isinstance(body, (bytes, str)):
            decoded = (
                body.decode("utf-8", errors="replace")
                if isinstance(body, bytes)
                else body
            )
            try:
                parsed = json.loads(decoded)
            except json.JSONDecodeError:
                return r[t_api.Api.ResponseDict].fail(
                    "Unable to parse response body as JSON",
                )
            if isinstance(parsed, dict):
                return r[t_api.Api.ResponseDict].ok(
                    self._normalize_response_dict(parsed),
                )
            return r[t_api.Api.ResponseDict].fail(
                f"Unexpected parsed response type: {type(parsed)}",
            )

        return r[t_api.Api.ResponseDict].fail(
            f"Unsupported response body type: {type(body)}",
        )

    def _normalize_response_dict(
        self,
        payload: dict[str, object],
    ) -> t_api.Api.ResponseDict:
        return {str(key): value for key, value in payload.items()}

    def _resolve_body(
        self,
        method: str,
        data: t_api.Api.RequestBody | None,
    ) -> t_api.Api.RequestBody | None:
        if data is None:
            return None
        if method.upper() in {"GET", "DELETE"}:
            return None
        return data

    def _resolve_query(
        self,
        method: str,
        data: t_api.Api.RequestBody | None,
        query: t_api.Api.WebParams | None,
    ) -> t_api.Api.WebParams | None:
        if isinstance(data, dict) and method.upper() == "GET":
            query_dict = query if query is not None else {}
            merged_query = {**query_dict, **data}
            normalized: t_api.Api.WebParams = {}
            for key, value in merged_query.items():
                if isinstance(value, list):
                    normalized[str(key)] = [str(item) for item in value]
                else:
                    normalized[str(key)] = str(value)
            return normalized
        return query

    def _validate_userinfo_response(
        self,
        payload: t_api.Api.ResponseDict,
    ) -> r[t_api.Api.ResponseDict]:
        if "sub" not in payload:
            return r[t_api.Api.ResponseDict].fail(
                "UserInfo response missing required 'sub' claim",
            )

        self.logger.info(
            "UserInfo retrieved successfully",
            extra={"subject": payload["sub"]},
        )
        return r[t_api.Api.ResponseDict].ok(payload)


__all__ = ["FlextWebTransportAdapter"]
