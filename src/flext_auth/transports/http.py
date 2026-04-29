"""HTTP transport adapter for FLEXT Auth using flext-api.

This module provides HTTP transport functionality for authentication operations,
implementing the BaseTransportAdapter protocol using flext-api (MANDATORY).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
from collections.abc import (
    Mapping,
    MutableMapping,
)
from urllib.parse import urlencode

from flext_api import FlextApiClient, FlextApiSettings

from flext_auth import c, m, p, r, t, u


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
        >>> if result.success:
        ...     token_data = result.value
        ...     print(f"Access token: {token_data['access_token']}")
    """

    def __init__(self, timeout: float = 30, max_retries: int = 3) -> None:
        """Initialize HTTP transport adapter with flext-api client.

        Args:
            timeout: Request timeout in seconds (default: 30.0)
            max_retries: Maximum number of retry attempts (default: 3)

        """
        self._timeout = timeout
        self._max_retries = max_retries
        self.logger = u.fetch_logger(__name__)
        settings = FlextApiSettings(timeout=timeout, max_retries=max_retries)
        self._client = FlextApiClient(settings=settings)

    def get_transport_type(self) -> str:
        """Get the transport type identifier.

        Returns:
            str: Transport type identifier ("http")

        """
        return "http"

    def get_userinfo(
        self,
        url: str,
        access_token: str,
        headers: t.StrMapping,
    ) -> p.Result[t.JsonMapping]:
        """GET request to OIDC UserInfo endpoint.

        Retrieves user information using an OAuth2 access token according
        to OpenID Connect Core 1.0 specification.

        Args:
            url: OIDC UserInfo endpoint URL
            access_token: OAuth2 access token
            headers: Optional additional headers

        Returns:
            r containing user information or error

        Example:
            >>> result = adapter.get_userinfo(
            ...     url="https://oauth.example.com/userinfo",
            ...     access_token="ya29.a0AfH6...",
            ... )
            >>> if result.success:
            ...     userinfo = result.value
            ...     print(f"User ID: {userinfo['sub']}")

        """
        request_headers = dict(headers) if headers else {}
        request_headers["Authorization"] = f"Bearer {access_token}"
        self.logger.debug("Requesting UserInfo from %s", url)
        return self._execute_request(
            m.Api.HttpRequest(
                method="GET",
                url=url,
                headers=request_headers,
                timeout=self._timeout,
            ),
        ).flat_map(self._validate_userinfo_response)

    def post_token_request(
        self,
        url: str,
        data: t.JsonMapping,
        auth: t.Pair[str, str] | None = None,
        headers: t.StrMapping | None = None,
    ) -> p.Result[t.JsonMapping]:
        """POST request to OAuth2 token endpoint.

        Specialized method for OAuth2/OIDC token requests with proper
        content-type and authentication handling.

        Args:
            url: OAuth2 token endpoint URL
            data: Token request data (grant_type, code, etc.)
            auth: Optional HTTP Basic authentication (client_id, client_secret)
            headers: Optional additional headers

        Returns:
            r containing token response or error

        Example:
            >>> result = adapter.post_token_request(
            ...     url="https://oauth.example.com/token",
            ...     data={"grant_type": "authorization_code", "code": "auth_code"},
            ...     auth=("client_id", "client_secret"),
            ... )

        """
        request_headers: t.MutableStrMapping = dict(headers) if headers else {}
        if "Content-Type" not in request_headers:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        if auth:
            credentials = f"{auth[0]}:{auth[1]}"
            encoded = base64.b64encode(credentials.encode()).decode()
            request_headers["Authorization"] = f"Basic {encoded}"
        self.logger.debug(
            "Sending token request to %s",
            url,
            grant_type=str(data.get("grant_type", "")),
        )
        request_body = urlencode(data, doseq=True)
        response = self._execute_request(
            m.Api.HttpRequest(
                method="POST",
                url=url,
                headers=request_headers,
                body=request_body,
                timeout=self._timeout,
            ),
        )
        return response.flat_map(self._parse_token_response)

    def send_request(
        self,
        url: str,
        method: str = "POST",
        data: t.Api.RequestBody | None = None,
        headers: t.StrMapping | None = None,
        **kwargs: t.Scalar,
    ) -> p.Result[t.JsonMapping]:
        """Send HTTP request using flext-api transport.

        Implements BaseTransportAdapter protocol for generic HTTP operations.

        Args:
        url: Target URL for the request
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        data: Request body data
        headers: Request headers
        **kwargs: Optional transport controls such as ``query`` and ``timeout``

        Returns:
        r containing response data or error

        """
        request_headers: t.StrMapping = dict(headers) if headers is not None else {}
        query_raw = kwargs.get("query")
        query = query_raw if isinstance(query_raw, Mapping) else None
        timeout_raw = kwargs.get("timeout")
        request_timeout = (
            float(timeout_raw)
            if isinstance(timeout_raw, (int, float))
            else self._timeout
        )
        resolved_body = self._resolve_body(method, data)
        resolved_query = self._resolve_query(method, data, query)
        request = m.Api.HttpRequest(
            method=method.upper(),
            url=url,
            headers=request_headers,
            timeout=request_timeout,
        )
        if resolved_body is not None:
            request = m.Api.HttpRequest(
                method=request.method,
                url=request.url,
                headers=request.headers,
                body=resolved_body,
                query_params=resolved_query or {},
                timeout=request.timeout,
            )
        elif resolved_query is not None:
            request = m.Api.HttpRequest(
                method=request.method,
                url=request.url,
                headers=request.headers,
                query_params=resolved_query,
                timeout=request.timeout,
            )
        return self._execute_request(request)

    def _execute_request(self, request: m.Api.HttpRequest) -> p.Result[t.JsonMapping]:
        response = self._client.request(request)
        if response.failure:
            return r[t.JsonMapping].fail(response.error)
        http_response = response.value
        body = http_response.body
        if body is None:
            return r[t.JsonMapping].ok(t.json_mapping_adapter().validate_python({}))
        if isinstance(body, Mapping):
            return r[t.JsonMapping].ok(
                t.json_mapping_adapter().validate_python(body),
            )
        match body:
            case bytes() as body_bytes:
                decoded = body_bytes.decode("utf-8", errors="replace")
            case str() as body_text:
                decoded = body_text
            case _:
                return r[t.JsonMapping].fail(
                    f"Unsupported response body type: {type(body)}",
                )
        try:
            parsed = t.json_mapping_adapter().validate_json(decoded)
            return r[t.JsonMapping].ok(parsed)
        except (ValueError, c.ValidationError):
            return r[t.JsonMapping].fail("Unable to parse response body as JSON")

    def _parse_token_response(
        self,
        response_data: t.JsonMapping,
    ) -> p.Result[t.JsonMapping]:
        """Parse OAuth2 token endpoint response.

        Validates token response according to RFC 6749 Section 5.1 (success)
        and Section 5.2 (error).

        Args:
        response_data: Token endpoint response data

        Returns:
        r containing validated token data or error

        """
        if "error" in response_data:
            error_code_value = response_data.get("error")
            match error_code_value:
                case str() as code if code:
                    error_code = code
                case _:
                    error_code = "unknown_error"
            error_description_value = response_data.get("error_description")
            match error_description_value:
                case str() as description if description:
                    error_description = description
                case _:
                    error_description = "No error description"
            error_uri = response_data.get("error_uri")
            error_msg = f"OAuth2 error: {error_code} - {error_description}"
            if error_uri:
                error_msg += f" (see {error_uri})"
            return r[t.JsonMapping].fail(error_msg)
        if "access_token" not in response_data:
            return r[t.JsonMapping].fail(
                "Token response missing required 'access_token' field",
            )
        if "token_type" not in response_data:
            return r[t.JsonMapping].fail(
                "Token response missing required 'token_type' field",
            )
        self.logger.info(
            "Token response validated successfully",
            token_type=str(response_data.get("token_type", "")),
            has_refresh_token="refresh_token" in response_data,
            expires_in=str(response_data.get("expires_in", "")),
        )
        return r[t.JsonMapping].ok(response_data)

    def _resolve_body(
        self,
        method: str,
        data: t.Api.RequestBody | None,
    ) -> t.Api.RequestBody | None:
        if data is None:
            return None
        if method.upper() in {"GET", "DELETE"}:
            return None
        return data

    def _resolve_query(
        self,
        method: str,
        data: t.Api.RequestBody | None,
        query: t.Api.WebParams | None,
    ) -> t.Api.WebParams | None:
        if isinstance(data, Mapping) and method.upper() == c.Api.Method.GET.value:
            data_mapping = dict(data.items())
            query_dict: t.Api.WebParams = query if query is not None else {}
            merged_query: t.Api.WebParams = {
                **query_dict,
                **{k: str(v) for k, v in data_mapping.items()},
            }
            normalized: MutableMapping[str, t.StrSequence | str] = {}
            for key, value in merged_query.items():
                match value:
                    case str() as string_value:
                        normalized[key] = string_value
                    case list() as list_value:
                        normalized[key] = list(list_value)
                    case tuple() as tuple_value:
                        normalized[key] = list(tuple_value)
                    case _:
                        normalized[key] = str(value)
            return normalized
        return query

    def _validate_userinfo_response(
        self,
        payload: t.JsonMapping,
    ) -> p.Result[t.JsonMapping]:
        if "sub" not in payload:
            return r[t.JsonMapping].fail(
                "UserInfo response missing required 'sub' claim",
            )
        self.logger.info(
            "UserInfo retrieved successfully",
            subject=str(payload.get("sub", "")),
        )
        return r[t.JsonMapping].ok(payload)


__all__: t.MutableSequenceOf[str] = ["FlextWebTransportAdapter"]
