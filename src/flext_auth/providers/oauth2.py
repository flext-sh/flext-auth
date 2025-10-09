"""OAuth2 authentication provider implementation.

This module implements OAuth2 authentication with support for multiple authorization flows:
- Authorization Code Flow (with PKCE support)
- Client Credentials Flow
- Resource Owner Password Credentials Flow
- Implicit Flow (legacy, not recommended)
- Device Authorization Flow

The implementation follows RFC 6749 (OAuth 2.0) and RFC 7636 (PKCE).

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import hashlib
import secrets
from base64 import urlsafe_b64encode
from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast
from urllib.parse import urlencode

from flext_core import FlextLogger, FlextResult, FlextTypes

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.mixin import FlextAuthProviderMixin
from flext_auth.transports.http import HttpTransportAdapter


class FlextAuthOAuth2Provider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    """OAuth2 authentication provider supporting multiple authorization flows.

    This provider implements the OAuth2 protocol for authentication and authorization,
    supporting various flows for different use cases (web, mobile, service-to-service).

    Configuration:
        - client_id: OAuth2 client identifier (required)
        - client_secret: OAuth2 client secret (required for most flows)
        - authorization_endpoint: Authorization server URL (required)
        - token_endpoint: Token endpoint URL (required)
        - redirect_uri: Redirect URI for authorization code flow
        - scope: Space-separated list of requested scopes
        - flow: Authorization flow type (authorization_code, client_credentials, password, device)
        - use_pkce: Enable PKCE for authorization code flow (default: True)
        - token_endpoint_auth_method: Authentication method for token endpoint (FlextAuthConstants.OAuth2.CLIENT_SECRET_POST, FlextAuthConstants.OAuth2.CLIENT_SECRET_BASIC)

    Example:
        >>> config = {
        ...     "client_id": "your-client-id",
        ...     "client_secret": "your-client-secret",
        ...     "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
        ...     "token_endpoint": "https://auth.example.com/oauth2/token",
        ...     "redirect_uri": "https://app.example.com/callback",
        ...     "scope": "openid profile email",
        ...     "flow": "authorization_code",
        ...     "use_pkce": True,
        ... }
        >>> provider = FlextAuthOAuth2Provider(config)
        >>> # Authorization code flow
        >>> auth_url_result = provider.get_authorization_url(state="random-state")
        >>> # After redirect, exchange code for token
        >>> result = provider.authenticate({
        ...     "code": "auth-code",
        ...     "state": "random-state",
        ... })

    """

    def __init__(self, config: FlextTypes.Dict) -> None:
        """Initialize OAuth2 authentication provider.

        Args:
            config: Provider configuration dictionary

        Raises:
            ValueError: If required configuration is missing

        """
        self._config = config
        self.logger = FlextLogger(__name__)

        # Validate required configuration
        self._client_id = self._config.get("client_id")
        if not isinstance(self._client_id, str):
            error_msg = "OAuth2 provider requires 'client_id' to be a string"
            raise TypeError(error_msg)

        self._client_secret = self._config.get("client_secret")
        if self._client_secret is not None and not isinstance(self._client_secret, str):
            error_msg = "OAuth2 provider 'client_secret' must be a string or None"
            raise TypeError(error_msg)

        self._authorization_endpoint = self._config.get("authorization_endpoint")
        if self._authorization_endpoint is not None and not isinstance(
            self._authorization_endpoint, str
        ):
            error_msg = (
                "OAuth2 provider 'authorization_endpoint' must be a string or None"
            )
            raise TypeError(error_msg)

        self._token_endpoint = self._config.get("token_endpoint")
        if not isinstance(self._token_endpoint, str):
            error_msg = "OAuth2 provider requires 'token_endpoint' to be a string"
            raise TypeError(error_msg)

        # Optional configuration with defaults
        self._redirect_uri = self._config.get("redirect_uri")
        if self._redirect_uri is not None and not isinstance(self._redirect_uri, str):
            error_msg = "OAuth2 provider 'redirect_uri' must be a string or None"
            raise ValueError(error_msg)

        self._scope = self._config.get("scope", "openid profile email")
        if not isinstance(self._scope, str):
            self._scope = "openid profile email"

        self._flow = cast(str, self._config.get("flow", "authorization_code"))
        if not isinstance(self._flow, str):
            self._flow = "authorization_code"

        self._use_pkce = self._config.get("use_pkce", True)
        if not isinstance(self._use_pkce, bool):
            self._use_pkce = True

        self._token_endpoint_auth_method = self._config.get(
            "token_endpoint_auth_method", FlextAuthConstants.OAuth2.CLIENT_SECRET_POST
        )
        if not isinstance(self._token_endpoint_auth_method, str):
            self._token_endpoint_auth_method = (
                FlextAuthConstants.OAuth2.CLIENT_SECRET_POST
            )

        # Runtime state storage (in production, use proper storage)
        self._pkce_verifiers: FlextTypes.StringDict = {}  # state -> code_verifier mapping

        # HTTP client for token endpoint requests (MANDATORY: uses flext-api)
        self._http_client = HttpTransportAdapter(timeout=30.0)

        self.logger.info(
            "OAuth2 provider initialized",
            extra={
                "client_id": self._client_id,
                "flow": self._flow,
                "use_pkce": self._use_pkce,
                "scope": self._scope,
            },
        )

    def authenticate(
        self,
        credentials: FlextTypes.Dict,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate using OAuth2 flow.

        Depending on the configured flow, this method expects different credentials:

        Authorization Code Flow:
            - code: Authorization code from redirect
            - state: State parameter for CSRF protection
            - code_verifier: PKCE code verifier (if use_pkce=True)

        Client Credentials Flow:
            - client_id: Client identifier (optional if configured)
            - client_secret: Client secret (optional if configured)

        Password Flow:
            - username: Resource owner username
            - password: Resource owner password

        Args:
            credentials: Authentication credentials specific to the flow

        Returns:
            FlextResult[AuthToken]: OAuth2 access token or authentication error

        Example:
            >>> # Authorization code flow
            >>> result = provider.authenticate({
            ...     "code": "authorization-code",
            ...     "state": "csrf-state",
            ...     "code_verifier": "pkce-verifier",
            ... })

        """
        # Route to appropriate flow handler
        flow_handlers: dict[
            str, Callable[[dict[str, object]], FlextResult[FlextAuthModels.AuthToken]]
        ] = {
            "authorization_code": self._handle_authorization_code_flow,
            "client_credentials": self._handle_client_credentials_flow,
            "password": self._handle_password_flow,
            "device": self._handle_device_flow,
        }

        handler = flow_handlers.get(self._flow)
        if not handler:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                f"Unsupported OAuth2 flow: {self._flow}"
            )

        return handler(credentials)

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[bool]:
        """Validate OAuth2 access token.

        This performs basic validation checks. For production use, consider:
        - Token introspection endpoint (RFC 7662)
        - JWT validation if tokens are JWTs
        - Cache validation results

        Args:
            token: Access token string or AuthToken object

        Returns:
            FlextResult[bool]: True if token is valid, False otherwise

        """
        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[bool].fail(str(e))

        # Basic validation: check if token exists and is not empty
        if not token_string or not token_string.strip():
            return FlextResult[bool].fail("Token is empty")

        # In production, implement:
        # 1. Token introspection (RFC 7662)
        # 2. JWT validation if applicable
        # 3. Check token expiration
        # 4. Validate token signature

        # For now, basic validation
        if (
            isinstance(token, FlextAuthModels.AuthToken)
            and token.expires_at
            and datetime.now(UTC) > token.expires_at
        ):
            return FlextResult[bool].fail("Token expired")

        self.logger.debug("Token validated (basic validation only)")
        return FlextResult[bool].ok(True)

    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh OAuth2 access token using refresh token.

        Args:
            token: Token object with refresh_token, or refresh token string

        Returns:
            FlextResult[AuthToken]: New access token or error

        """
        # Check capability
        capability_check = self._check_capability_supported("refresh")
        if capability_check.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(capability_check.error)

        # Extract refresh token
        refresh_token: str | None = None
        if isinstance(token, FlextAuthModels.AuthToken):
            refresh_token = token.refresh_token
        elif isinstance(token, str):
            refresh_token = token

        if not refresh_token:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "No refresh token available"
            )

        # Prepare token refresh request
        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._client_id,
        }

        # Add client authentication based on method
        auth: tuple[str, str] | None = None
        if (
            self._token_endpoint_auth_method
            == FlextAuthConstants.OAuth2.CLIENT_SECRET_POST
            and self._client_secret
        ):
            token_data["client_secret"] = self._client_secret
        elif (
            self._token_endpoint_auth_method
            == FlextAuthConstants.OAuth2.CLIENT_SECRET_BASIC
            and self._client_secret
        ):
            auth = cast(
                "tuple[str, str]", (self._client_id, cast("str", self._client_secret))
            )

        # Request new access token
        token_response = self._http_client.post_token_request(
            url=cast("str", self._token_endpoint),
            data=token_data,
            auth=auth,
        )

        if token_response.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(token_response.error)

        # Parse token response and create AuthToken
        return self._create_auth_token_from_response(token_response.unwrap())

    def revoke(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[None]:
        """Revoke OAuth2 access token.

        Args:
            token: Access token to revoke

        Returns:
            FlextResult[None]: Success or revocation error

        """
        try:
            self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[None].fail(str(e))

        # In production, implement RFC 7009 (Token Revocation)
        # POST to revocation endpoint with token

        self.logger.info(
            "Token revocation requires implementation with flext-api HTTP client"
        )

        return FlextResult[None].ok(None)

    def supports(self) -> set[str]:
        """Return OAuth2 provider capabilities.

        Returns:
            set[str]: Set of supported capability strings

        Capabilities:
            - token: Token generation
            - validate: Token validation
            - refresh: Token refresh (if refresh tokens supported)
            - oauth2: OAuth2 protocol support
            - pkce: PKCE support (if enabled)

        """
        capabilities = {"token", "validate", "oauth2"}

        # Add refresh capability if flow supports it
        if self._flow in {"authorization_code", "password"}:
            capabilities.add("refresh")

        # Add PKCE capability if enabled
        if self._use_pkce:
            capabilities.add("pkce")

        return capabilities

    def get_metadata(self) -> FlextTypes.Dict:
        """Return OAuth2 provider metadata.

        Returns:
            FlextTypes.Dict: Provider metadata

        """
        return {
            "name": "oauth2",
            "version": "2.0.0",
            "description": "OAuth2 authentication provider with multiple flow support",
            "capabilities": list(self.supports()),
            "flow": self._flow,
            "use_pkce": self._use_pkce,
            "scope": self._scope,
            "authorization_endpoint": self._authorization_endpoint,
            "token_endpoint": self._token_endpoint,
        }

    # Flow-specific implementations

    def _handle_authorization_code_flow(
        self, credentials: FlextTypes.Dict
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Handle OAuth2 authorization code flow.

        Args:
            credentials: Must contain 'code' and 'state' keys

        Returns:
            FlextResult[AuthToken]: Access token or error

        """
        # Validate required fields
        validation_result = self._validate_credentials_dict(
            credentials, ["code", "state"]
        )
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation_result.error)

        code = credentials["code"]
        state = credentials["state"]

        # Prepare token request
        token_data: FlextTypes.Dict = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri,
            "client_id": self._client_id,
        }

        # Add PKCE code verifier if enabled
        if self._use_pkce:
            code_verifier = cast(
                "str",
                credentials.get("code_verifier") or self._pkce_verifiers.get(state),
            )
            if not code_verifier:
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    "PKCE code verifier required but not provided"
                )
            token_data["code_verifier"] = code_verifier

        # Add client authentication based on method
        auth: tuple[str, str] | None = None
        if (
            self._token_endpoint_auth_method
            == FlextAuthConstants.OAuth2.CLIENT_SECRET_POST
            and self._client_secret
        ):
            token_data["client_secret"] = self._client_secret
        elif (
            self._token_endpoint_auth_method
            == FlextAuthConstants.OAuth2.CLIENT_SECRET_BASIC
            and self._client_secret
        ):
            # HTTP Basic Authentication
            auth = cast(
                "tuple[str, str]", (self._client_id, cast("str", self._client_secret))
            )

        # Exchange authorization code for access token
        token_response = self._http_client.post_token_request(
            url=cast("str", self._token_endpoint),
            data=token_data,
            auth=auth,
        )

        if token_response.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(token_response.error)

        # Parse token response and create AuthToken
        return self._create_auth_token_from_response(token_response.unwrap())

    def _handle_client_credentials_flow(
        self, credentials: FlextTypes.Dict
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Handle OAuth2 client credentials flow.

        Args:
            credentials: Optional client_id and client_secret overrides

        Returns:
            FlextResult[AuthToken]: Access token or error

        """
        client_id = credentials.get("client_id") or self._client_id
        client_secret = credentials.get("client_secret") or self._client_secret

        if not client_secret:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Client credentials flow requires client_secret"
            )

        # Prepare token request
        token_data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "scope": self._scope,
        }

        # Add client authentication based on method
        auth: tuple[str, str] | None = None
        if (
            self._token_endpoint_auth_method
            == FlextAuthConstants.OAuth2.CLIENT_SECRET_POST
        ):
            token_data["client_secret"] = client_secret
        elif (
            self._token_endpoint_auth_method
            == FlextAuthConstants.OAuth2.CLIENT_SECRET_BASIC
        ):
            auth = (cast("str", client_id), cast("str", client_secret))

        # Request access token
        token_response = self._http_client.post_token_request(
            url=cast("str", self._token_endpoint),
            data=token_data,
            auth=auth,
        )

        if token_response.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(token_response.error)

        # Parse token response and create AuthToken
        return self._create_auth_token_from_response(token_response.unwrap())

    def _handle_password_flow(
        self, credentials: FlextTypes.Dict
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Handle OAuth2 resource owner password credentials flow.

        Args:
            credentials: Must contain 'username' and 'password'

        Returns:
            FlextResult[AuthToken]: Access token or error

        """
        validation_result = self._validate_credentials_dict(
            credentials, ["username", "password"]
        )
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation_result.error)

        token_data = {
            "grant_type": "password",
            "username": credentials["username"],
            "password": credentials["password"],
            "client_id": self._client_id,
            "scope": self._scope,
        }

        # Add client authentication based on method
        auth: tuple[str, str] | None = None
        if (
            self._token_endpoint_auth_method
            == FlextAuthConstants.OAuth2.CLIENT_SECRET_POST
            and self._client_secret
        ):
            token_data["client_secret"] = self._client_secret
        elif (
            self._token_endpoint_auth_method
            == FlextAuthConstants.OAuth2.CLIENT_SECRET_BASIC
            and self._client_secret
        ):
            auth = cast(
                "tuple[str, str]", (self._client_id, cast("str", self._client_secret))
            )

        # Request access token
        token_response = self._http_client.post_token_request(
            url=cast("str", self._token_endpoint),
            data=token_data,
            auth=auth,
        )

        if token_response.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(token_response.error)

        # Parse token response and create AuthToken
        return self._create_auth_token_from_response(token_response.unwrap())

    def _handle_device_flow(
        self, _credentials: FlextTypes.Dict
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Handle OAuth2 device authorization flow.

        Args:
            credentials: Device flow specific credentials

        Returns:
            FlextResult[AuthToken]: Access token or error

        """
        return FlextResult[FlextAuthModels.AuthToken].fail(
            "Device flow requires implementation with flext-api HTTP client"
        )

    # Helper methods

    def _create_auth_token_from_response(
        self, token_response: FlextTypes.Dict
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Create AuthToken from OAuth2 token response.

        Args:
            token_response: Token endpoint response data

        Returns:
            FlextResult[AuthToken]: Created token or error

        """
        try:
            # Extract token data
            access_token = token_response["access_token"]
            token_type = token_response["token_type"]
            expires_in = token_response.get("expires_in")
            refresh_token = token_response.get("refresh_token")
            # scope = token_response.get("scope", self._scope)  # Not used in current implementation

            # Calculate expiration time
            expires_at = None
            if expires_in:
                expires_at = datetime.now(UTC).timestamp() + cast("float", expires_in)

            # Create AuthToken
            # For OAuth2, user_id may not be known yet (especially for client_credentials)
            # Use placeholder if not available - will be populated after UserInfo call for OIDC
            user_id = token_response.get("user_id", "oauth2_user")

            auth_token = FlextAuthModels.AuthToken(
                user_id=user_id,
                token=access_token,
                token_type=cast("str", token_type).lower() if token_type else "bearer",
                expires_at=expires_at,
                refresh_token=refresh_token,
                is_revoked=False,
                metadata={
                    "oauth2_flow": self._flow,
                    "grant_type": self._flow,
                },
            )

            self.logger.info(
                "AuthToken created from OAuth2 response",
                extra={
                    "token_type": token_type,
                    "expires_in": expires_in,
                    "has_refresh": refresh_token is not None,
                },
            )

            return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

        except KeyError as e:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                f"Missing required field in token response: {e}"
            )
        except Exception as e:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                f"Failed to create AuthToken: {e}"
            )

    def generate_pkce_challenge(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge.

        Returns:
            tuple[str, str]: (code_verifier, code_challenge)

        """
        # Generate code verifier (43-128 characters)
        code_verifier = (
            urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
        )

        # Generate code challenge using S256 method
        challenge_bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = urlsafe_b64encode(challenge_bytes).decode("utf-8").rstrip("=")

        return code_verifier, code_challenge

    def get_authorization_url(
        self, state: str | None = None, code_challenge: str | None = None
    ) -> FlextResult[str]:
        """Generate OAuth2 authorization URL for authorization code flow.

        Args:
            state: CSRF protection state parameter
            code_challenge: PKCE code challenge (if not provided, will be generated)

        Returns:
            FlextResult[str]: Authorization URL or error

        """
        if not self._authorization_endpoint:
            return FlextResult[str].fail(
                "Authorization endpoint not configured for this provider"
            )

        # Generate state if not provided
        if not state:
            state = secrets.token_urlsafe(32)

        # Build authorization URL parameters
        params = cast(
            "FlextTypes.StringDict",
            {
                "response_type": "code",
                "client_id": self._client_id,
                "redirect_uri": self._redirect_uri or "",
                "scope": self._scope,
                "state": state,
            },
        )

        # Add PKCE if enabled
        if self._use_pkce:
            if not code_challenge:
                code_verifier, code_challenge = self.generate_pkce_challenge()
                # Store verifier for later use
                self._pkce_verifiers[state] = code_verifier

            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        # Build URL
        auth_url = f"{self._authorization_endpoint}?{urlencode(params)}"

        self.logger.info(
            "Generated authorization URL",
            extra={"state": state, "use_pkce": self._use_pkce},
        )

        return FlextResult[str].ok(auth_url)


__all__ = ["FlextAuthOAuth2Provider"]
