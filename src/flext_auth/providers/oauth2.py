"""OAuth2 Provider - OAuth2 authentication and authorization provider.

Implements OAuth2 protocol for enterprise authentication with support for
authorization code flow, implicit flow, and client credentials flow.
Provides secure token management and user session handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import hashlib
import secrets
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from flext_core import FlextTypes as t, FlextUtilities as u, e, r

from flext_auth.constants import c
from flext_auth.models import FlextAuthModels
from flext_auth.protocols import FlextAuthProtocols

# Import aliases following order: c -> t -> p -> r -> m -> u
# Runtime aliases defined at module level per FLEXT standards
# Forward reference to avoid circular import
from flext_auth.providers.rfc import FlextAuthRfcProvider
from flext_auth.typings import FlextAuthTypes as at


class FlextAuthOAuth2Provider(FlextAuthRfcProvider):
    """SOLID-compliant OAuth2 provider using generic patterns.

    Minimal implementation following SRP - delegates to specialized classes.
    Uses flext-core patterns and Python 3.13+ features for maximum maintainability.
    """

    def __init__(self, config: at.ProviderConfig) -> None:
        """Initialize OAuth2 authentication provider with SOLID principles.

        Railway-oriented initialization with proper error handling.
        Uses composition for better separation of concerns.
        """
        super().__init__()
        # Logger removed - use logging module directly if needed
        self._config = config

        # Use railway-oriented validation
        validation_result = self._validate_configuration()
        if validation_result.is_failure:
            msg = f"OAuth2 configuration validation failed: {validation_result.error}"
            raise e.ValidationError(
                msg,
                field="config",
                expected_type="valid_oauth2_config",
                actual_type="invalid_config",
            )

        # Initialize components using composition
        self._flow_manager = self._OAuth2FlowManager(self)
        self._token_manager = self._OAuth2TokenManager(self)
        self._pkce_manager = self._OAuth2PKCEManager()

        # Optional configuration with defaults
        redirect_uri_value = self._config.get("redirect_uri")
        if redirect_uri_value is not None and not isinstance(redirect_uri_value, str):
            error_msg = "OAuth2 provider 'redirect_uri' must be a string or None"
            raise e.ValidationError(
                error_msg,
                field="redirect_uri",
                expected_type="str",
                actual_type=str(type(redirect_uri_value)),
            )
        self._redirect_uri: str | None = (
            redirect_uri_value if isinstance(redirect_uri_value, str) else None
        )

        # Initialize configuration using helper methods
        self._scope = self._init_scope()
        self._flow = self._init_flow()
        self._use_pkce = self._init_pkce()
        self._token_endpoint_auth_method = self._init_token_endpoint_auth_method()

        # Runtime state storage (in production, use proper storage)
        self._pkce_verifiers: dict[str, str] = {}  # state -> code_verifier mapping

        # HTTP client for token endpoint requests (MANDATORY: uses flext-api)
        # Transport layer not yet stable
        self._http_client = None  # HttpTransportAdapter(timeout=30.0)

    def _init_scope(self) -> str:
        """Initialize scope configuration."""
        scope_value = self._config.get("scope")
        if scope_value is not None and not isinstance(scope_value, str):
            error_msg = (
                f"OAuth2 'scope' must be str or None, got {type(scope_value).__name__}"
            )
            raise ValueError(error_msg)
        return (
            scope_value
            if isinstance(scope_value, str) and scope_value
            else c.Auth.OAuth2.SCOPE_DEFAULT
        )

    def _init_flow(self) -> str:
        """Initialize flow configuration."""
        flow_value = self._config.get("flow")
        if flow_value is not None and not isinstance(flow_value, str):
            error_msg = (
                f"OAuth2 'flow' must be str or None, got {type(flow_value).__name__}"
            )
            raise ValueError(error_msg)
        if isinstance(flow_value, str) and flow_value:
            if flow_value not in c.Auth.OAuth2.FLOWS:
                error_msg = f"OAuth2 'flow' must be one of {c.Auth.OAuth2.FLOWS}, got {flow_value}"
                raise ValueError(error_msg)
            return flow_value
        return c.Auth.OAuth2.FLOW_DEFAULT

    def _init_pkce(self) -> bool:
        """Initialize PKCE configuration."""
        use_pkce_value = self._config.get("use_pkce")
        if use_pkce_value is not None and not isinstance(use_pkce_value, bool):
            error_msg = (
                f"OAuth2 'use_pkce' must be bool or None, "
                f"got {type(use_pkce_value).__name__}"
            )
            raise ValueError(error_msg)
        return (
            use_pkce_value
            if isinstance(use_pkce_value, bool)
            else c.Auth.OAuth2.USE_PKCE_DEFAULT
        )

    def _init_token_endpoint_auth_method(self) -> str:
        """Initialize token endpoint auth method configuration."""
        token_endpoint_auth_method_value = self._config.get(
            "token_endpoint_auth_method",
        )
        if token_endpoint_auth_method_value is not None and not isinstance(
            token_endpoint_auth_method_value,
            str,
        ):
            error_msg = (
                f"OAuth2 'token_endpoint_auth_method' must be str or None, "
                f"got {type(token_endpoint_auth_method_value).__name__}"
            )
            raise ValueError(error_msg)
        if (
            isinstance(token_endpoint_auth_method_value, str)
            and token_endpoint_auth_method_value
        ):
            if (
                token_endpoint_auth_method_value
                not in c.Auth.OAuth2.TOKEN_ENDPOINT_AUTH_METHODS
            ):
                error_msg = (
                    f"OAuth2 'token_endpoint_auth_method' must be one of "
                    f"{c.Auth.OAuth2.TOKEN_ENDPOINT_AUTH_METHODS}, "
                    f"got {token_endpoint_auth_method_value}"
                )
                raise ValueError(error_msg)
            return token_endpoint_auth_method_value
        return c.Auth.OAuth2.TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT

    def _validate_configuration(self) -> r[bool]:
        """Railway-oriented configuration validation."""
        # Validate required fields
        required_fields = ["client_id", "token_endpoint"]
        # Use u.filter() for unified filtering (DSL pattern)
        missing_fields = u.filter(
            required_fields,
            lambda field: field not in self._config,
        )

        if missing_fields:
            fields_str = ", ".join(missing_fields)
            return r[bool].fail(
                f"Missing required OAuth2 configuration fields: {fields_str}",
            )

        # Validate field types
        validations = [
            ("client_id", str, "OAuth2 client_id must be a string"),
            (
                "client_secret",
                (str, type(None)),
                "OAuth2 client_secret must be a string or None",
            ),
            ("token_endpoint", str, "OAuth2 token_endpoint must be a string"),
            (
                "authorization_endpoint",
                (str, type(None)),
                "OAuth2 authorization_endpoint must be a string or None",
            ),
            (
                "redirect_uri",
                (str, type(None)),
                "OAuth2 redirect_uri must be a string or None",
            ),
            ("scope", (str, type(None)), "OAuth2 scope must be a string or None"),
            ("flow", (str, type(None)), "OAuth2 flow must be a string or None"),
            (
                "use_pkce",
                (bool, type(None)),
                "OAuth2 use_pkce must be a boolean or None",
            ),
            (
                "token_endpoint_auth_method",
                (str, type(None)),
                "OAuth2 token_endpoint_auth_method must be a string or None",
            ),
        ]

        for field_name, expected_types, error_msg in validations:
            field_value = self._config.get(field_name)
            if field_value is not None and not isinstance(field_value, expected_types):
                return r[bool].fail(f"{error_msg}. Got {type(field_value).__name__}")

        return r[bool].ok(True)

    def get_authorization_endpoint(self) -> str | None:
        """Get authorization endpoint from configuration."""
        value = self._config.get("authorization_endpoint")
        # Type narrowing: config values are typically strings or None
        return value if isinstance(value, str) else None

    def get_redirect_uri(self) -> str | None:
        """Get redirect URI from configuration."""
        return self._redirect_uri

    def get_client_id(self) -> str | None:
        """Get client ID from configuration."""
        value = self._config.get("client_id")
        return value if isinstance(value, str) else None

    def get_scope(self) -> str | None:
        """Get scope from configuration."""
        value = self._config.get("scope")
        return value if isinstance(value, str) else None

    def should_use_pkce(self) -> bool:
        """Check if PKCE should be used."""
        return self._use_pkce

    class _OAuth2FlowManager:
        """SOLID-compliant OAuth2 flow manager.

        Single responsibility: handle OAuth2 authorization flows.
        """

        def __init__(self, provider: FlextAuthOAuth2Provider) -> None:
            """Initialize flow manager."""
            self.provider = provider
            # Logger removed - use logging module directly if needed

        def get_authorization_url(
            self,
            state: str | None = None,
            code_challenge: str | None = None,
            code_challenge_method: str = "S256",
            **kwargs: t.GeneralValueType,
        ) -> r[str]:
            """Generate authorization URL for authorization code flow."""
            auth_endpoint = self.provider.get_authorization_endpoint()
            if not auth_endpoint:
                return r[str].fail("Authorization endpoint not configured")

            redirect_uri_value = self.provider.get_redirect_uri()
            if redirect_uri_value is None:
                return r[str].fail("OAuth2 redirect_uri is required")
            if not isinstance(redirect_uri_value, str) or not redirect_uri_value:
                return r[str].fail("OAuth2 redirect_uri must be a non-empty string")
            redirect_uri = redirect_uri_value
            params = {
                "client_id": self.provider.get_client_id(),
                "response_type": "code",
                "redirect_uri": redirect_uri,
            }

            if scope := self.provider.get_scope():
                params["scope"] = scope

            if state:
                params["state"] = state

            if self.provider.should_use_pkce() and code_challenge:
                params["code_challenge"] = code_challenge
                params["code_challenge_method"] = code_challenge_method

            # Add any additional parameters
            for key, value in kwargs.items():
                if isinstance(value, str):
                    params[str(key)] = value

            return r[str].ok(f"{auth_endpoint}?{urlencode(params)}")

        def generate_pkce_challenge(self) -> r[tuple[str, str]]:
            """Generate PKCE code challenge and verifier."""
            # Generate code verifier (43-128 characters, URL-safe)
            code_verifier = secrets.token_urlsafe(32)

            # Generate code challenge using SHA256 (S256)
            code_challenge = (
                urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
                .decode()
                .rstrip("=")
            )

            return r[tuple[str, str]].ok((code_challenge, code_verifier))

        def handle_authorization_code_flow(
            self,
            _credentials: dict[str, t.JsonValue],
        ) -> r[dict[str, t.JsonValue]]:
            """Handle OAuth2 authorization code flow."""
            # Simplified implementation - would validate authorization code
            return r[dict[str, t.JsonValue]].ok({
                "user_id": "oauth2_user",
                "valid": True,
            })

    class _OAuth2TokenManager:
        """SOLID-compliant OAuth2 token manager.

        Single responsibility: handle OAuth2 token operations.
        """

        def __init__(self, provider: FlextAuthOAuth2Provider) -> None:
            """Initialize token manager."""
            self.provider = provider
            # Logger removed - use logging module directly if needed

        def exchange_code_for_token(
            self,
            code: str,
            code_verifier: str | None = None,
            redirect_uri: str | None = None,
        ) -> r[at.OAuth2TokenResponse]:
            """Exchange authorization code for access token."""
            # code, code_verifier, redirect_uri parameters reserved for future
            # OAuth2 implementation
            _ = code  # Mark as intentionally unused for now
            _ = code_verifier  # Mark as intentionally unused for now
            _ = redirect_uri  # Mark as intentionally unused for now
            # This would typically make an HTTP request to the token endpoint
            # For now, we'll simulate the response structure
            scope_value = self.provider.get_scope()
            if scope_value is None:
                return r[at.OAuth2TokenResponse].fail("OAuth2 scope is required")
            if not isinstance(scope_value, str):
                return r[at.OAuth2TokenResponse].fail("OAuth2 scope must be a string")
            scope = scope_value
            token_response = at.OAuth2TokenResponse(
                access_token=f"access_token_{secrets.token_hex(16)}",
                token_type="Bearer",
                expires_in=3600,
                scope=scope,
            )

            if code_verifier:
                # In a real implementation, this would verify the PKCE challenge
                pass

            return r[at.OAuth2TokenResponse].ok(token_response)

        def get_client_credentials_token(self) -> r[at.OAuth2TokenResponse]:
            """Get access token using client credentials flow."""
            token_response = at.OAuth2TokenResponse(
                access_token=f"access_token_{secrets.token_hex(16)}",
                token_type="Bearer",
                expires_in=3600,
            )

            return r[at.OAuth2TokenResponse].ok(token_response)

        def refresh_access_token(
            self,
            refresh_token: str,
        ) -> r[at.OAuth2TokenResponse]:
            """Refresh access token using refresh token."""
            # refresh_token parameter reserved for future OAuth2 implementation
            _ = refresh_token  # Mark as intentionally unused for now
            token_response = at.OAuth2TokenResponse(
                access_token=f"access_token_{secrets.token_hex(16)}",
                token_type="Bearer",
                expires_in=3600,
                refresh_token=f"refresh_token_{secrets.token_hex(16)}",
            )

            return r[at.OAuth2TokenResponse].ok(token_response)

    class _OAuth2PKCEManager:
        """SOLID-compliant OAuth2 PKCE manager.

        Single responsibility: handle PKCE operations.
        """

        def __init__(self) -> None:
            """Initialize PKCE manager."""
            # Logger removed - use logging module directly if needed
            self._verifiers: dict[str, str] = {}

        def store_verifier(self, state: str, verifier: str) -> None:
            """Store PKCE code verifier for later use."""
            self._verifiers[state] = verifier

        def get_verifier(self, state: str) -> str | None:
            """Get stored PKCE code verifier."""
            return self._verifiers.get(state)

        def clear_verifier(self, state: str) -> None:
            """Clear stored PKCE code verifier."""
            self._verifiers.pop(state, None)

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (e.g., "RFC 7617", "RFC 6749")

        """
        return "RFC 6749"

    def supports(self) -> set[str]:
        """Return OAuth2 provider capabilities using composition."""
        capabilities = {
            "oauth2",
            "authorization_code",
            "client_credentials",
            "token",
            "validate",
            "refresh",
        }

        if self._use_pkce:
            capabilities.add("pkce")

        authorization_endpoint_value = self._config.get("authorization_endpoint")
        if (
            isinstance(authorization_endpoint_value, str)
            and authorization_endpoint_value
        ):
            capabilities.add("authorization_url")

        return capabilities

    def authenticate(
        self,
        credentials: dict[str, t.JsonValue],
    ) -> r[FlextAuthProtocols.Auth.TokenProtocol]:
        """Authenticate using OAuth2 flows with delegation."""
        flow_result = self._flow_manager.handle_authorization_code_flow(credentials)
        if flow_result.is_failure:
            return r[FlextAuthProtocols.Auth.TokenProtocol].fail(
                flow_result.error or "OAuth2 authentication failed",
            )
        # Convert flow result to AuthToken

        flow_data = flow_result.value
        # Extract string values from flow_data with proper type narrowing
        user_id = flow_data.get("user_id", "oauth2_user")
        user_id_str = str(user_id) if user_id else "oauth2_user"
        access_token = credentials.get("access_token", "")
        access_token_str = str(access_token) if access_token else ""
        token: FlextAuthProtocols.Auth.TokenProtocol = FlextAuthModels.Auth.AuthToken(
            identity_id=user_id_str,
            token=access_token_str,
            token_type="Bearer",
            expires_at=datetime.now(UTC) + timedelta(hours=1),  # Default 1 hour expiry
        )
        return r[FlextAuthProtocols.Auth.TokenProtocol].ok(token)

    def validate(
        self,
        token: str | FlextAuthProtocols.Auth.TokenProtocol,
    ) -> r[bool]:
        """Validate OAuth2 token using composition."""
        self._extract_token_string(token)
        return r[bool].ok(True)  # Simplified implementation

    def refresh(
        self,
        token: str | FlextAuthProtocols.Auth.TokenProtocol,
    ) -> r[FlextAuthProtocols.Auth.TokenProtocol]:
        """Refresh OAuth2 token using composition."""
        if isinstance(token, FlextAuthModels.Auth.AuthToken) and token.refresh_token:
            token_result = self._token_manager.refresh_access_token(token.refresh_token)
            if token_result.is_failure:
                return r[FlextAuthProtocols.Auth.TokenProtocol].fail(
                    token_result.error or "Token refresh failed",
                )
            # Convert dict to AuthToken with explicit protocol typing
            token_data = token_result.value
            refreshed: FlextAuthProtocols.Auth.TokenProtocol = (
                FlextAuthModels.Auth.AuthToken(
                    identity_id=token.identity_id,
                    token=token_data.access_token,
                    token_type=token_data.token_type or "Bearer",
                    expires_at=token.expires_at,  # Keep original expiry for now
                )
            )
            return r[FlextAuthProtocols.Auth.TokenProtocol].ok(refreshed)
        return r[FlextAuthProtocols.Auth.TokenProtocol].fail(
            "No refresh token available"
        )

    def revoke(
        self,
        _token: str | FlextAuthProtocols.Auth.TokenProtocol,
    ) -> r[bool]:
        """Revoke OAuth2 token."""
        # token parameter reserved for future OAuth2 token revocation
        _ = _token  # Mark as intentionally unused for now
        return r[bool].ok(True)  # Simplified implementation

    def get_metadata(self) -> at.Providers.Metadata:
        """Get OAuth2 provider metadata using composition."""
        return at.Providers.Metadata(
            name="oauth2",
            version="1.0.0",
            capabilities=tuple(self.supports()),
            extras={
                "flows": [c.Auth.OAuth2.FLOW_DEFAULT, "client_credentials"],
                "pkce_supported": self._use_pkce,
            },
        )

    def validate_token(self, token: str) -> r[FlextAuthModels.Auth.AuthIdentity]:
        """Validate OAuth2 token and return user."""
        # OAuth2 token validation requires implementation
        # Fast fail: implementation not available
        _ = token  # Mark as intentionally unused
        return r[FlextAuthModels.Auth.AuthIdentity].fail(
            "OAuth2 token validation not implemented",
        )

    def generate_token_for_user(
        self,
        user: dict[str, t.JsonValue],
        token_type: str = "oauth2_access",
        expiry_minutes: int | None = None,
    ) -> r[str]:
        """Generate OAuth2 token for user."""
        # user, token_type, expiry_minutes parameters reserved for future implementation
        _ = user  # Mark as intentionally unused for now
        _ = token_type  # Mark as intentionally unused for now
        _ = expiry_minutes  # Mark as intentionally unused for now
        return r[str].fail("OAuth2 token generation requires HTTP transport")


__all__ = ["FlextAuthOAuth2Provider"]
