"""FLEXT Auth Provider Service - Advanced flext-core patterns with minimal line count.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated patterns
for maximum maintainability. Single FlextAuthProviderService class with advanced composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextService

from flext_auth.config import FlextAuthConfig
from flext_auth.models import FlextAuthModels
from flext_auth.providers import *
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.registry import FlextAuthRegistry


class FlextAuthProviderService(FlextService):
    """Advanced provider service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Advanced composition with dependency injection and error handling.
    """

    def __init__(self, config: FlextAuthConfig) -> None:
        """Advanced initialization with automatic provider registration."""
        super().__init__()
        self._config, self._providers = config, FlextAuthRegistry()
        self._register_builtin_providers()

    def execute(self) -> FlextResult[object]:
        """Railway-oriented execute with focused service pattern."""
        return FlextResult.fail(
            "Use specific provider methods: get_provider, authenticate_user, etc."
        )

    def _register_builtin_providers(self) -> None:
        """Advanced provider registration with conditional loading."""
        if not self._config:
            self.logger.warning(
                "No configuration provided, skipping provider registration"
            )
            return

        config_dict = self._config.model_dump()
        provider_config = dict[str, object](config_dict)
        if hasattr(self._config, "jwt_auth_secret") and self._config.jwt_auth_secret:
            provider_config["secret_key"] = (
                self._config.jwt_auth_secret.get_secret_value()
            )

        # Provider registration mapping with requirements
        providers = [
            ("basic", FlextAuthBasicProvider, lambda: True),
            (
                "jwt",
                FlextAuthJwtProvider,
                lambda: bool(provider_config.get("secret_key")),
            ),
            (
                "ldap",
                FlextAuthLdapProvider,
                lambda: bool(config_dict.get("server") and config_dict.get("base_dn")),
            ),
            (
                "oauth2",
                FlextAuthOAuth2Provider,
                lambda: bool(
                    config_dict.get("client_id") and config_dict.get("token_endpoint")
                ),
            ),
            ("oidc", FlextAuthOidcProvider, lambda: bool(config_dict.get("issuer"))),
            (
                "saml",
                FlextAuthSamlProvider,
                lambda: bool(
                    config_dict.get("entity_id") and config_dict.get("sso_url")
                ),
            ),
            (
                "kerberos",
                FlextAuthKerberosProvider,
                lambda: bool(config_dict.get("realm") and config_dict.get("kdc")),
            ),
            ("certificate", FlextAuthCertificateProvider, lambda: True),
            ("apikey", FlextAuthApiKeyProvider, lambda: True),
        ]

        for name, provider_class, condition in providers:
            if condition():
                try:
                    provider = provider_class(provider_config)
                    self._providers.register(name, provider)
                except Exception as e:
                    self.logger.warning(f"Failed to register {name} provider: {e}")

    # =========================================================================
    # CONSOLIDATED PROVIDER MANAGEMENT
    # =========================================================================

    def get_provider(self, name: str) -> FlextResult[FlextAuthBaseProvider]:
        """Get registered provider."""
        return self._providers.get(name)

    def register_provider(
        self, name: str, provider: FlextAuthBaseProvider
    ) -> FlextResult[None]:
        """Register custom provider."""
        return self._providers.register(name, provider)

    def list_providers(self) -> list[str]:
        """List registered provider names."""
        return self._providers.list_providers()

    # =========================================================================
    # ADVANCED AUTHENTICATION OPERATIONS
    # =========================================================================

    def authenticate_user(
        self,
        username: str,
        password: str,
        provider: str = "basic",
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Railway-oriented user authentication with provider selection."""
        return self._providers.get(provider).flat_map(
            lambda p: p.authenticate({"username": username, "password": password})
        )

    def generate_tokens_for_user(
        self,
        user: FlextAuthModels.User,
        provider: str = "jwt",
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Railway-oriented token generation for authenticated user."""
        return self._providers.get(provider).flat_map(
            lambda p: p.authenticate({
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "roles": user.roles,
                "permissions": user.permissions,
            })
        )

    def validate_token_and_get_user(
        self, token: str
    ) -> FlextResult[FlextAuthModels.User | None]:
        """Advanced token validation with provider selection."""
        providers = ["jwt", "apikey"]
        for provider_name in providers:
            result = self._providers.get(provider_name)
            if result.is_success:
                validation_result = result.unwrap().validate_token(token)
                if validation_result.is_success:
                    return validation_result
        return FlextResult.fail("No token provider available")

    def generate_token_for_user(
        self,
        user: FlextAuthModels.User,
        token_type: str = "access",
        expiry_minutes: int | None = None,
    ) -> FlextResult[str]:
        """Advanced token generation with provider selection."""
        providers = ["jwt", "apikey"]
        for provider_name in providers:
            result = self._providers.get(provider_name)
            if result.is_success:
                token_result = result.unwrap().generate_token_for_user(
                    user, token_type, expiry_minutes
                )
                if token_result.is_success:
                    return token_result
        return FlextResult.fail("No token provider available")

    # =========================================================================
    # SESSION MANAGEMENT (PLACEHOLDER)
    # =========================================================================

    def revoke_session(self, _session_id: str) -> FlextResult[None]:
        """Revoke user session (placeholder implementation)."""
        return FlextResult.ok(None)

    def get_user_sessions(
        self, _user_id: str
    ) -> FlextResult[list[FlextAuthModels.Session]]:
        """Get user sessions (placeholder implementation)."""
        return FlextResult.ok([])


__all__ = ["FlextAuthProviderService"]
