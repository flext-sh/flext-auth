"""FLEXT Auth Provider Service - Flexible flext-core patterns with minimal line count.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated patterns
for maximum maintainability. Single FlextAuthProviderService class with composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextService

from flext_auth.config import FlextAuthConfig
from flext_auth.models import FlextAuthModels
from flext_auth.providers import (
    FlextAuthApiKeyProvider,
    FlextAuthBasicProvider,
    FlextAuthCertificateProvider,
    FlextAuthJwtProvider,
    FlextAuthKerberosProvider,
    FlextAuthLdapProvider,
    FlextAuthOAuth2Provider,
    FlextAuthOidcProvider,
    FlextAuthSamlProvider,
)
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.registry import FlextAuthRegistry


class FlextAuthProviderService(FlextService):
    """Flexible provider service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Flexible composition with dependency injection and error handling.
    """

    def __init__(self, config: FlextAuthConfig) -> None:
        """Flexible initialization with automatic provider registration."""
        super().__init__()
        self._config, self._providers = config, FlextAuthRegistry()
        self._register_builtin_providers()

    def execute(self) -> FlextResult[object]:
        """Railway-oriented execute with focused service pattern."""
        return FlextResult.fail(
            "Use specific provider methods: get_provider, authenticate_user, etc."
        )

    def _register_builtin_providers(self) -> None:
        """Flexible provider registration with conditional loading."""
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
    # Advanced AUTHENTICATION OPERATIONS
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

    def generate_token_for_user(
        self,
        user: FlextAuthModels.Identity,
        provider: str = "jwt",
        token_type: str = "access_token",
        expiry_minutes: int | None = None,
    ) -> FlextResult[str]:
        """Railway-oriented token generation with direct provider access."""
        return self._providers.get(provider).flat_map(
            lambda p: p.generate_token_for_user(user, token_type, expiry_minutes)
        )

    def validate_token(
        self,
        token: str,
        provider: str = "jwt",
    ) -> FlextResult[FlextAuthModels.Identity | None]:
        """Railway-oriented token validation with direct provider access."""
        return self._providers.get(provider).flat_map(lambda p: p.validate_token(token))


__all__ = ["FlextAuthProviderService"]
