"""FLEXT Auth Provider Service - Focused authentication provider management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult, FlextService, FlextTypes

from flext_auth.config import FlextAuthConfig
from flext_auth.models import FlextAuthModels
from flext_auth.providers import (
    ApiKeyAuthProvider,
    BasicAuthProvider,
    CertificateAuthProvider,
    JwtAuthProvider,
    KerberosAuthProvider,
    LdapAuthProvider,
    OAuth2AuthProvider,
    OidcAuthProvider,
    SamlAuthProvider,
)
from flext_auth.providers.base import BaseAuthProvider
from flext_auth.registry import FlextAuthRegistry


class FlextAuthProviderService(FlextService):
    """Focused service for authentication provider management with flext-core integration."""

    def __init__(self, config: FlextAuthConfig) -> None:
        """Initialize provider service with flext-core integration."""
        super().__init__()
        self._config = config
        self._providers = FlextAuthRegistry()
        self._logger = FlextLogger(__name__)
        self._register_builtin_providers()

    def execute(self, _request: object) -> FlextResult[object]:
        """Execute method for FlextService interface.

        Provider service doesn't use generic execute pattern.
        Use specific provider methods instead.
        """
        return FlextResult[object].fail(
            "FlextAuthProviderService is focused - use specific provider methods like get_provider()"
        )

    def _register_builtin_providers(self) -> None:
        """Register all built-in authentication providers."""
        config_dict = self._config.model_dump()

        # Map flext-auth config fields to provider-expected fields
        provider_config = dict(config_dict)
        if hasattr(self._config, "jwt_secret") and self._config.jwt_secret:
            provider_config["secret_key"] = self._config.jwt_secret.get_secret_value()

        # Basic authentication
        basic_provider = BasicAuthProvider(provider_config)
        self._providers.register("basic", basic_provider)

        # JWT authentication
        jwt_provider = JwtAuthProvider(provider_config)
        self._providers.register("jwt", jwt_provider)

        # LDAP authentication (if configured)
        if hasattr(self._config, "ldap_enabled") and self._config.ldap_enabled:
            ldap_provider = LdapAuthProvider(config_dict)
            self._providers.register("ldap", ldap_provider)

        # OAuth2 authentication
        oauth2_provider = OAuth2AuthProvider(config_dict)
        self._providers.register("oauth2", oauth2_provider)

        # OIDC authentication
        oidc_provider = OidcAuthProvider(config_dict)
        self._providers.register("oidc", oidc_provider)

        # SAML authentication
        saml_provider = SamlAuthProvider(config_dict)
        self._providers.register("saml", saml_provider)

        # Kerberos authentication
        kerberos_provider = KerberosAuthProvider(config_dict)
        self._providers.register("kerberos", kerberos_provider)

        # Certificate authentication
        cert_provider = CertificateAuthProvider(config_dict)
        self._providers.register("certificate", cert_provider)

        # API Key authentication
        apikey_provider = ApiKeyAuthProvider(config_dict)
        self._providers.register("apikey", apikey_provider)

    def get_provider(self, name: str) -> FlextResult[BaseAuthProvider]:
        """Get a registered authentication provider."""
        return self._providers.get(name)

    def register_provider(
        self, name: str, provider: BaseAuthProvider
    ) -> FlextResult[None]:
        """Register a custom authentication provider."""
        return self._providers.register(name, provider)

    def list_providers(self) -> FlextTypes.StringList:
        """List all registered provider names."""
        return self._providers.list_providers()

    def authenticate_user(
        self,
        username: str,
        password: str,
        provider: str = "basic",
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate a user with username/password using specified provider."""
        # Get the authentication provider
        provider_result = self._providers.get(provider)
        if provider_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(provider_result.error)

        auth_provider = provider_result.value

        # Attempt authentication
        return auth_provider.authenticate({
            "username": username,
            "password": password,
        })


__all__ = ["FlextAuthProviderService"]
