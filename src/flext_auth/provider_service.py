"""FLEXT Auth Provider Service - Focused authentication provider management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextCore

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


class FlextAuthProviderService(FlextCore.Service):
    """Focused service for authentication provider management with flext-core integration."""

    def __init__(self, config: FlextAuthConfig) -> None:
        """Initialize provider service with flext-core integration."""
        super().__init__()
        self._config = config
        self._providers = FlextAuthRegistry()
        self._register_builtin_providers()

    def execute(self) -> FlextCore.Result[object]:
        """Execute method for FlextCore.Service interface.

        Provider service doesn't use generic execute pattern.
        Use specific provider methods instead.
        """
        return FlextCore.Result[object].fail(
            "FlextAuthProviderService is focused - use specific provider methods like get_provider()"
        )

    def _register_builtin_providers(self) -> None:
        """Register all built-in authentication providers that have required configuration."""
        if self._config is None:
            self.logger.warning(
                "No configuration provided, skipping provider registration"
            )
            return

        config_dict = self._config.model_dump()

        # Map flext-auth config fields to provider-expected fields
        provider_config = dict(config_dict)
        if hasattr(self._config, "jwt_auth_secret") and self._config.jwt_auth_secret:
            provider_config["secret_key"] = (
                self._config.jwt_auth_secret.get_secret_value()
            )

        # Basic authentication (always available)
        try:
            basic_provider = FlextAuthBasicProvider(provider_config)
            self._providers.register("basic", basic_provider)
        except (ValueError, TypeError) as e:
            self.logger.warning(f"Failed to register basic provider: {e}")

        # JWT authentication (requires secret_key)
        if provider_config.get("secret_key"):
            try:
                jwt_provider = FlextAuthJwtProvider(provider_config)
                self._providers.register("jwt", jwt_provider)
            except (ValueError, TypeError) as e:
                self.logger.warning(f"Failed to register JWT provider: {e}")

        # LDAP authentication (requires server and base_dn)
        if config_dict.get("server") and config_dict.get("base_dn"):
            try:
                ldap_provider = FlextAuthLdapProvider(config_dict)
                self._providers.register("ldap", ldap_provider)
            except (ValueError, TypeError) as e:
                self.logger.warning(f"Failed to register LDAP provider: {e}")

        # OAuth2 authentication (requires client_id and token_endpoint)
        if config_dict.get("client_id") and config_dict.get("token_endpoint"):
            try:
                oauth2_provider = FlextAuthOAuth2Provider(config_dict)
                self._providers.register("oauth2", oauth2_provider)
            except (ValueError, TypeError) as e:
                self.logger.warning(f"Failed to register OAuth2 provider: {e}")

        # OIDC authentication (requires issuer)
        if config_dict.get("issuer"):
            try:
                oidc_provider = FlextAuthOidcProvider(config_dict)
                self._providers.register("oidc", oidc_provider)
            except (ValueError, TypeError) as e:
                self.logger.warning(f"Failed to register OIDC provider: {e}")

        # SAML authentication (requires entity_id and sso_url)
        if config_dict.get("entity_id") and config_dict.get("sso_url"):
            try:
                saml_provider = FlextAuthSamlProvider(config_dict)
                self._providers.register("saml", saml_provider)
            except (ValueError, TypeError) as e:
                self.logger.warning(f"Failed to register SAML provider: {e}")

        # Kerberos authentication (requires realm and kdc)
        if config_dict.get("realm") and config_dict.get("kdc"):
            try:
                kerberos_provider = FlextAuthKerberosProvider(config_dict)
                self._providers.register("kerberos", kerberos_provider)
            except (ValueError, TypeError) as e:
                self.logger.warning(f"Failed to register Kerberos provider: {e}")

        # Certificate authentication (no specific config required beyond base)
        try:
            cert_provider = FlextAuthCertificateProvider(config_dict)
            self._providers.register("certificate", cert_provider)
        except (ValueError, TypeError) as e:
            self.logger.warning(f"Failed to register certificate provider: {e}")

        # API Key authentication (no specific config required beyond base)
        try:
            apikey_provider = FlextAuthApiKeyProvider(config_dict)
            self._providers.register("apikey", apikey_provider)
        except (ValueError, TypeError) as e:
            self.logger.warning(f"Failed to register API key provider: {e}")

    def get_provider(self, name: str) -> FlextCore.Result[FlextAuthBaseProvider]:
        """Get a registered authentication provider."""
        return self._providers.get(name)

    def register_provider(
        self, name: str, provider: FlextAuthBaseProvider
    ) -> FlextCore.Result[None]:
        """Register a custom authentication provider."""
        return self._providers.register(name, provider)

    def list_providers(self) -> FlextCore.Types.StringList:
        """List all registered provider names."""
        return self._providers.list_providers()

    def authenticate_user(
        self,
        username: str,
        password: str,
        provider: str = "basic",
    ) -> FlextCore.Result[FlextAuthModels.AuthToken]:
        """Authenticate a user with username/password using specified provider."""
        # Get the authentication provider
        provider_result = self._providers.get(provider)
        if provider_result.is_failure:
            return FlextCore.Result[FlextAuthModels.AuthToken].fail(
                provider_result.error
            )

        auth_provider = provider_result.value

        # Attempt authentication
        return auth_provider.authenticate({
            "username": username,
            "password": password,
        })

    def generate_tokens_for_user(
        self,
        user: FlextAuthModels.User,
        provider: str = "jwt",
    ) -> FlextCore.Result[FlextAuthModels.AuthToken]:
        """Generate authentication tokens for an authenticated user.

        Args:
            user: Authenticated user
            provider: Token provider to use

        Returns:
            FlextCore.Result containing AuthToken or error

        """
        # Get the token provider
        provider_result = self._providers.get(provider)
        if provider_result.is_failure:
            return FlextCore.Result[FlextAuthModels.AuthToken].fail(
                provider_result.error
            )

        token_provider = provider_result.value

        # Generate tokens using user data
        return token_provider.authenticate({
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "permissions": user.permissions,
        })


__all__ = ["FlextAuthProviderService"]
