"""OAuth2 Provider - OAuth2 authentication and authorization provider."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, override

from flext_auth import e, m, t
from flext_auth.providers.oauth2_tokens import FlextAuthOAuth2Tokens

if TYPE_CHECKING:
    import http.client


class FlextAuthOAuth2Provider(FlextAuthOAuth2Tokens):
    """OAuth2 provider using focused configuration and token operation owners."""

    def __init__(self, settings: m.Auth.ProviderConfig | t.ScalarMapping) -> None:
        """Initialize OAuth2 authentication provider with SOLID principles.

        Railway-oriented initialization with proper error handling.
        Uses composition for better separation of concerns.
        """
        raw_config = (
            settings
            if isinstance(settings, Mapping)
            else settings.model_dump(
                mode="json",
                exclude_none=True,
            )
        )
        normalized_config: t.ScalarMapping = t.scalar_mapping_adapter().validate_python(
            raw_config,
        )
        scalar_config = self.project_to_scalar_config(normalized_config) or {}
        super().__init__(scalar_config)
        self.config = normalized_config
        self._oauth2_config: t.MappingKV[str, t.Primitives] = scalar_config
        # Pydantic-typed view of the OAuth2 config — eliminates dict.get + isinstance
        # narrowing at every access site. ProviderConfig owns the field-typing
        # contract and validation centralization.
        self.provider_config: m.Auth.ProviderConfig = (
            m.Auth.ProviderConfig.model_validate({
                "name": str(scalar_config.get("name", "oauth2")),
                "type": str(scalar_config.get("type", "oauth2")),
                **scalar_config,
            })
        )
        validation_result = self._validate_configuration()
        if validation_result.failure:
            msg = f"OAuth2 configuration validation failed: {validation_result.error}"
            raise e.ValidationError(
                msg,
                field="settings",
                expected_type="valid_oauth2_config",
                actual_type="invalid_config",
            )
        self.scope = self._init_scope()
        self._flow = self._init_flow()
        self.use_pkce = self._init_pkce()
        self._token_endpoint_auth_method = self._init_token_endpoint_auth_method()
        self._http_client: http.client.HTTPSConnection | None = None

    @override
    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (e.g., "RFC 7617", "RFC 6749")

        """
        return "RFC 6749"


__all__: t.MutableSequenceOf[str] = ["FlextAuthOAuth2Provider"]
