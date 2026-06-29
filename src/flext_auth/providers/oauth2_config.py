"""OAuth2 provider configuration helpers."""

from __future__ import annotations

from collections.abc import Collection

from flext_auth import c, m, p, r


class FlextAuthOAuth2Config:
    """OAuth2 provider configuration helper owner."""

    provider_config: m.Auth.ProviderConfig

    @staticmethod
    def _validated_choice(
        value: str | None,
        *,
        key: str,
        default: str,
        allowed: Collection[str],
    ) -> str:
        """Validate one ProviderConfig str field against an allowed set."""
        if not value:
            return default
        if value not in allowed:
            msg = f"OAuth2 {key!r} must be one of {allowed}, got {value}"
            raise ValueError(msg)
        return value

    def _init_flow(self) -> str:
        """Initialize flow configuration."""
        return self._validated_choice(
            self.provider_config.flow,
            key="flow",
            default=c.Auth.OAUTH2_FLOW_DEFAULT,
            allowed=c.Auth.OAUTH2_FLOWS,
        )

    def _init_pkce(self) -> bool:
        """Initialize PKCE configuration."""
        use_pkce: bool | None = self.provider_config.use_pkce
        return use_pkce if use_pkce is not None else c.Auth.OAUTH2_USE_PKCE_DEFAULT

    def _init_scope(self) -> str:
        """Initialize scope configuration."""
        scope: str | None = self.provider_config.scope
        return scope or c.Auth.OAUTH2_SCOPE_DEFAULT

    def _init_token_endpoint_auth_method(self) -> str:
        """Initialize token endpoint auth method configuration."""
        return self._validated_choice(
            self.provider_config.token_endpoint_auth_method,
            key="token_endpoint_auth_method",
            default=c.Auth.OAUTH2_TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT,
            allowed=c.Auth.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS,
        )

    def _validate_configuration(self) -> p.Result[bool]:
        """Railway-oriented presence check (typing centralized in ProviderConfig)."""
        # Per-field type validation is owned by ``m.Auth.ProviderConfig`` —
        # ``model_validate`` already raised on type mismatch before this runs.
        # Only required-field presence remains here.
        missing = [
            field
            for field in ("client_id", "token_endpoint")
            if not getattr(self.provider_config, field)
        ]
        if missing:
            return r[bool].fail(
                f"Missing required OAuth2 configuration fields: {', '.join(missing)}",
            )
        return r[bool].ok(value=True)


__all__: list[str] = ["FlextAuthOAuth2Config"]
