"""Typed, frozen business policy loaded by the canonical FLEXT config sources.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextConfig, FlextSettings

from flext_auth import m, t, u


class FlextAuthConfig(FlextSettings, FlextConfig, strict=True):
    """Auth policy with native settings-source precedence and immutable models."""

    class AuthPolicy(m.FrozenModel, str_strip_whitespace=False):
        """Business rules owned by the packaged and operator Auth YAML."""

        class Jwt(m.FrozenModel, str_strip_whitespace=False):
            """JWT policy defaults."""

            default_algorithm: str = m.Field(
                description="Default JWT signing algorithm."
            )
            default_expiry_minutes: int = m.Field(
                ge=1,
                description="Default JWT expiry in minutes.",
            )
            max_expiry_minutes: int = m.Field(
                ge=1,
                description="Maximum JWT expiry in minutes.",
            )
            issuer_claim: str = m.Field(description="Default JWT issuer claim.")
            audience_claim: str = m.Field(description="Default JWT audience claim.")
            min_secret_key_length: int = m.Field(
                ge=1,
                description="Minimum secret key length for JWT.",
            )
            default_token_type: str = m.Field(
                description="Default token type for Authorization header.",
            )

        class OAuth2(m.FrozenModel, str_strip_whitespace=False):
            """OAuth2 policy defaults."""

            default_scope: str = m.Field(description="Default OAuth2 scope.")
            flows: tuple[str, ...] = m.Field(description="Supported OAuth2 flows.")
            default_flow: str = m.Field(description="Default OAuth2 flow.")
            use_pkce_default: bool = m.Field(
                description="Whether to use PKCE by default."
            )
            token_endpoint_auth_methods: tuple[str, ...] = m.Field(
                description="Supported token endpoint authentication methods.",
            )
            default_token_endpoint_auth_method: str = m.Field(
                description="Default token endpoint authentication method.",
            )

        class Credentials(m.FrozenModel):
            """Credential validation defaults."""

            username_min_length: int = m.Field(
                ge=1, description="Minimum username length."
            )
            username_max_length: int = m.Field(
                ge=1, description="Maximum username length."
            )
            password_min_length: int = m.Field(
                ge=1, description="Minimum password length."
            )
            password_max_length: int = m.Field(
                ge=1, description="Maximum password length."
            )
            password_min_score: int = m.Field(
                ge=0,
                description="Minimum password strength score.",
            )
            password_min_bcrypt_hash_length: int = m.Field(
                ge=1,
                description="Minimum bcrypt hash length.",
            )
            password_bcrypt_rounds: int = m.Field(
                ge=4,
                le=31,
                description="Default bcrypt rounds.",
            )

        class Session(m.FrozenModel):
            """Session policy defaults."""

            default_expiry_minutes: int = m.Field(
                ge=1,
                description="Default session expiry in minutes.",
            )
            max_expiry_minutes: int = m.Field(
                ge=1,
                description="Maximum session expiry in minutes.",
            )
            max_sessions_per_user: int = m.Field(
                ge=1,
                description="Maximum sessions per user.",
            )
            min_token_length: int = m.Field(
                ge=1,
                description="Minimum session token length.",
            )

        class Security(m.FrozenModel):
            """Rate-limit and lockout defaults."""

            max_login_attempts: int = m.Field(
                ge=1,
                description="Maximum login attempts before lockout.",
            )
            lockout_duration_minutes: int = m.Field(
                ge=1,
                description="Lockout duration in minutes.",
            )
            max_requests_per_minute: int = m.Field(
                ge=1,
                description="Maximum requests per minute.",
            )
            max_requests_per_hour: int = m.Field(
                ge=1,
                description="Maximum requests per hour.",
            )

        class Validation(m.FrozenModel):
            """Generic validation length defaults."""

            short_name_max: int = m.Field(
                ge=1,
                description="Maximum length for short names.",
            )
            bcrypt_rounds: int = m.Field(
                ge=4,
                le=31,
                description="Bcrypt rounds for password hashing.",
            )
            default_token_expiry_minutes: int = m.Field(
                ge=1,
                description="Default token expiry in minutes.",
            )
            max_role_name_length: int = m.Field(
                ge=1,
                description="Maximum length for role names.",
            )
            max_role_description_length: int = m.Field(
                ge=1,
                description="Maximum length for role descriptions.",
            )
            max_permission_name_length: int = m.Field(
                ge=1,
                description="Maximum length for permission names.",
            )
            max_permission_description_length: int = m.Field(
                ge=1,
                description="Maximum length for permission descriptions.",
            )

        name: str = m.Field(description="Package identity name metadata.")
        version: str = m.Field(description="Package identity version metadata.")
        jwt: Jwt = m.Field(description="JWT policy defaults.")
        oauth2: OAuth2 = m.Field(
            description="OAuth2 policy defaults.",
        )
        credentials: Credentials = m.Field(
            description="Credential validation defaults.",
        )
        session: Session = m.Field(
            description="Session policy defaults.",
        )
        security: Security = m.Field(
            description="Rate-limit and lockout defaults.",
        )
        validation: Validation = m.Field(
            description="Generic validation length defaults.",
        )

    Auth: AuthPolicy

    @m.field_validator("Auth", mode="before")
    @classmethod
    def _parse_auth_policy(cls, value: t.JsonValue | AuthPolicy) -> AuthPolicy:
        """Validate JSON-shaped sources without changing their merge precedence.

        Returns:
            The strict Auth policy from the already merged native sources.

        """
        if isinstance(value, cls.AuthPolicy):
            return value
        return cls.AuthPolicy.model_validate_json(
            u.json_value_adapter().dump_json(value, warnings="error"),
            strict=True,
        )


config: FlextAuthConfig = FlextAuthConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_auth import config``."""

__all__: list[str] = ["FlextAuthConfig", "config"]
