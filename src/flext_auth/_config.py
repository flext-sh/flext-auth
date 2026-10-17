"""Typed, frozen business policy loaded by the canonical FLEXT config sources.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import (
    FlextConfig,
    FlextModels,
    FlextSettings,
    FlextTypes,
    FlextUtilities,
)


class FlextAuthConfig(FlextSettings, FlextConfig, strict=True):
    """Auth policy with native settings-source precedence and immutable models."""

    class AuthPolicy(FlextModels.FrozenModel, str_strip_whitespace=False):
        """Business rules owned by the packaged and operator Auth YAML."""

        class Jwt(FlextModels.FrozenModel, str_strip_whitespace=False):
            """JWT policy defaults."""

            default_algorithm: str = FlextModels.Field(
                description="Default JWT signing algorithm."
            )
            default_expiry_minutes: int = FlextModels.Field(
                ge=1,
                description="Default JWT expiry in minutes.",
            )
            max_expiry_minutes: int = FlextModels.Field(
                ge=1,
                description="Maximum JWT expiry in minutes.",
            )
            issuer_claim: str = FlextModels.Field(
                description="Default JWT issuer claim."
            )
            audience_claim: str = FlextModels.Field(
                description="Default JWT audience claim."
            )
            min_secret_key_length: int = FlextModels.Field(
                ge=1,
                description="Minimum secret key length for JWT.",
            )
            default_token_type: str = FlextModels.Field(
                description="Default token type for Authorization header.",
            )

        class OAuth2(FlextModels.FrozenModel, str_strip_whitespace=False):
            """OAuth2 policy defaults."""

            default_scope: str = FlextModels.Field(description="Default OAuth2 scope.")
            flows: tuple[str, ...] = FlextModels.Field(
                description="Supported OAuth2 flows."
            )
            default_flow: str = FlextModels.Field(description="Default OAuth2 flow.")
            use_pkce_default: bool = FlextModels.Field(
                description="Whether to use PKCE by default."
            )
            token_endpoint_auth_methods: tuple[str, ...] = FlextModels.Field(
                description="Supported token endpoint authentication methods.",
            )
            default_token_endpoint_auth_method: str = FlextModels.Field(
                description="Default token endpoint authentication method.",
            )

        class Credentials(FlextModels.FrozenModel):
            """Credential validation defaults."""

            username_min_length: int = FlextModels.Field(
                ge=1, description="Minimum username length."
            )
            username_max_length: int = FlextModels.Field(
                ge=1, description="Maximum username length."
            )
            password_min_length: int = FlextModels.Field(
                ge=1, description="Minimum password length."
            )
            password_max_length: int = FlextModels.Field(
                ge=1, description="Maximum password length."
            )
            password_min_score: int = FlextModels.Field(
                ge=0,
                description="Minimum password strength score.",
            )
            password_min_bcrypt_hash_length: int = FlextModels.Field(
                ge=1,
                description="Minimum bcrypt hash length.",
            )
            password_bcrypt_rounds: int = FlextModels.Field(
                ge=4,
                le=31,
                description="Default bcrypt rounds.",
            )

        class Session(FlextModels.FrozenModel):
            """Session policy defaults."""

            default_expiry_minutes: int = FlextModels.Field(
                ge=1,
                description="Default session expiry in minutes.",
            )
            max_expiry_minutes: int = FlextModels.Field(
                ge=1,
                description="Maximum session expiry in minutes.",
            )
            max_sessions_per_user: int = FlextModels.Field(
                ge=1,
                description="Maximum sessions per user.",
            )
            min_token_length: int = FlextModels.Field(
                ge=1,
                description="Minimum session token length.",
            )

        class Security(FlextModels.FrozenModel):
            """Rate-limit and lockout defaults."""

            max_login_attempts: int = FlextModels.Field(
                ge=1,
                description="Maximum login attempts before lockout.",
            )
            lockout_duration_minutes: int = FlextModels.Field(
                ge=1,
                description="Lockout duration in minutes.",
            )
            max_requests_per_minute: int = FlextModels.Field(
                ge=1,
                description="Maximum requests per minute.",
            )
            max_requests_per_hour: int = FlextModels.Field(
                ge=1,
                description="Maximum requests per hour.",
            )

        class Validation(FlextModels.FrozenModel):
            """Generic validation length defaults."""

            short_name_max: int = FlextModels.Field(
                ge=1,
                description="Maximum length for short names.",
            )
            bcrypt_rounds: int = FlextModels.Field(
                ge=4,
                le=31,
                description="Bcrypt rounds for password hashing.",
            )
            default_token_expiry_minutes: int = FlextModels.Field(
                ge=1,
                description="Default token expiry in minutes.",
            )
            max_role_name_length: int = FlextModels.Field(
                ge=1,
                description="Maximum length for role names.",
            )
            max_role_description_length: int = FlextModels.Field(
                ge=1,
                description="Maximum length for role descriptions.",
            )
            max_permission_name_length: int = FlextModels.Field(
                ge=1,
                description="Maximum length for permission names.",
            )
            max_permission_description_length: int = FlextModels.Field(
                ge=1,
                description="Maximum length for permission descriptions.",
            )

        name: str = FlextModels.Field(description="Package identity name metadata.")
        version: str = FlextModels.Field(
            description="Package identity version metadata."
        )
        jwt: Jwt = FlextModels.Field(description="JWT policy defaults.")
        oauth2: OAuth2 = FlextModels.Field(
            description="OAuth2 policy defaults.",
        )
        credentials: Credentials = FlextModels.Field(
            description="Credential validation defaults.",
        )
        session: Session = FlextModels.Field(
            description="Session policy defaults.",
        )
        security: Security = FlextModels.Field(
            description="Rate-limit and lockout defaults.",
        )
        validation: Validation = FlextModels.Field(
            description="Generic validation length defaults.",
        )

    Auth: AuthPolicy

    @FlextModels.field_validator("Auth", mode="before")
    @classmethod
    def _parse_auth_policy(cls, value: FlextTypes.JsonValue | AuthPolicy) -> AuthPolicy:
        """Validate JSON-shaped sources without changing their merge precedence.

        Returns:
            The strict Auth policy from the already merged native sources.

        """
        if isinstance(value, cls.AuthPolicy):
            return value
        return cls.AuthPolicy.model_validate_json(
            FlextUtilities.json_value_adapter().dump_json(value, warnings="error"),
            strict=True,
        )


config: FlextAuthConfig = FlextAuthConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_auth import config``."""

__all__: list[str] = ["FlextAuthConfig", "config"]
