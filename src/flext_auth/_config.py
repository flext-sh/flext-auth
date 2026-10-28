"""Typed, frozen business policy loaded by the canonical FLEXT config sources.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextConfig, FlextSettings
from pydantic import BaseModel, Field, JsonValue, TypeAdapter, field_validator


class FlextAuthConfig(FlextSettings, FlextConfig, strict=True):
    """Auth policy with native settings-source precedence and immutable models."""

    class AuthPolicy(
        BaseModel,
        extra="forbid",
        defer_build=True,
        validate_assignment=True,
        use_enum_values=True,
        str_strip_whitespace=False,
        strict=True,
        validate_default=True,
        frozen=True,
    ):
        """Business rules owned by the packaged and operator Auth YAML."""

        class Jwt(
            BaseModel,
            extra="forbid",
            defer_build=True,
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=False,
            strict=True,
            validate_default=True,
            frozen=True,
        ):
            """JWT policy defaults."""

            default_algorithm: str = Field(description="Default JWT signing algorithm.")
            default_expiry_minutes: int = Field(
                ge=1,
                description="Default JWT expiry in minutes.",
            )
            max_expiry_minutes: int = Field(
                ge=1,
                description="Maximum JWT expiry in minutes.",
            )
            issuer_claim: str = Field(description="Default JWT issuer claim.")
            audience_claim: str = Field(description="Default JWT audience claim.")
            min_secret_key_length: int = Field(
                ge=1,
                description="Minimum secret key length for JWT.",
            )
            default_token_type: str = Field(
                description="Default token type for Authorization header.",
            )

        class OAuth2(
            BaseModel,
            extra="forbid",
            defer_build=True,
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=False,
            strict=True,
            validate_default=True,
            frozen=True,
        ):
            """OAuth2 policy defaults."""

            default_scope: str = Field(description="Default OAuth2 scope.")
            flows: tuple[str, ...] = Field(description="Supported OAuth2 flows.")
            default_flow: str = Field(description="Default OAuth2 flow.")
            use_pkce_default: bool = Field(
                description="Whether to use PKCE by default."
            )
            token_endpoint_auth_methods: tuple[str, ...] = Field(
                description="Supported token endpoint authentication methods.",
            )
            default_token_endpoint_auth_method: str = Field(
                description="Default token endpoint authentication method.",
            )

        class Credentials(
            BaseModel,
            extra="forbid",
            defer_build=True,
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=True,
            strict=True,
            validate_default=True,
            frozen=True,
        ):
            """Credential validation defaults."""

            username_min_length: int = Field(
                ge=1, description="Minimum username length."
            )
            username_max_length: int = Field(
                ge=1, description="Maximum username length."
            )
            password_min_length: int = Field(
                ge=1, description="Minimum password length."
            )
            password_max_length: int = Field(
                ge=1, description="Maximum password length."
            )
            password_min_score: int = Field(
                ge=0,
                description="Minimum password strength score.",
            )
            password_min_bcrypt_hash_length: int = Field(
                ge=1,
                description="Minimum bcrypt hash length.",
            )
            password_bcrypt_rounds: int = Field(
                ge=4,
                le=31,
                description="Default bcrypt rounds.",
            )

        class Session(
            BaseModel,
            extra="forbid",
            defer_build=True,
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=True,
            strict=True,
            validate_default=True,
            frozen=True,
        ):
            """Session policy defaults."""

            default_expiry_minutes: int = Field(
                ge=1,
                description="Default session expiry in minutes.",
            )
            max_expiry_minutes: int = Field(
                ge=1,
                description="Maximum session expiry in minutes.",
            )
            max_sessions_per_user: int = Field(
                ge=1,
                description="Maximum sessions per user.",
            )
            min_token_length: int = Field(
                ge=1,
                description="Minimum session token length.",
            )

        class Security(
            BaseModel,
            extra="forbid",
            defer_build=True,
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=True,
            strict=True,
            validate_default=True,
            frozen=True,
        ):
            """Rate-limit and lockout defaults."""

            max_login_attempts: int = Field(
                ge=1,
                description="Maximum login attempts before lockout.",
            )
            lockout_duration_minutes: int = Field(
                ge=1,
                description="Lockout duration in minutes.",
            )
            max_requests_per_minute: int = Field(
                ge=1,
                description="Maximum requests per minute.",
            )
            max_requests_per_hour: int = Field(
                ge=1,
                description="Maximum requests per hour.",
            )

        class Validation(
            BaseModel,
            extra="forbid",
            defer_build=True,
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=True,
            strict=True,
            validate_default=True,
            frozen=True,
        ):
            """Generic validation length defaults."""

            short_name_max: int = Field(
                ge=1,
                description="Maximum length for short names.",
            )
            bcrypt_rounds: int = Field(
                ge=4,
                le=31,
                description="Bcrypt rounds for password hashing.",
            )
            default_token_expiry_minutes: int = Field(
                ge=1,
                description="Default token expiry in minutes.",
            )
            max_role_name_length: int = Field(
                ge=1,
                description="Maximum length for role names.",
            )
            max_role_description_length: int = Field(
                ge=1,
                description="Maximum length for role descriptions.",
            )
            max_permission_name_length: int = Field(
                ge=1,
                description="Maximum length for permission names.",
            )
            max_permission_description_length: int = Field(
                ge=1,
                description="Maximum length for permission descriptions.",
            )

        name: str = Field(description="Package identity name metadata.")
        version: str = Field(description="Package identity version metadata.")
        jwt: Jwt = Field(description="JWT policy defaults.")
        oauth2: OAuth2 = Field(
            description="OAuth2 policy defaults.",
        )
        credentials: Credentials = Field(
            description="Credential validation defaults.",
        )
        session: Session = Field(
            description="Session policy defaults.",
        )
        security: Security = Field(
            description="Rate-limit and lockout defaults.",
        )
        validation: Validation = Field(
            description="Generic validation length defaults.",
        )

    Auth: AuthPolicy

    @field_validator("Auth", mode="before")
    @classmethod
    def _parse_auth_policy(cls, value: JsonValue | AuthPolicy) -> AuthPolicy:
        """Validate JSON-shaped sources without changing their merge precedence.

        Returns:
            The strict Auth policy from the already merged native sources.

        """
        if isinstance(value, cls.AuthPolicy):
            return value
        return cls.AuthPolicy.model_validate_json(
            TypeAdapter(JsonValue).dump_json(value, warnings="error"),
            strict=True,
        )


config: FlextAuthConfig = FlextAuthConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_auth import config``."""

__all__: list[str] = ["FlextAuthConfig", "config"]
