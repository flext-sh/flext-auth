"""flext-auth config models — typed business-rule shapes.

Frozen Pydantic shapes for the ``config/auth.yaml`` business-rule SSOT.
The ``_config.py`` facade validates the model-less YAML slice into these
classes and exposes the ready objects under ``config.Auth``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FlextAuthConfigModels:
    """Namespace of typed flext-auth config models."""

    class Jwt(BaseModel):
        """JWT policy defaults."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        default_algorithm: str = Field(
            description="Default JWT signing algorithm.",
        )
        default_expiry_minutes: int = Field(
            ge=1,
            description="Default JWT expiry in minutes.",
        )
        max_expiry_minutes: int = Field(
            ge=1,
            description="Maximum JWT expiry in minutes.",
        )
        issuer_claim: str = Field(
            description="Default JWT issuer claim.",
        )
        audience_claim: str = Field(
            description="Default JWT audience claim.",
        )
        min_secret_key_length: int = Field(
            ge=1,
            description="Minimum secret key length for JWT.",
        )
        default_token_type: str = Field(
            description="Default token type for Authorization header.",
        )

    class OAuth2(BaseModel):
        """OAuth2 policy defaults."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        default_scope: str = Field(
            description="Default OAuth2 scope.",
        )
        flows: tuple[str, ...] = Field(
            description="Supported OAuth2 flows.",
        )
        default_flow: str = Field(
            description="Default OAuth2 flow.",
        )
        use_pkce_default: bool = Field(
            description="Whether to use PKCE by default.",
        )
        token_endpoint_auth_methods: tuple[str, ...] = Field(
            description="Supported token endpoint authentication methods.",
        )
        default_token_endpoint_auth_method: str = Field(
            description="Default token endpoint authentication method.",
        )

    class Credentials(BaseModel):
        """Credential validation defaults."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        username_min_length: int = Field(
            ge=1,
            description="Minimum username length.",
        )
        username_max_length: int = Field(
            ge=1,
            description="Maximum username length.",
        )
        password_min_length: int = Field(
            ge=1,
            description="Minimum password length.",
        )
        password_max_length: int = Field(
            ge=1,
            description="Maximum password length.",
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

    class Session(BaseModel):
        """Session policy defaults."""

        model_config = ConfigDict(frozen=True, extra="forbid")

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

    class Security(BaseModel):
        """Rate-limit and lockout defaults."""

        model_config = ConfigDict(frozen=True, extra="forbid")

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

    class Validation(BaseModel):
        """Generic validation length defaults."""

        model_config = ConfigDict(frozen=True, extra="forbid")

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

    class Auth(BaseModel):
        """Root auth business-rule namespace."""

        model_config = ConfigDict(frozen=True, extra="forbid")

        jwt: FlextAuthConfigModels.Jwt = Field(
            description="JWT policy defaults.",
        )
        oauth2: FlextAuthConfigModels.OAuth2 = Field(
            description="OAuth2 policy defaults.",
        )
        credentials: FlextAuthConfigModels.Credentials = Field(
            description="Credential validation defaults.",
        )
        session: FlextAuthConfigModels.Session = Field(
            description="Session policy defaults.",
        )
        security: FlextAuthConfigModels.Security = Field(
            description="Rate-limit and lockout defaults.",
        )
        validation: FlextAuthConfigModels.Validation = Field(
            description="Generic validation length defaults.",
        )

    class Root(BaseModel):
        """Root flext-auth config validated from ``config/*.yaml``."""

        model_config = ConfigDict(frozen=True, extra="ignore")

        Auth: FlextAuthConfigModels.Auth = Field(
            description="Auth business-rule config namespace.",
        )


__all__: list[str] = ["FlextAuthConfigModels"]
