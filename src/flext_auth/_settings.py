"""Settings for flext-auth — namespaced under ``settings.Auth``.

Layer-0: imports only stdlib + pydantic + ``FlextSettings``. The universal
runtime fields (``debug``/``trace``/``log_level``/``timezone``/``async_logging``)
come from ``FlextSettings`` by MRO and are NOT redeclared here. Every project
field lives inside the ``Auth`` namespace group with simple scalar types so each
is settable via ``.env`` / env vars / params (``FLEXT_AUTH_AUTH__SECRET_KEY`` …).
JWT/session/hashing defaults are inlined from
``flext_auth._constants.auth_security`` (SSOT); ``secret_key`` is env-provided
(plain ``str``, empty default) per the strict pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Annotated, Final

from pydantic import BaseModel, Field, SecretStr, computed_field, field_validator
from pydantic_settings import SettingsConfigDict

from flext_core import FlextSettings

_SECRET_MIN_LENGTH: Final[int] = 32


class FlextAuthSettings(FlextSettings):
    """Auth settings; all project fields under ``settings.Auth.*``."""

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_AUTH_", env_nested_delimiter="__", extra="ignore"
    )

    # mro-wkii.17.25: publish the owned settings model used by service contracts.
    class AuthSettings(BaseModel):
        """Namespaced auth settings (JWT + session + hashing)."""

        class _Kerberos(BaseModel):
            """Namespaced Kerberos provider settings (realm/KDC/ticket policy)."""

            realm: Annotated[str, Field(default="", description="Kerberos realm")]
            kdc: Annotated[
                str, Field(default="", description="Key Distribution Center host")
            ]
            service_principal: Annotated[
                str, Field(default="", description="Service principal name (SPN)")
            ]
            keytab_path: Annotated[
                str | None, Field(default=None, description="Path to the keytab file")
            ]
            clockskew_tolerance: Annotated[
                int | None,
                Field(default=None, description="Allowed clock skew in seconds"),
            ]
            ticket_lifetime: Annotated[
                int | None,
                Field(default=None, description="Ticket lifetime in seconds"),
            ]
            renew_lifetime: Annotated[
                int | None,
                Field(default=None, description="Renewable ticket lifetime in seconds"),
            ]
            forwardable: Annotated[
                bool | None,
                Field(default=None, description="Whether tickets are forwardable"),
            ]
            proxiable: Annotated[
                bool | None,
                Field(default=None, description="Whether tickets are proxiable"),
            ]

        secret_key: Annotated[
            str,
            Field(
                default_factory=lambda: secrets.token_urlsafe(_SECRET_MIN_LENGTH),
                description="JWT signing secret (env-provided; auto-generated).",
            ),
        ]
        algorithm: Annotated[
            str, Field(default="HS256", description="JWT signing algorithm")
        ]
        issuer: Annotated[
            str, Field(default="flext-auth", description="Token issuer claim")
        ]
        audience: Annotated[
            str, Field(default="flext-auth-users", description="Token audience claim")
        ]
        expiry_minutes: Annotated[
            int, Field(default=1440, gt=0, description="Access token expiry in minutes")
        ]
        session_expiry_minutes: Annotated[
            int, Field(default=1440, gt=0, description="Session expiry in minutes")
        ]
        max_sessions_per_user: Annotated[
            int, Field(default=5, gt=0, description="Max parallel sessions per user")
        ]
        hash_rounds: Annotated[
            int,
            Field(default=12, ge=4, le=31, description="Password hash rounds (bcrypt)"),
        ]

        @field_validator("secret_key", mode="before")
        @classmethod
        def _normalize_secret_key(cls, value: str | SecretStr) -> str:
            """Unwrap a SecretStr input and enforce the min length when set."""
            plain = value.get_secret_value() if isinstance(value, SecretStr) else value
            if plain and len(plain) < _SECRET_MIN_LENGTH:
                msg = "secret_key must be at least 32 characters when provided"
                raise ValueError(msg)
            return plain

        @computed_field
        @property
        def auth_secret(self) -> SecretStr:
            """The JWT signing secret wrapped as a SecretStr."""
            return SecretStr(self.secret_key)

        kerberos: Annotated[
            _Kerberos,
            Field(
                # mro-j47u: close the AuthSettings rename without a legacy alias.
                default_factory=lambda: FlextAuthSettings.AuthSettings._Kerberos(),
                description="Kerberos realm/KDC settings.",
            ),
        ]

    if TYPE_CHECKING:
        Auth: AuthSettings
    else:
        Auth: AuthSettings = Field(
            default_factory=AuthSettings, description="Namespaced auth settings."
        )


settings: FlextAuthSettings = FlextAuthSettings.fetch_global()
"""Pre-instantiated project settings singleton — ``from flext_auth import settings``."""

__all__: list[str] = ["FlextAuthSettings", "settings"]
