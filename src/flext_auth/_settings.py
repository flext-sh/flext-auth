"""Settings for flext-auth — namespaced under ``settings.Auth``.

Layer-0: imports only stdlib + ``pydantic_settings`` + ``FlextSettings`` / ``m``
/ ``t`` facades. The universal runtime fields (``debug``/``trace``/``log_level``/
``timezone``/``async_logging``) come from ``FlextSettings`` by MRO and are NOT
redeclared here. Every project
field lives inside the ``Auth`` namespace group with simple scalar types so each
is settable via ``.env`` / env vars / params (``FLEXT_AUTH_AUTH__SECRET_KEY`` …).
JWT/session/hashing defaults are inlined from
``flext_auth._constants.auth_security`` (SSOT); ``secret_key`` is env-provided
(plain ``str``, empty default) per the strict pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import ipaddress
import secrets
from typing import Annotated, Self
from urllib.parse import urlsplit

from flext_core import FlextSettings, m, t

from flext_auth._constants.base import FlextAuthConstantsBase


class FlextAuthSettings(FlextSettings):
    """Auth settings; all project fields under ``settings.Auth.*``."""

    model_config = m.SettingsConfigDict(
        env_prefix="FLEXT_AUTH_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # mro-wkii.17.25: publish the owned settings model used by service contracts.
    class AuthSettings(m.BaseModel):
        """Namespaced auth settings (JWT + session + hashing).

        Defaults live on the assignment side (checker-visible optional
        constructor parameters); the nested provider namespace is public
        (``KerberosSettings``) so ``default_factory`` type-checks without a
        TYPE_CHECKING split.
        """

        class KerberosSettings(m.BaseModel):
            """Namespaced Kerberos provider settings (realm/KDC/ticket policy)."""

            realm: Annotated[str, m.Field(description="Kerberos realm")] = ""
            kdc: Annotated[
                str,
                m.Field(description="Key Distribution Center host"),
            ] = ""
            service_principal: Annotated[
                str,
                m.Field(description="Service principal name (SPN)"),
            ] = ""
            keytab_path: Annotated[
                str | None,
                m.Field(description="Path to the keytab file"),
            ] = None
            clockskew_tolerance: Annotated[
                int | None,
                m.Field(description="Allowed clock skew in seconds"),
            ] = None
            ticket_lifetime: Annotated[
                int | None,
                m.Field(description="Ticket lifetime in seconds"),
            ] = None
            renew_lifetime: Annotated[
                int | None,
                m.Field(description="Renewable ticket lifetime in seconds"),
            ] = None
            forwardable: Annotated[
                bool | None,
                m.Field(description="Whether tickets are forwardable"),
            ] = None
            proxiable: Annotated[
                bool | None,
                m.Field(description="Whether tickets are proxiable"),
            ] = None

        class KeycloakSettings(m.BaseModel, extra="forbid"):
            """Keycloak realm settings; an empty issuer leaves Keycloak uncomposed."""

            issuer: Annotated[
                str,
                m.Field(description="Realm issuer URL (iss claim)"),
            ] = ""
            audience: Annotated[
                str,
                m.Field(description="Expected access-token audience (aud claim)"),
            ] = ""

            @m.field_validator("issuer", mode="after")
            @classmethod
            def _normalize_issuer(cls, value: str) -> str:
                """Normalize the realm issuer and require a trusted transport.

                Returns:
                    The issuer without a trailing slash, as Keycloak emits ``iss``.

                Raises:
                    ValueError: If the issuer is not https, or plain http on a
                        loopback host.

                """
                issuer = value.rstrip("/")
                if not issuer:
                    return issuer
                parts = urlsplit(issuer)
                host = parts.hostname or ""
                try:
                    loopback = ipaddress.ip_address(host).is_loopback
                except ValueError:
                    loopback = host == "localhost"
                if parts.scheme != "https" and not (
                    parts.scheme == "http" and loopback
                ):
                    msg = "Keycloak issuer must use https (plain http only on loopback)"
                    raise ValueError(msg)
                return issuer

            @m.model_validator(mode="after")
            def _require_audience_with_issuer(self) -> Self:
                """Reject a realm issuer configured without its audience.

                Returns:
                    The validated settings.

                Raises:
                    ValueError: If the issuer is set and the audience is empty.

                """
                if self.issuer and not self.audience:
                    msg = "Keycloak audience is required when issuer is set"
                    raise ValueError(msg)
                return self

        secret_key: str = m.Field(
            default_factory=lambda: secrets.token_urlsafe(
                FlextAuthConstantsBase.SECRET_MIN_LENGTH,
            ),
            description="JWT signing secret (env-provided; auto-generated).",
        )
        algorithm: Annotated[
            str,
            m.Field(description="JWT signing algorithm"),
        ] = "HS256"
        issuer: Annotated[
            str,
            m.Field(description="Token issuer claim"),
        ] = "flext-auth"
        audience: Annotated[
            str,
            m.Field(description="Token audience claim"),
        ] = "flext-auth-users"
        expiry_minutes: Annotated[
            int,
            m.Field(gt=0, description="Access token expiry in minutes"),
        ] = 1440
        session_expiry_minutes: Annotated[
            int,
            m.Field(gt=0, description="Session expiry in minutes"),
        ] = 1440
        max_sessions_per_user: Annotated[
            int,
            m.Field(gt=0, description="Max parallel sessions per user"),
        ] = 5
        hash_rounds: Annotated[
            int,
            m.Field(ge=4, le=31, description="Password hash rounds (bcrypt)"),
        ] = 12

        @m.field_validator("secret_key", mode="before")
        @classmethod
        def _normalize_secret_key(cls, value: str | t.SecretStr) -> str:
            """Unwrap a t.SecretStr input and enforce the min length when set.

            Returns:
                The resulting ``str``.

            Raises:
                ValueError: If secret_key must be at least 32 characters when provided.

            """
            plain = (
                value.get_secret_value() if isinstance(value, t.SecretStr) else value
            )
            if plain and len(plain) < FlextAuthConstantsBase.SECRET_MIN_LENGTH:
                msg = "secret_key must be at least 32 characters when provided"
                raise ValueError(msg)
            return plain

        @m.computed_field
        @property
        def auth_secret(self) -> t.SecretStr:
            """The JWT signing secret wrapped as a t.SecretStr."""
            return t.SecretStr(self.secret_key)

        # mro-j47u: close the AuthSettings rename without a legacy alias.
        Kerberos: KerberosSettings = m.Field(
            default_factory=KerberosSettings,
            description="Kerberos realm/KDC settings.",
        )
        Keycloak: KeycloakSettings = m.Field(
            default_factory=KeycloakSettings,
            description="Keycloak realm issuer/audience settings.",
        )

    Auth: AuthSettings = m.Field(
        default_factory=AuthSettings,
        description="Namespaced auth settings.",
    )


settings: FlextAuthSettings = FlextAuthSettings.fetch_global()
"""Pre-instantiated project settings singleton — ``from flext_auth import settings``."""

__all__: list[str] = ["FlextAuthSettings", "settings"]
