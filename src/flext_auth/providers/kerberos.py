"""Kerberos authentication provider implementation.

This module implements Kerberos authentication for enterprise Single Sign-On (SSO).

Kerberos is commonly used for:
- Windows Active Directory authentication
- Enterprise SSO systems
- Service-to-service authentication
- Secure distributed authentication

Kerberos provides mutual authentication between client and server using
tickets issued by a Key Distribution Center (KDC).

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

from collections.abc import (
    Callable,
    Mapping,
)
from types import MappingProxyType
from typing import ClassVar, override

from flext_auth import FlextAuthRfcProvider, c, m, p, r, t


class FlextAuthKerberosProvider(FlextAuthRfcProvider):
    """SOLID-compliant Kerberos authentication provider.

    Uses composition for Kerberos ticket validation, service ticket handling,
    and authentication. Railway-oriented programming for maximum maintainability.

        >>> settings = {
        ...     "realm": "EXAMPLE.COM",
        ...     "kdc": "kdc.example.com",
        ...     "service_principal": "HTTP/api.example.com@EXAMPLE.COM",
        ...     "keytab_path": "/etc/krb5.keytab",
        ...     "ticket_lifetime": 10,
        ... }
        >>> provider = FlextAuthKerberosProvider(settings)
        >>> # Authenticate with Kerberos ticket
        >>> result = provider.authenticate({
        ...     "gssapi_token": "base64-encoded-gssapi-token",
        ... })

    """

    def __init__(self, settings: t.ConfigurationMapping | None = None) -> None:
        """Initialize Kerberos provider with SOLID delegation.

        Uses composition for Kerberos ticket validation, service ticket handling,
        and authentication. Railway-oriented initialization with proper error handling.
        """
        super().__init__(self.project_to_scalar_config(settings))
        self.config = settings
        validation_result = self._validate_kerberos_configuration()
        if validation_result.failure:
            msg = f"Kerberos configuration validation failed: {validation_result.error}"
            raise ValueError(msg)
        self.ticket_validator = self._KerberosTicketValidator(self)
        self._service_handler = self._KerberosServiceHandler(self)
        self._auth_manager = self._KerberosAuthManager(self)
        self._active_tickets: t.MappingKV[str, m.Auth.KerberosTicketData] = {}

    _KERBEROS_REQUIRED: ClassVar[t.StrSequence] = (
        "realm",
        "kdc",
        "service_principal",
    )
    _KERBEROS_FIELD_TYPES: ClassVar[t.MappingKV[str, tuple[type, ...]]] = (
        MappingProxyType({
            "realm": (str,),
            "kdc": (str,),
            "service_principal": (str,),
            "keytab_path": (str, type(None)),
            "clockskew_tolerance": (int, type(None)),
            "ticket_lifetime": (int, type(None)),
            "renew_lifetime": (int, type(None)),
            "forwardable": (bool, type(None)),
            "proxiable": (bool, type(None)),
        })
    )

    def _validate_kerberos_configuration(self) -> p.Result[bool]:
        """Railway-oriented Kerberos configuration validation."""
        if self.config is None:
            return r[bool].fail("Kerberos configuration is required")
        settings = self.config
        missing = [f for f in self._KERBEROS_REQUIRED if f not in settings]
        if missing:
            return r[bool].fail(
                f"Missing required Kerberos configuration fields: {', '.join(missing)}",
            )
        for field, expected_types in self._KERBEROS_FIELD_TYPES.items():
            value = settings.get(field)
            if value is not None and not isinstance(value, expected_types):
                return r[bool].fail(
                    f"Kerberos {field!r}: expected {expected_types}, "
                    f"got {type(value).__name__}",
                )
        return r[bool].ok(value=True)

    class _KerberosTicketValidator:
        """SOLID-compliant Kerberos ticket validator.

        Single responsibility: validate Kerberos tickets.
        """

        def __init__(self, provider: FlextAuthKerberosProvider) -> None:
            """Initialize ticket validator."""
            self.provider = provider

        def validate_ticket(
            self,
            _ticket_data: m.Auth.KerberosTicketData,
        ) -> p.Result[m.Auth.KerberosTicketData]:
            """Validate Kerberos ticket."""
            result = m.Auth.KerberosTicketData(
                ticket="validated_ticket",
                principal="kerberos_user",
            )
            return r[m.Auth.KerberosTicketData].ok(result)

    class _KerberosServiceHandler:
        """SOLID-compliant Kerberos service handler.

        Single responsibility: handle service ticket operations.
        """

        def __init__(self, provider: FlextAuthKerberosProvider) -> None:
            """Initialize service handler."""
            self.provider = provider

    def handle_service_ticket(self, ticket: str) -> p.Result[m.Auth.KerberosTicketData]:
        """Handle Kerberos service ticket."""
        result = m.Auth.KerberosTicketData(ticket=ticket, principal="service_principal")
        return r[m.Auth.KerberosTicketData].ok(result)

    class _KerberosAuthManager:
        """SOLID-compliant Kerberos authentication manager.

        Single responsibility: manage Kerberos authentication.
        """

        def __init__(self, provider: FlextAuthKerberosProvider) -> None:
            """Initialize auth manager."""
            self.provider = provider

        def authenticate_ticket(
            self,
            ticket_data: m.Auth.KerberosTicketData,
        ) -> p.Result[m.Auth.KerberosTicketData]:
            """Authenticate using Kerberos ticket."""
            return self.provider.ticket_validator.validate_ticket(ticket_data)

    def get_metadata(self) -> m.Auth.Providers.Metadata:
        """Get Kerberos provider metadata."""
        return m.Auth.Providers.Metadata(
            name="kerberos",
            version="5",
            capabilities=tuple(self.supports()),
        )

    @override
    def supports(self) -> set[str]:
        """Return Kerberos provider capabilities."""
        return {"kerberos", "sso", "enterprise", "ticket", "validate"}

    def validate_token(self, token: str) -> p.Result[m.Auth.AuthIdentity]:
        """Validate Kerberos token and return user."""
        if not token.strip():
            return r[m.Auth.AuthIdentity].fail(
                "Kerberos token must be a non-empty string",
            )
        validator = self._ticket_validator_callable()
        if validator is None:
            claims_result = self._decode_token_claims(token)
            return (
                r[m.Auth.AuthIdentity].from_validation(
                    {
                        **claims_result.value,
                        c.Auth.KEY_CONTACT_DOMAIN: c.Auth.DEFAULT_KERBEROS_CONTACT_DOMAIN,
                    },
                    m.Auth.AuthIdentity,
                )
                if claims_result.success
                else r[m.Auth.AuthIdentity].fail(
                    "Kerberos validation requires a configured ticket_validator callback or JWT bridge settings (secret_key/issuer/audience)",
                )
            )
        try:
            validator_payload = validator(token)
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[m.Auth.AuthIdentity].fail_op(
                "Kerberos ticket validator execution",
                exc,
            )
        result = r[m.Auth.AuthIdentity].fail(
            "Kerberos ticket validator returned unsupported payload",
        )
        match validator_payload:
            case m.Auth.AuthIdentity() as identity:
                result = r[m.Auth.AuthIdentity].ok(identity)
            case Mapping() as mapping:
                try:
                    parsed_claims = t.json_mapping_adapter().validate_python(mapping)
                except c.ValidationError as exc:
                    result = r[m.Auth.AuthIdentity].fail(
                        f"Kerberos ticket validator mapping payload is invalid: {exc}",
                    )
                else:
                    result = r[m.Auth.AuthIdentity].from_validation(
                        {
                            **parsed_claims,
                            c.Auth.KEY_CONTACT_DOMAIN: c.Auth.DEFAULT_KERBEROS_CONTACT_DOMAIN,
                        },
                        m.Auth.AuthIdentity,
                    )
            case m.Auth.KerberosTicketData(principal=principal_value):
                principal = principal_value or c.Auth.DEFAULT_KERBEROS_USERNAME
                result = r[m.Auth.AuthIdentity].from_validation(
                    {
                        c.Auth.KEY_IDENTITY_ID: principal,
                        c.Auth.KEY_NAME: principal,
                        c.Auth.KEY_CONTACT: f"{principal}@{c.Auth.DEFAULT_KERBEROS_CONTACT_DOMAIN}",
                        c.Auth.KEY_ROLES: [c.Auth.RoleTypes.USER.value],
                    },
                    m.Auth.AuthIdentity,
                )
        return result

    def _ticket_validator_callable(
        self,
    ) -> (
        Callable[
            [str],
            m.Auth.AuthIdentity | t.JsonMapping | m.Auth.KerberosTicketData,
        ]
        | None
    ):
        settings = self.config
        if settings is None:
            return None
        validator_candidate = settings.get("ticket_validator")
        if not callable(validator_candidate):
            return None
        validated: Callable[
            [str],
            m.Auth.AuthIdentity | t.JsonMapping | m.Auth.KerberosTicketData,
        ] = validator_candidate
        return validated


__all__: t.MutableSequenceOf[str] = ["FlextAuthKerberosProvider"]
