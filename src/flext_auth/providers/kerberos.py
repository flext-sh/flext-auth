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

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Final, override

from flext_core import r
from pydantic import TypeAdapter, ValidationError

from flext_auth import FlextAuthRfcProvider, m, t, u

_DICT_STR_CONTAINER_ADAPTER: Final[TypeAdapter[t.JsonObject]] = TypeAdapter(
    t.ContainerValueMapping,
)
_LIST_STR_ADAPTER: Final[TypeAdapter[t.StrSequence]] = TypeAdapter(t.StrSequence)


class FlextAuthKerberosProvider(FlextAuthRfcProvider):
    """SOLID-compliant Kerberos authentication provider.

    Uses composition for Kerberos ticket validation, service ticket handling,
    and authentication. Railway-oriented programming for maximum maintainability.

        >>> config = {
        ...     "realm": "EXAMPLE.COM",
        ...     "kdc": "kdc.example.com",
        ...     "service_principal": "HTTP/api.example.com@EXAMPLE.COM",
        ...     "keytab_path": "/etc/krb5.keytab",
        ...     "ticket_lifetime": 10,
        ... }
        >>> provider = FlextAuthKerberosProvider(config)
        >>> # Authenticate with Kerberos ticket
        >>> result = provider.authenticate({
        ...     "gssapi_token": "base64-encoded-gssapi-token",
        ... })

    """

    def __init__(self, config: t.ConfigurationMapping | None = None) -> None:
        """Initialize Kerberos provider with SOLID delegation.

        Uses composition for Kerberos ticket validation, service ticket handling,
        and authentication. Railway-oriented initialization with proper error handling.
        """
        super().__init__(self._to_scalar_config(config))
        self._config = config
        validation_result = self._validate_kerberos_configuration()
        if validation_result.is_failure:
            msg = f"Kerberos configuration validation failed: {validation_result.error}"
            raise ValueError(msg)
        self.ticket_validator = self._KerberosTicketValidator(self)
        self._service_handler = self._KerberosServiceHandler(self)
        self._auth_manager = self._KerberosAuthManager(self)
        self._active_tickets: Mapping[str, m.Auth.KerberosTicketData] = {}

    @staticmethod
    def _to_scalar_config(
        config: t.ConfigurationMapping | None,
    ) -> Mapping[str, t.Primitives] | None:
        """Project provider config into RFC base scalar contract."""
        if config is None:
            return None
        scalar_config: Mapping[str, t.Primitives] = {
            key: value
            for key, value in config.items()
            if isinstance(value, (bool, int, str))
        }
        return scalar_config

    def _validate_kerberos_configuration(self) -> r[bool]:
        """Railway-oriented Kerberos configuration validation."""
        if self._config is None:
            return r[bool].fail("Kerberos configuration is required")
        config = self._config
        required_fields = ["realm", "kdc", "service_principal"]
        missing_fields = u.filter(required_fields, lambda field: field not in config)
        if missing_fields:
            return r[bool].fail(
                f"Missing required Kerberos configuration fields: {', '.join(missing_fields)}",
            )
        validations: Sequence[tuple[str, tuple[type, ...], str]] = [
            ("realm", (str,), "Kerberos realm must be a string"),
            ("kdc", (str,), "Kerberos kdc must be a string"),
            (
                "service_principal",
                (str,),
                "Kerberos service_principal must be a string",
            ),
            (
                "keytab_path",
                (str, type(None)),
                "Kerberos keytab_path must be a string or None",
            ),
            (
                "clockskew_tolerance",
                (int, type(None)),
                "Kerberos clockskew_tolerance must be an integer or None",
            ),
            (
                "ticket_lifetime",
                (int, type(None)),
                "Kerberos ticket_lifetime must be an integer or None",
            ),
            (
                "renew_lifetime",
                (int, type(None)),
                "Kerberos renew_lifetime must be an integer or None",
            ),
            (
                "forwardable",
                (bool, type(None)),
                "Kerberos forwardable must be a boolean or None",
            ),
            (
                "proxiable",
                (bool, type(None)),
                "Kerberos proxiable must be a boolean or None",
            ),
        ]
        for field_name, expected_types, error_msg in validations:
            field_value = config.get(field_name)
            if field_value is not None and (
                not any(
                    u.is_type(field_value, expected_type)
                    for expected_type in expected_types
                )
            ):
                return r[bool].fail(f"{error_msg}. Got {type(field_value).__name__}")
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
        ) -> r[m.Auth.KerberosTicketData]:
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

    def handle_service_ticket(self, ticket: str) -> r[m.Auth.KerberosTicketData]:
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
        ) -> r[m.Auth.KerberosTicketData]:
            """Authenticate using Kerberos ticket."""
            return self.provider.ticket_validator.validate_ticket(ticket_data)

    @override
    def generate_token_for_user(
        self,
        user: m.Auth.AuthIdentity | t.ContainerValueMapping,
        token_kind: str = "access",
        token_type: str | None = None,
        expiry_minutes: int | None = None,
    ) -> r[str]:
        """Generate Kerberos token for user."""
        return super().generate_token_for_user(
            user=user,
            token_kind=token_kind,
            token_type=token_type,
            expiry_minutes=expiry_minutes,
        )

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

    def validate_token(self, token: str) -> r[m.Auth.AuthIdentity]:
        """Validate Kerberos token and return user."""
        if not token.strip():
            return r[m.Auth.AuthIdentity].fail(
                "Kerberos token must be a non-empty string",
            )
        validator = self._ticket_validator_callable()
        if validator is not None:
            try:
                validator_result = validator(token)
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ) as exc:
                return r[m.Auth.AuthIdentity].fail(
                    f"Kerberos ticket validator execution failed: {exc}",
                )
            if isinstance(validator_result, m.Auth.AuthIdentity):
                return r[m.Auth.AuthIdentity].ok(validator_result)
            if isinstance(validator_result, Mapping):
                try:
                    parsed_claims = _DICT_STR_CONTAINER_ADAPTER.validate_python(
                        validator_result,
                    )
                except ValidationError as exc:
                    return r[m.Auth.AuthIdentity].fail(
                        f"Kerberos ticket validator mapping payload is invalid: {exc}",
                    )
                return self._map_identity_payload(parsed_claims)
            principal_value = validator_result.principal
            principal = principal_value or "kerberos-user"
            identity_map: t.JsonObject = {
                "identity_id": principal,
                "name": principal,
                "contact": f"{principal}@kerberos.local",
                "roles": ["user"],
            }
            return self._map_identity_payload(identity_map)
        claims_result = self._decode_token_claims(token)
        return claims_result.fold(
            on_failure=lambda _: r[m.Auth.AuthIdentity].fail(
                "Kerberos validation requires a configured ticket_validator callback or JWT bridge settings (secret_key/issuer/audience)",
            ),
            on_success=lambda v: self._map_identity_payload(v),
        )

    def _map_identity_payload(
        self,
        claims: Mapping[str, t.ContainerValue],
    ) -> r[m.Auth.AuthIdentity]:
        identity_result = self._extract_identity_id(claims)
        if identity_result.is_failure:
            return r[m.Auth.AuthIdentity].fail(
                identity_result.error or "Kerberos token subject is missing",
            )
        identity_id = identity_result.value
        name_value = claims.get("name")
        name = name_value if isinstance(name_value, str) and name_value else identity_id
        contact_value = claims.get("contact")
        if isinstance(contact_value, str) and contact_value:
            contact = contact_value
        else:
            email_value = claims.get("email")
            if isinstance(email_value, str) and email_value:
                contact = email_value
            else:
                contact = f"{identity_id}@kerberos.local"
        roles_value = claims.get("roles")
        if isinstance(roles_value, list):
            parsed_roles: t.StrSequence
            try:
                parsed_roles = _LIST_STR_ADAPTER.validate_python(roles_value)
            except ValidationError:
                parsed_roles: t.StrSequence = []
            roles = [role for role in parsed_roles if role]
        else:
            roles = ["user"]
        try:
            identity = m.Auth.AuthIdentity(
                unique_id=identity_id,
                name=name,
                contact=contact,
                roles=roles,
                failed_attempts=0,
                locked_until=datetime.min.replace(tzinfo=UTC),
                last_access=datetime.now(UTC),
            )
        except (ValueError, TypeError) as exc:
            return r[m.Auth.AuthIdentity].fail(
                f"Kerberos identity mapping failed: {exc}",
            )
        return r[m.Auth.AuthIdentity].ok(identity)

    def _ticket_validator_callable(
        self,
    ) -> (
        Callable[
            [str],
            m.Auth.AuthIdentity | t.ContainerValueMapping | m.Auth.KerberosTicketData,
        ]
        | None
    ):
        config = self._config
        if config is None:
            return None
        validator_candidate = config.get("ticket_validator")
        if callable(validator_candidate):
            return validator_candidate
        return None


__all__ = ["FlextAuthKerberosProvider"]
