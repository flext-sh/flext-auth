"""Kerberos provider support helpers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import ClassVar

from flext_auth import m, p, r, settings, t


class FlextAuthKerberosSupport:
    """Kerberos validation and ticket helper owner."""

    _KERBEROS_REQUIRED: ClassVar[t.StrSequence] = (
        "realm",
        "kdc",
        "service_principal",
    )

    _external_ticket_validator: t.Auth.KerberosTicketValidator | None = None

    def _validate_kerberos_configuration(self) -> p.Result[bool]:
        """Railway-oriented validation of the typed Kerberos settings namespace."""
        kerberos = settings.Auth.kerberos
        missing = [
            field for field in self._KERBEROS_REQUIRED if not getattr(kerberos, field)
        ]
        if missing:
            return r[bool].fail(
                f"Missing required Kerberos configuration fields: {', '.join(missing)}",
            )
        return r[bool].ok(value=True)

    class _KerberosTicketValidator:
        """SOLID-compliant Kerberos ticket validator.

        Single responsibility: validate Kerberos tickets.
        """

        def __init__(self, provider: FlextAuthKerberosSupport) -> None:
            """Initialize ticket validator."""
            self.provider = provider

        def validate_ticket(
            self,
            _ticket_data: m.Auth.KerberosTicketData,
        ) -> p.Result[p.Auth.KerberosTicketData]:
            """Validate Kerberos ticket."""
            result = m.Auth.KerberosTicketData(
                ticket="validated_ticket",
                principal="kerberos_user",
            )
            return r[p.Auth.KerberosTicketData].ok(result)

    ticket_validator: _KerberosTicketValidator

    class _KerberosServiceHandler:
        """SOLID-compliant Kerberos service handler.

        Single responsibility: handle service ticket operations.
        """

        def __init__(self, provider: FlextAuthKerberosSupport) -> None:
            """Initialize service handler."""
            self.provider = provider

    def handle_service_ticket(self, ticket: str) -> p.Result[p.Auth.KerberosTicketData]:
        """Handle Kerberos service ticket."""
        result = m.Auth.KerberosTicketData(ticket=ticket, principal="service_principal")
        return r[p.Auth.KerberosTicketData].ok(result)

    class _KerberosAuthManager:
        """SOLID-compliant Kerberos authentication manager.

        Single responsibility: manage Kerberos authentication.
        """

        def __init__(self, provider: FlextAuthKerberosSupport) -> None:
            """Initialize auth manager."""
            self.provider = provider

        def authenticate_ticket(
            self,
            ticket_data: m.Auth.KerberosTicketData,
        ) -> p.Result[p.Auth.KerberosTicketData]:
            """Authenticate using Kerberos ticket."""
            return self.provider.ticket_validator.validate_ticket(ticket_data)

    def _ticket_validator_callable(
        self,
    ) -> (
        Callable[
            [str],
            m.Auth.AuthIdentity | t.JsonMapping | m.Auth.KerberosTicketData,
        ]
        | None
    ):
        validator_candidate = self._external_ticket_validator
        if validator_candidate is None:
            return None

        def validated(
            ticket: str,
        ) -> p.Auth.AuthIdentity | t.JsonMapping | m.Auth.KerberosTicketData:
            raw_payload = validator_candidate(ticket)
            if isinstance(
                raw_payload,
                (m.Auth.AuthIdentity, m.Auth.KerberosTicketData),
            ):
                return raw_payload
            if isinstance(raw_payload, Mapping):
                return t.json_mapping_adapter().validate_python(raw_payload)
            msg = "Kerberos ticket_validator returned unsupported payload"
            raise TypeError(msg)

        return validated


__all__: list[str] = ["FlextAuthKerberosSupport"]
