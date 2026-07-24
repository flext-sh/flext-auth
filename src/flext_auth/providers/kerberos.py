"""Kerberos authentication provider implementation."""

from __future__ import annotations

from typing import override

from flext_auth import FlextAuthRfcProvider, c, m, p, r, t
from flext_auth.providers.kerberos_support import FlextAuthKerberosSupport


class FlextAuthKerberosProvider(FlextAuthKerberosSupport, FlextAuthRfcProvider):
    """Kerberos authentication provider."""

    def __init__(self) -> None:
        """Initialize Kerberos provider with SOLID delegation.

        Uses composition for Kerberos ticket validation, service ticket handling,
        and authentication. Railway-oriented initialization with proper error handling.
        """
        super().__init__()
        validation_result = self._validate_kerberos_configuration()
        if validation_result.failure:
            msg = f"Kerberos configuration validation failed: {validation_result.error}"
            raise ValueError(msg)
        self.ticket_validator = self._KerberosTicketValidator(self)
        self._service_handler = self._KerberosServiceHandler(self)
        self._auth_manager = self._KerberosAuthManager(self)
        self._active_tickets: t.MappingKV[str, m.Auth.KerberosTicketData] = {}

    def get_metadata(self) -> p.Auth.Providers.Metadata:
        """Get Kerberos provider metadata."""
        return m.Auth.Providers.Metadata(
            name="kerberos", version="5", capabilities=tuple(self.supports())
        )

    @override
    def supports(self) -> set[str]:
        """Return Kerberos provider capabilities."""
        return {"kerberos", "sso", "enterprise", "ticket", "validate"}

    def validate_token(self, token: str) -> p.Result[p.Auth.AuthIdentity]:
        """Validate Kerberos token and return user."""
        if not token.strip():
            return r[p.Auth.AuthIdentity].fail(
                "Kerberos token must be a non-empty string"
            )
        validator = self._ticket_validator_callable()
        if validator is None:
            claims_result = self._decode_token_claims(token)
            return (
                r[p.Auth.AuthIdentity].from_validation(
                    {
                        **claims_result.value,
                        c.Auth.KEY_CONTACT_DOMAIN: c.Auth.DEFAULT_KERBEROS_CONTACT_DOMAIN,
                    },
                    m.Auth.AuthIdentity,
                )
                if claims_result.success
                else r[p.Auth.AuthIdentity].fail(
                    "Kerberos validation requires a configured ticket_validator callback or JWT bridge settings (secret_key/issuer/audience)"
                )
            )
        try:
            validator_payload = validator(token)
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[p.Auth.AuthIdentity].fail_op(
                "Kerberos ticket validator execution", exc
            )
        if isinstance(validator_payload, m.Auth.AuthIdentity):
            return r[p.Auth.AuthIdentity].ok(validator_payload)
        if isinstance(validator_payload, m.Auth.KerberosTicketData):
            principal = validator_payload.principal or c.Auth.DEFAULT_KERBEROS_USERNAME
            return r[p.Auth.AuthIdentity].from_validation(
                {
                    c.Auth.KEY_IDENTITY_ID: principal,
                    c.Auth.KEY_NAME: principal,
                    c.Auth.KEY_CONTACT: f"{principal}@{c.Auth.DEFAULT_KERBEROS_CONTACT_DOMAIN}",
                    c.Auth.KEY_ROLES: [c.Auth.RoleTypes.USER.value],
                },
                m.Auth.AuthIdentity,
            )
        try:
            parsed_claims = t.json_mapping_adapter().validate_python(validator_payload)
        except c.ValidationError as exc:
            return r[p.Auth.AuthIdentity].fail(
                f"Kerberos ticket validator mapping payload is invalid: {exc}"
            )
        return r[p.Auth.AuthIdentity].from_validation(
            {
                **parsed_claims,
                c.Auth.KEY_CONTACT_DOMAIN: c.Auth.DEFAULT_KERBEROS_CONTACT_DOMAIN,
            },
            m.Auth.AuthIdentity,
        )


__all__: t.MutableSequenceOf[str] = ["FlextAuthKerberosProvider"]
