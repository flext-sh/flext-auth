"""Kerberos authentication provider implementation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_auth import c, m, p, r, t
from flext_auth.providers.kerberos_support import FlextAuthKerberosSupport
from flext_auth.providers.rfc import FlextAuthRfcProvider


class FlextAuthKerberosProvider(FlextAuthKerberosSupport, FlextAuthRfcProvider):
    """Kerberos authentication provider."""

    def __init__(self) -> None:
        """Initialize Kerberos provider with SOLID delegation.

        Uses composition for Kerberos ticket validation, service ticket handling,
        and authentication. Railway-oriented initialization with proper error handling.

        Raises:
            ValueError: If Kerberos configuration validation failed.
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

    @override
    def supports(self) -> set[str]:
        """Return Kerberos provider capabilities."""
        return {"kerberos", "sso", "enterprise", "ticket", "validate"}

    def validate_token(self, token: str) -> p.Result[m.Auth.AuthIdentity]:
        """Validate Kerberos token and return user.

        Returns:
            The resulting ``p.Result[m.Auth.AuthIdentity]``.
        """
        if not token.strip():
            return r[m.Auth.AuthIdentity].fail(
                "Kerberos token must be a non-empty string",
            )
        validator = self._ticket_validator_callable()
        if validator is None:
            claims_result = self._decode_token_claims(token)
            if claims_result.failure:
                return r[m.Auth.AuthIdentity].fail(
                    "Kerberos validation requires a configured ticket_validator"
                    " callback or JWT bridge settings (secret_key/issuer/audience)",
                )
            return self._identity_from_claims(claims_result.value)
        try:
            validator_payload = validator(token)
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[m.Auth.AuthIdentity].fail_op(
                "Kerberos ticket validator execution",
                exc,
            )
        return self._identity_from_validator_payload(validator_payload)

    @staticmethod
    def _identity_from_claims(
        claims: t.JsonMapping,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Build an identity from decoded claims on the Kerberos contact domain.

        Returns:
            The resulting ``p.Result[m.Auth.AuthIdentity]``.
        """
        domain = c.Auth.DEFAULT_KERBEROS_CONTACT_DOMAIN
        return r[m.Auth.AuthIdentity].from_validation(
            {**claims, c.Auth.KEY_CONTACT_DOMAIN: domain},
            m.Auth.AuthIdentity,
        )

    @classmethod
    def _identity_from_validator_payload(
        cls,
        payload: m.Auth.AuthIdentity | t.JsonMapping | m.Auth.KerberosTicketData,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Map a ticket validator payload to an identity.

        Returns:
            The resulting ``p.Result[m.Auth.AuthIdentity]``.
        """
        if isinstance(payload, m.Auth.AuthIdentity):
            return r[m.Auth.AuthIdentity].ok(payload)
        if isinstance(payload, m.Auth.KerberosTicketData):
            principal = payload.principal or c.Auth.DEFAULT_KERBEROS_USERNAME
            domain = c.Auth.DEFAULT_KERBEROS_CONTACT_DOMAIN
            return r[m.Auth.AuthIdentity].from_validation(
                {
                    c.Auth.KEY_IDENTITY_ID: principal,
                    c.Auth.KEY_NAME: principal,
                    c.Auth.KEY_CONTACT: f"{principal}@{domain}",
                    c.Auth.KEY_ROLES: [c.Auth.RoleTypes.USER.value],
                },
                m.Auth.AuthIdentity,
            )
        try:
            claims = t.json_mapping_adapter().validate_python(payload)
        except c.ValidationError as exc:
            return r[m.Auth.AuthIdentity].fail(
                f"Kerberos ticket validator mapping payload is invalid: {exc}",
                exception=exc,
            )
        return cls._identity_from_claims(claims)


__all__: t.MutableSequenceOf[str] = ["FlextAuthKerberosProvider"]
