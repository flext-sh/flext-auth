"""Authentication identity models.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, Self

from flext_api import m, r, u

from flext_auth import c, p, t
from flext_auth._models.auth_credential import FlextAuthModelsAuthCredential


class FlextAuthModelsAuthIdentity:
    class AuthIdentity(m.Entity):
        """Generic identity/user entity with minimal fields."""

        # Reference to PasswordUtil for use in methods
        _password_util: type | None = (
            None  # Will be set to Auth.PasswordUtil at class definition time
        )

        name: Annotated[
            str,
            u.Field(
                ...,
                min_length=c.Auth.CREDENTIALS_USERNAME_MIN_LENGTH,
                max_length=c.Auth.CREDENTIALS_USERNAME_MAX_LENGTH,
                description="Unique identity name",
            ),
        ]
        contact: Annotated[str, u.Field(..., description="Contact info")]
        credential_hash: Annotated[
            str,
            u.Field(description="Hashed credential", exclude=True),
        ] = ""
        full_name: Annotated[str, u.Field(description="Full name")] = ""
        is_active: Annotated[bool, u.Field(description="Active status")] = True
        roles: t.StrSequence = u.Field(
            default_factory=lambda: [c.Auth.RoleTypes.USER.value],
            description="Roles",
        )
        permissions: t.StrSequence = u.Field(
            default_factory=tuple,
            description="List of permissions assigned to the identity",
        )
        failed_attempts: Annotated[
            t.NonNegativeInt,
            u.Field(description="Failed attempts"),
        ] = 0
        locked_until: datetime = u.Field(
            default_factory=lambda: datetime.min.replace(tzinfo=UTC),
            description="Lock time (datetime.min means not locked)",
        )
        last_access: datetime = u.Field(
            default_factory=lambda: datetime.min.replace(tzinfo=UTC),
            description="Last access (datetime.min means never accessed)",
        )

        # Additional attributes expected by tests
        token: Annotated[str, u.Field(description="Associated token", exclude=True)] = (
            ""
        )
        session_id: Annotated[str, u.Field(description="Session ID")] = ""

        @u.model_validator(mode="before")
        @classmethod
        def normalize_token_claims(
            cls,
            data: object,
        ) -> object:
            """Normalize OAuth/Kerberos claim payloads into identity fields.

            Pydantic hands before-model validators the raw untrusted input; the
            boundary parses it into a strictly keyed mapping before use.

            Returns:
                The resulting normalized mapping or the original input.
            """
            if isinstance(data, cls):
                return data
            if not isinstance(data, Mapping):
                return data
            # Boundary parse: the raw payload's keys and values are untyped.
            payload: dict[str, object] = {
                str(key): value for key, value in data.items()
            }
            if c.Auth.KEY_NAME in payload and c.Auth.KEY_CONTACT in payload:
                return data
            identity_candidates = tuple(
                value
                for value in (payload.get(key) for key in c.Auth.TOKEN_IDENTITY_KEYS)
                if u.string_non_empty(value)
            )
            identity_id = identity_candidates[0] if identity_candidates else ""
            if not identity_id:
                return data
            name_candidates = tuple(
                value
                for value in (payload.get(key) for key in c.Auth.TOKEN_NAME_KEYS)
                if u.string_non_empty(value)
            )
            name = name_candidates[0] if name_candidates else identity_id
            contact_candidates = tuple(
                value
                for value in (payload.get(key) for key in c.Auth.TOKEN_CONTACT_KEYS)
                if u.string_non_empty(value)
            )
            contact = contact_candidates[0] if contact_candidates else ""
            if not contact:
                domain_value = payload.get(c.Auth.KEY_CONTACT_DOMAIN)
                domain = (
                    domain_value
                    if u.string_non_empty(domain_value)
                    else c.Auth.DEFAULT_OAUTH_CONTACT_DOMAIN
                )
                contact = f"{identity_id}@{domain}"
            roles_value = payload.get(c.Auth.KEY_ROLES)
            if roles_value is None:
                scope_value = payload.get(c.Auth.KEY_SCOPE)
                scope_text = (
                    scope_value
                    if isinstance(scope_value, str) and u.string_non_empty(scope_value)
                    else ""
                )
                roles_value = (
                    [
                        scope
                        for scope in scope_text.split(c.Auth.SCOPE_SEPARATOR)
                        if scope
                    ]
                    if scope_text
                    else [c.Auth.RoleTypes.USER.value]
                )
            normalized: t.MutableMappingKV[str, t.JsonPayload | datetime] = {
                c.FIELD_ID: identity_id,
                c.Auth.KEY_NAME: name,
                c.Auth.KEY_CONTACT: contact,
                c.Auth.KEY_ROLES: roles_value,
            }
            normalized.update({
                field_name: field_value
                for field_name in c.Auth.TOKEN_IDENTITY_PASSTHROUGH_FIELDS
                if (field_value := payload.get(field_name)) is not None
            })
            return normalized

        def locked(self) -> bool:
            """Check if identity is locked.

            Returns:
                The resulting ``bool``.
            """
            if self.locked_until == datetime.min.replace(tzinfo=UTC):
                return False
            current_time: datetime = u.now()
            return current_time < self.locked_until

        def update_credential(self, credential: str) -> p.Result[bool]:
            """Update credential with bcrypt hashing via domain verb.

            Returns:
                The resulting ``p.Result[bool]``.
            """
            try:
                self.credential_hash = (
                    FlextAuthModelsAuthCredential.PasswordUtil.hash_password(credential)
                )
                return r[bool].ok(value=True)
            except c.EXC_BROAD_IO_TYPE as exc:
                return r[bool].fail(f"Failed to hash credential: {exc}", exception=exc)

        def verify_credential(self, credential: str) -> p.Result[bool]:
            """Verify a credential against stored hash using bcrypt.

            Returns:
                The resulting ``p.Result[bool]``.
            """
            try:
                valid = FlextAuthModelsAuthCredential.PasswordUtil.verify_password(
                    credential,
                    self.credential_hash,
                )
                return r[bool].ok(valid)
            except c.EXC_BROAD_IO_TYPE as exc:
                return r[bool].fail_op("Credential verification", exc)

        def with_successful_access(self) -> Self:
            """Record successful access (fluent interface).

            Returns:
                The resulting ``Self``.
            """
            self.last_access = u.now()
            self.failed_attempts = 0
            self.locked_until = datetime.min.replace(tzinfo=UTC)
            return self


__all__: list[str] = ["FlextAuthModelsAuthIdentity"]
