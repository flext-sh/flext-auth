"""Authentication identity models.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, Self, cast

from flext_api import m, r, u

from flext_auth import c, p, t
from flext_auth._models import FlextAuthModelsAuthCredential


class FlextAuthModelsAuthIdentity:
    """Identity entity model namespace."""

    class AuthIdentity(m.Entity):
        """Generic identity/user entity with minimal fields."""

        # Reference to PasswordUtil for use in methods
        _password_util: type | None = (
            None  # Will be set to Auth.PasswordUtil at class definition time
        )

        name: Annotated[
            str,
            m.Field(
                ...,
                min_length=c.Auth.CREDENTIALS_USERNAME_MIN_LENGTH,
                max_length=c.Auth.CREDENTIALS_USERNAME_MAX_LENGTH,
                description="Unique identity name",
            ),
        ]
        contact: Annotated[str, m.Field(..., description="Contact info")]
        credential_hash: Annotated[
            str,
            m.Field(description="Hashed credential", exclude=True),
        ] = ""
        full_name: Annotated[str, m.Field(description="Full name")] = ""
        is_active: Annotated[bool, m.Field(description="Active status")] = True
        roles: t.StrSequence = m.Field(
            default_factory=lambda: [c.Auth.RoleTypes.USER.value],
            description="Roles",
        )
        permissions: t.StrSequence = m.Field(
            default_factory=tuple,
            description="List of permissions assigned to the identity",
        )
        failed_attempts: Annotated[
            t.NonNegativeInt,
            m.Field(description="Failed attempts"),
        ] = 0
        locked_until: datetime = m.Field(
            default_factory=lambda: datetime.min.replace(tzinfo=UTC),
            description="Lock time (datetime.min means not locked)",
        )
        last_access: datetime = m.Field(
            default_factory=lambda: datetime.min.replace(tzinfo=UTC),
            description="Last access (datetime.min means never accessed)",
        )

        # Additional attributes expected by tests
        token: Annotated[str, m.Field(description="Associated token", exclude=True)] = (
            ""
        )
        session_id: Annotated[str, m.Field(description="Session ID")] = ""

        @m.model_validator(mode="before")
        @classmethod
        def normalize_token_claims[TPayload](
            cls,
            data: TPayload,
        ) -> TPayload | t.MutableMappingKV[str, t.JsonPayload]:
            """Normalize OAuth/Kerberos claim payloads into identity fields.

            Pydantic hands before-model validators the raw untrusted input; the
            boundary parses it into a strictly keyed mapping before use.

            Args:
                data: Raw model input, typically a token claim mapping.

            Returns:
                The normalized mapping, or the original input untouched when
                no claim normalization applies.

            """
            original: TPayload = data
            if isinstance(data, cls):
                return original
            if not isinstance(data, Mapping):
                return original
            # Boundary parse (rule 6): the raw payload keys and values are
            # untrusted input; the JsonPayload contract is enforced by the
            # typed model this validator feeds, so the parse re-keys once and
            # hands the mapping downstream in the fleet's JSON vocabulary.
            typed_payload = cast("Mapping[str, t.JsonPayload]", data)
            payload: t.MutableMappingKV[str, t.JsonPayload] = dict(typed_payload)
            if c.Auth.KEY_NAME in payload and c.Auth.KEY_CONTACT in payload:
                return original
            identity_candidates = tuple(
                value
                for value in (payload.get(key) for key in c.Auth.TOKEN_IDENTITY_KEYS)
                if u.string_non_empty(value)
            )
            identity_id = identity_candidates[0] if identity_candidates else ""
            if not identity_id:
                return original
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
            roles_value: t.JsonPayload = payload.get(c.Auth.KEY_ROLES)
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
                Whether the lockout window is still in effect.

            """
            if self.locked_until == datetime.min.replace(tzinfo=UTC):
                return False
            current_time: datetime = u.now()
            return current_time < self.locked_until

        def update_credential(self, credential: str) -> p.Result[bool]:
            """Update credential with bcrypt hashing via domain verb.

            Args:
                credential: Plain credential to hash and store.

            Returns:
                Success once the hash is stored; failure when hashing fails.

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

            Args:
                credential: Plain credential to check.

            Returns:
                Success wrapping the match outcome; failure on verification
                errors.

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
            """Record a successful access and reset the failure counters.

            Returns:
                This entity, for fluent chaining.

            """
            self.last_access = u.now()
            self.failed_attempts = 0
            self.locked_until = datetime.min.replace(tzinfo=UTC)
            return self


__all__: list[str] = ["FlextAuthModelsAuthIdentity"]
