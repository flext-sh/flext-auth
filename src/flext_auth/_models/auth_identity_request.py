"""Authentication identity request models."""

from __future__ import annotations

from typing import Annotated

from flext_api import m, u
from flext_auth import c, t


class FlextAuthModelsAuthIdentityRequest:
    class AuthIdentityRequest(m.Value):
        """Generic identity creation request (immutable value object)."""

        name: Annotated[
            str,
            u.Field(
                ...,
                min_length=c.Auth.CREDENTIALS_USERNAME_MIN_LENGTH,
                max_length=c.Auth.CREDENTIALS_USERNAME_MAX_LENGTH,
                description="Unique identity name",
            ),
        ]
        contact: Annotated[
            t.NonEmptyStr,
            u.Field(
                ...,
                pattern=c.Auth.PATTERN_EMAIL,
                description="Contact info (email)",
            ),
        ]
        credential: Annotated[
            str,
            u.Field(
                ...,
                min_length=c.Auth.CREDENTIALS_PASSWORD_MIN_LENGTH,
                description="Credential (password/key)",
                exclude=True,
            ),
        ]
        full_name: Annotated[str, u.Field(description="Full name")] = ""
        roles: t.StrSequence = u.Field(
            default_factory=lambda: [c.Auth.RoleTypes.USER.value],
            description="Roles",
        )


__all__: list[str] = ["FlextAuthModelsAuthIdentityRequest"]
