# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_auth/_protocols/auth_identity_request
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_api import FlextApiProtocols

if TYPE_CHECKING:
    from flext_auth import t


class FlextAuthProtocolsAuthIdentityRequest:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class AuthIdentityRequest(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def name(self) -> str:
            """Unique identity name."""
            ...

        @property
        def contact(self) -> t.NonEmptyStr:
            """Contact info (email)."""
            ...

        @property
        def credential(self) -> str:
            """Credential (password/key)."""
            ...

        @property
        def full_name(self) -> str:
            """Full name."""
            ...

        @property
        def roles(self) -> Sequence[str]:
            """Roles."""
            ...


__all__: list[str] = [
    "FlextAuthProtocolsAuthIdentityRequest",
]
