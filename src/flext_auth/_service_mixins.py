"""FlextAuth Service Mixins - Decomposed service concerns via MRO.

Each mixin represents one service domain responsibility.
Composed into FlextAuth facade via inheritance.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_auth import p, t
    from flext_auth.registry import FlextAuthRegistry


class FlextAuthProviderConcernMixin:
    """Provider management concern: registry and resolution.

    Provides provider lifecycle operations: fetch, register, list.
    Delegates to FlextAuthRegistry for persistence and resolution.
    """

    _registry: FlextAuthRegistry

    def fetch_provider(
        self, name: str
    ) -> p.Result[p.Auth.FlextAuthBaseProvider]:
        """Railway-oriented provider retrieval.

        Args:
            name: Provider identifier

        Returns:
            Result containing provider or error

        """
        return self._registry.get(name)

    def list_providers(self) -> t.StrSequence:
        """List all registered provider identifiers.

        Returns:
            Sequence of provider names

        """
        return self._registry.list_providers()

    def register_provider(
        self,
        name: str,
        provider: p.Auth.FlextAuthBaseProvider,
    ) -> p.Result[bool]:
        """Railway-oriented provider registration.

        Args:
            name: Provider identifier
            provider: Provider implementation

        Returns:
            Result indicating success or error

        """
        return self._registry.register_provider(name, provider)
