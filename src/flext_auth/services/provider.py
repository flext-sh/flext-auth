"""Provider concern mixin for the FlextAuth service facade."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth import p, t

if TYPE_CHECKING:
    from flext_auth.registry import FlextAuthRegistry


class FlextAuthProviderConcernMixin:
    """Provider lifecycle concern: fetch, list, and register."""

    _registry: FlextAuthRegistry

    def fetch_provider(self, name: str) -> p.Result[p.Auth.FlextAuthBaseProvider]:
        """Railway-oriented provider retrieval."""
        return self._registry.get(name)

    def list_providers(self) -> t.StrSequence:
        """List all registered provider identifiers."""
        return self._registry.list_providers()

    def register_provider(
        self,
        name: str,
        provider: p.Auth.FlextAuthBaseProvider,
    ) -> p.Result[bool]:
        """Railway-oriented provider registration."""
        return self._registry.register_provider(name, provider)
