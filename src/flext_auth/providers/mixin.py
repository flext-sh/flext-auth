"""FLEXT Auth provider mixin facade."""

from __future__ import annotations

from flext_auth import t
from flext_auth.providers._mixins.tokens import FlextAuthProviderTokenMixin
from flext_auth.providers._mixins.validation import FlextAuthProviderValidationMixin


class FlextAuthProviderMixin(
    FlextAuthProviderTokenMixin,
    FlextAuthProviderValidationMixin,
):
    """Common functionality for authentication providers."""

    _provider_config: t.ScalarMapping | None

    def __init__(self, settings: t.ScalarMapping | None = None) -> None:
        """Initialize provider mixin with optional configuration.

        Args:
            settings: Provider configuration mapping with scalar values.

        """
        super().__init__()
        self._provider_config = settings

    @property
    def settings(self) -> t.ScalarMapping | None:
        """Get provider configuration."""
        return self._provider_config


__all__: t.MutableSequenceOf[str] = ["FlextAuthProviderMixin"]
