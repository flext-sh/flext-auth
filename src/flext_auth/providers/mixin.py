"""FLEXT Auth provider mixin facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence
from typing import TYPE_CHECKING

from flext_auth.providers._mixins import (
    FlextAuthProviderToken,
    FlextAuthProviderValidation,
)

if TYPE_CHECKING:
    from flext_auth import t


class FlextAuthProvider(
    FlextAuthProviderToken,
    FlextAuthProviderValidation,
):
    """Common functionality for authentication providers."""

    _provider_config: Mapping[str, t.Scalar] | None

    def __init__(self, settings: Mapping[str, t.Scalar] | None = None) -> None:
        """Initialize provider mixin with optional configuration.

        Args:
            settings: Provider configuration mapping with scalar values.

        """
        super().__init__()
        self._provider_config = settings

    @property
    def settings(self) -> Mapping[str, t.Scalar] | None:
        """Provider configuration mapping."""
        return self._provider_config


__all__: MutableSequence[str] = ["FlextAuthProvider"]
