"""FLEXT Auth Mixins - Simple mixin classes for integration.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_auth.core import FlextAuth


class FlextAuthMixin:
    """Simple mixin to provide authentication capabilities to classes.

    This mixin provides a simple way to add authentication functionality
    to existing classes by composition rather than inheritance.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Initialize mixin - compatible with multiple inheritance."""
        super().__init__(*args, **kwargs)
        self._auth_service: FlextAuth | None = None
        self._auth_initialized: bool = False

    def init_auth(self, auth_service: FlextAuth | None) -> FlextResult[None]:
        """Initialize authentication service for this mixin."""
        try:
            self._auth_service = auth_service
            self._auth_initialized = True
            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Auth initialization failed: {e}")

    def get_auth_service(self) -> FlextAuth | None:
        """Get the current authentication service."""
        return self._auth_service

    def is_auth_initialized(self) -> bool:
        """Check if authentication service is initialized."""
        # Consider initialized if properly set via init_auth() OR if service is present
        return self._auth_initialized or self._auth_service is not None


__all__ = ["FlextAuthMixin"]
