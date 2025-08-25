"""FLEXT Auth Mixins - Module for mixin classes.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

# This module provides mixin classes
# The actual implementations are in decorators.py

# Direct imports to avoid circular dependencies
from .decorators import (
    FlextAuthMixin,
    FlextAuthSessionMixin,
    FlextAuthUserMixin,
)

__all__ = [
    "FlextAuthMixin",
    "FlextAuthSessionMixin",
    "FlextAuthUserMixin",
]
