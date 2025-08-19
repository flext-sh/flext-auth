"""FLEXT Auth Mixins - Compatibility module for mixin classes.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

# This module provides a compatibility layer for mixin classes
# The actual implementations are in decorators.py

from flext_auth.decorators import (
    FlextAuthMixin,
    FlextAuthUserMixin,
    FlextAuthSessionMixin,
)

__all__ = [
    "FlextAuthMixin",
    "FlextAuthUserMixin", 
    "FlextAuthSessionMixin",
]