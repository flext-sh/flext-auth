"""Legacy compatibility facade for container_services.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

This module is deprecated. Use 'flext_auth.container' instead.
"""

# Legacy compatibility facade
import warnings

from .container import *  # noqa: F403,F401

warnings.warn(
    "container_services module is deprecated, use 'flext_auth.container' instead",
    DeprecationWarning,
    stacklevel=2,
)
