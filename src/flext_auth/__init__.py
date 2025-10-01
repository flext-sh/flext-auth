"""FLEXT Auth - Enterprise authentication library following flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.__version__ import __version__
from flext_auth.api import FlextAuth
from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.exceptions import FlextAuthExceptions
from flext_auth.models import FlextAuthModels
from flext_auth.protocols import FlextAuthProtocols

# Provider system (v2.0.0 API)
from flext_auth.providers import (
    BaseAuthProvider,
    BaseAuthProviderMixin,
    JwtAuthProvider,
)
from flext_auth.registry import FlextAuthRegistry
from flext_auth.typings import FlextAuthTypes

# Note: FlextAuthUtilities and FlextAuthMixins are INTERNAL ONLY - not exported

__all__ = [
    # Core API (v1.0.0)
    "__version__",
    "BaseAuthProvider",
    "BaseAuthProviderMixin",
    "FlextAuth",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "FlextAuthExceptions",
    "FlextAuthModels",
    "FlextAuthProtocols",
    "FlextAuthRegistry",
    "FlextAuthTypes",
    "JwtAuthProvider",
]
