"""FLEXT Auth - Enterprise Authentication and Authorization Library.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

Modern authentication library following Clean Architecture and Domain-Driven Design.
Built on Python 3.13 with Pydantic V2 for type safety and performance.
"""

from __future__ import annotations

import importlib.metadata

# Import from flext-core for foundational patterns
from flext_core import FlextContainer, FlextDomainService, FlextResult

try:
    __version__ = importlib.metadata.version("flext-auth")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.7.0"

__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())

# Core application services
from flext_auth.application.services import (
    FlextAuthenticationService,
    FlextAuthorizationService,
    FlextSessionService,
)

# Configuration
from flext_auth.config import FlextAuthConfig, FlextAuthSettings

# Domain entities
from flext_auth.domain.entities import (
    FlextEmailVerificationToken,
    FlextPasswordResetToken,
    FlextPermission,
    FlextRole,
    FlextSession,
    FlextSessionStatus,
    FlextUser,
    FlextUserRole,
    FlextUserStatus,
)

# Platform
from flext_auth.platform import FlextAuthPlatform

# Simple API functions removed - use proper services instead

# Main FlextAuth aliases
FlextAuth = FlextAuthPlatform
FlextAuthResult = FlextResult
FlextAuthBaseModel = FlextDomainService

# Prefixed helper functions removed - use proper services instead

__all__ = [
    "FlextAuth",
    "FlextAuthBaseModel",
    "FlextAuthConfig",
    "FlextAuthPlatform",
    "FlextAuthResult",
    "FlextAuthSettings",
    "FlextAuthenticationService",
    "FlextAuthorizationService",
    "FlextContainer",
    "FlextDomainService",
    "FlextEmailVerificationToken",
    "FlextPasswordResetToken",
    "FlextPermission",
    "FlextResult",
    "FlextRole",
    "FlextSession",
    "FlextSessionService",
    "FlextSessionStatus",
    "FlextUser",
    "FlextUserRole",
    "FlextUserStatus",
    "__version__",
]

# Module metadata
__architecture__ = "Clean Architecture + DDD"


def create_flext_auth_platform(
    config: dict[str, object] | None = None,
) -> FlextAuthPlatform:
    """Create unified FLEXT Auth platform instance.

    Args:
        config: Optional configuration dictionary

    Returns:
        Configured FlextAuthPlatform instance

    """
    return FlextAuthPlatform(config or {})
