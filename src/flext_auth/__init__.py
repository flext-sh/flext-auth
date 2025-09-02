"""FLEXT Authentication Library - Enterprise authentication following flext-core patterns.

This module provides comprehensive authentication workflows, session management,
and security features using flext-core foundation patterns.

Architecture:
    Foundation Layer: Constants, exceptions, version (from flext-core)
    Domain Layer: Domain entities using FlextModels patterns
    Service Layer: Authentication, password, token services
    Infrastructure Layer: Container, config, logging integration
    Support Layer: Utilities, mixins, decorators

Core Components:
    FlextAuth: Main authentication service with railway-oriented programming
    FlextAuthModels: Domain models using flext-core Entity patterns
    FlextPasswordService: Secure bcrypt password operations
    FlextJWTService: JWT token generation and validation
    FlextAuthConstants: Authentication system constants (inherits FlextConstants)
    FlextAuthExceptions: Clean exception hierarchy (inherits FlextExceptions)


Examples:
    Basic authentication workflow:
    >>> auth = FlextAuth()
    >>> result = auth.authenticate_user("user", "pass")
    >>> if result.success:
    ...     user_data = result.value

    Railway-oriented error handling:
    >>> (
    ...     FlextAuth.create_user(data)
    ...     .flat_map(lambda u: auth.authenticate_user(u.username, password))
    ...     .map(lambda r: create_session(r))
    ...     .map_error(lambda e: f"Auth failed: {e}")
    ... )

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

# =============================================================================
# FOUNDATION LAYER - Import first, no dependencies on other modules
# =============================================================================

from flext_auth.__version__ import *
from flext_auth.constants import *
from flext_auth.exceptions import *

# =============================================================================
# DOMAIN LAYER - Depends only on Foundation layer
# =============================================================================

from flext_auth.models import *

# =============================================================================
# APPLICATION LAYER - Depends on Domain + Foundation layers
# =============================================================================

# Domain services - authentication business logic
from flext_auth.core import *

# =============================================================================
# INFRASTRUCTURE LAYER - Depends on Application + Domain + Foundation
# =============================================================================

from flext_auth.services import *
from flext_auth.config import *

# =============================================================================
# SUPPORT LAYER - Depends on layers as needed, imported last
# =============================================================================

from flext_auth.mixins import *
from flext_auth.utilities import *

# =============================================================================
# CONSOLIDATED EXPORTS - Combine all __all__ from modules
# =============================================================================

# Import FlextResult for convenience (re-export flext-core)
from flext_core import FlextResult

# Combine all __all__ exports from imported modules
import flext_auth.__version__ as _version
import flext_auth.config as _config
import flext_auth.constants as _constants
import flext_auth.core as _core
import flext_auth.exceptions as _exceptions
import flext_auth.mixins as _mixins
import flext_auth.models as _models
import flext_auth.services as _services
import flext_auth.utilities as _utilities

# Collect all __all__ exports from imported modules
_temp_exports: list[str] = ["FlextResult"]  # Add FlextResult to exports

for module in [
    _version,
    _constants,
    _exceptions,
    _models,
    _core,
    _services,
    _config,
    _mixins,
    _utilities,
]:
    if hasattr(module, "__all__"):
        _temp_exports.extend(module.__all__)

# Remove duplicates and sort for consistent exports - build complete list first
_seen: set[str] = set()
_final_exports: list[str] = []
for item in _temp_exports:
    if item not in _seen:
        _seen.add(item)
        _final_exports.append(item)
_final_exports.sort()

# Define __all__ as literal list for linter compatibility
# This dynamic assignment is necessary for aggregating module exports
__all__: list[str] = _final_exports  # pyright: ignore[reportUnsupportedDunderAll] # noqa: PLE0605
