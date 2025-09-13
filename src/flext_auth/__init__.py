"""FLEXT Auth - Enterprise authentication library following flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_auth.__version__ import __version__
from flext_auth.auth import FlextAuth
from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.models import (
    FlextAuthModels,
    authenticate_user,
    create_session,
    create_user,
)
from flext_auth.quickstart import flext_auth_quick_start

# Extract classes from nested structure for easier imports
AuthToken = FlextAuthModels.AuthToken
Role = FlextAuthModels.Role
Session = FlextAuthModels.Session
User = FlextAuthModels.User
UserCreationRequest = FlextAuthModels.UserCreationRequest

__all__ = [
    "AuthToken",
    "FlextAuth",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "FlextAuthModels",
    "FlextResult",
    "Role",
    "Session",
    "User",
    "UserCreationRequest",
    "__version__",
    "authenticate_user",
    "create_session",
    "create_user",
    "flext_auth_quick_start",
]
