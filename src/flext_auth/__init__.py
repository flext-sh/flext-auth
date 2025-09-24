"""FLEXT Auth - Enterprise authentication library following flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.__version__ import __version__
from flext_auth.auth import FlextAuth
from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.exceptions import FlextAuthExceptions
from flext_auth.mixins import (
    FlextAuthBusinessRulesMixin,
    FlextAuthFactoryMixin,
    FlextAuthValidationMixin,
)
from flext_auth.models import FlextAuthModels
from flext_auth.protocols import FlextAuthProtocols
from flext_auth.quickstart import FlextAuthQuickstart
from flext_auth.typings import FlextAuthTypes
from flext_core import FlextResult

__all__ = [
    "FlextAuth",
    "FlextAuthBusinessRulesMixin",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "FlextAuthExceptions",
    "FlextAuthFactoryMixin",
    "FlextAuthModels",
    "FlextAuthProtocols",
    "FlextAuthQuickstart",
    "FlextAuthTypes",
    "FlextAuthValidationMixin",
    "FlextResult",
    "__version__",
]
