"""🚨 ARCHITECTURAL COMPLIANCE: ZERO EXCEPTION DUPLICATION using flext-core Factory.

✅ COMPLETE REFACTORING: 240+ lines of duplicated code ELIMINATED.

- BEFORE: 292 lines with 11 manual exception classes
- AFTER: <60 lines using clean and DRY factory pattern
- REDUCTION: 240+ lines eliminated = ~82% reduction
- PATTERN: Uses create_module_exception_classes() from flext-core
- ARCHITECTURE: Generic functionality remains in abstract libraries
- EXPOSURE: Correct public API through factory pattern

FLEXT Auth Exception Hierarchy - ZERO DUPLICATION.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

Type-safe error handling for authentication operations using factory pattern to eliminate duplication.
"""

from __future__ import annotations

# 🚨 ZERO DUPLICATION: Use flext-core exception factory - eliminates 240+ lines
from flext_core.exceptions import create_module_exception_classes

# Generate all standard exceptions using factory pattern
_auth_exceptions = create_module_exception_classes("flext_auth")

# Export factory-created exception classes (using actual factory keys)
FlextAuthError = _auth_exceptions["FlextAuthError"]
FlextAuthValidationError = _auth_exceptions["FlextAuthValidationError"]
FlextAuthConfigurationError = _auth_exceptions["FlextAuthConfigurationError"]
FlextAuthProcessingError = _auth_exceptions["FlextAuthProcessingError"]
FlextAuthConnectionError = _auth_exceptions["FlextAuthConnectionError"]
FlextAuthAuthenticationError = _auth_exceptions["FlextAuthAuthenticationError"]
FlextAuthTimeoutError = _auth_exceptions["FlextAuthTimeoutError"]

# Create backward-compatible aliases for existing code
FlextAuthSecurityError = FlextAuthProcessingError  # Security is processing domain
FlextAuthPermissionError = FlextAuthAuthenticationError  # Permission is auth domain
FlextAuthTokenError = FlextAuthAuthenticationError  # Token is auth domain
FlextAuthSessionError = FlextAuthProcessingError  # Session is processing domain


__all__ = [
    "FlextAuthAuthenticationError",
    "FlextAuthConfigurationError",
    "FlextAuthConnectionError",
    "FlextAuthError",
    "FlextAuthPermissionError",
    "FlextAuthProcessingError",
    "FlextAuthSecurityError",
    "FlextAuthSessionError",
    "FlextAuthTimeoutError",
    "FlextAuthTokenError",
    "FlextAuthValidationError",
]
