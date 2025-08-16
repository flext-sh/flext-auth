"""FLEXT Auth Exception Hierarchy - ZERO DUPLICATION.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

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
