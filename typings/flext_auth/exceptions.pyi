from _typeshed import Incomplete

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

FlextAuthError: Incomplete
FlextAuthValidationError: Incomplete
FlextAuthConfigurationError: Incomplete
FlextAuthProcessingError: Incomplete
FlextAuthConnectionError: Incomplete
FlextAuthAuthenticationError: Incomplete
FlextAuthTimeoutError: Incomplete
FlextAuthSecurityError = FlextAuthProcessingError
FlextAuthPermissionError = FlextAuthAuthenticationError
FlextAuthTokenError = FlextAuthAuthenticationError
FlextAuthSessionError = FlextAuthProcessingError
