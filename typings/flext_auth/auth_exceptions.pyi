from _typeshed import Incomplete

__all__ = [
    "FlextAccountInactiveError",
    "FlextAccountLockedError",
    "FlextAuthError",
    "FlextAuthenticationError",
    "FlextAuthorizationError",
    "FlextExpiredSessionError",
    "FlextExpiredTokenError",
    "FlextInsufficientPermissionError",
    "FlextInvalidCredentialsError",
    "FlextInvalidSessionError",
    "FlextInvalidTokenError",
    "FlextPasswordValidationError",
    "FlextPermissionError",
    "FlextRoleRequiredError",
    "FlextSessionError",
    "FlextTokenError",
    "FlextValidationError",
]

class FlextAuthError(Exception):
    message: Incomplete
    error_code: Incomplete
    def __init__(self, message: str, error_code: str = "AUTH_ERROR") -> None: ...

class FlextAuthenticationError(FlextAuthError):
    def __init__(self, message: str = "Authentication failed") -> None: ...

class FlextAuthorizationError(FlextAuthError):
    def __init__(self, message: str = "Access denied") -> None: ...

class FlextInvalidCredentialsError(FlextAuthenticationError):
    error_code: str
    def __init__(self, message: str = "Invalid credentials") -> None: ...

class FlextAccountLockedError(FlextAuthenticationError):
    error_code: str
    def __init__(self, message: str = "Account is locked") -> None: ...

class FlextAccountInactiveError(FlextAuthenticationError):
    error_code: str
    def __init__(self, message: str = "Account is inactive") -> None: ...

class FlextTokenError(FlextAuthError):
    def __init__(self, message: str) -> None: ...

class FlextInvalidTokenError(FlextTokenError):
    error_code: str
    def __init__(self, message: str = "Invalid token") -> None: ...

class FlextExpiredTokenError(FlextTokenError):
    error_code: str
    def __init__(self, message: str = "Token has expired") -> None: ...

class FlextSessionError(FlextAuthError):
    def __init__(self, message: str) -> None: ...

class FlextInvalidSessionError(FlextSessionError):
    error_code: str
    def __init__(self, message: str = "Invalid session") -> None: ...

class FlextExpiredSessionError(FlextSessionError):
    error_code: str
    def __init__(self, message: str = "Session has expired") -> None: ...

class FlextPermissionError(FlextAuthorizationError):
    error_code: str
    def __init__(self, message: str = "Permission denied") -> None: ...

class FlextInsufficientPermissionError(FlextPermissionError):
    required_permission: Incomplete
    def __init__(self, required_permission: str) -> None: ...

class FlextRoleRequiredError(FlextAuthorizationError):
    error_code: str
    required_role: Incomplete
    def __init__(self, required_role: str) -> None: ...

class FlextValidationError(FlextAuthError):
    field: Incomplete
    def __init__(self, message: str, field: str | None = None) -> None: ...

class FlextPasswordValidationError(FlextValidationError):
    error_code: str
    def __init__(
        self, message: str = "Password does not meet requirements"
    ) -> None: ...
