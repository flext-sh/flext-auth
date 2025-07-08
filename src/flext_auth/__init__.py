"""FLEXT AUTH - Enterprise Authentication & Authorization with Zero Tolerance for Technical Debt.

Professional imports with proper package management.
"""

from __future__ import annotations

# Version
__version__ = "0.6.0"

# Professional imports from installed flext-core package
try:
    from flext_core import Entity, ServiceResult, ValueObject, get_config

    __all__ = ["Entity", "ServiceResult", "ValueObject", "__version__", "get_config"]
except ImportError as e:
    print(f"Warning: Could not import flext-core: {e}")
    __all__ = ["__version__"]

from .authorization_service import AuthorizationService
from .jwt_service import JWTService
from .service import (
    AuthenticationService,
    ServiceInMemoryRoleRepository,
    ServiceInMemoryUserRepository,
)
from .user_service import UserService

__all__ = [
    "AuthenticationService",
    "AuthorizationService",
    "JWTService",
    "ServiceInMemoryRoleRepository",
    "ServiceInMemoryUserRepository",
    "UserService",
]
