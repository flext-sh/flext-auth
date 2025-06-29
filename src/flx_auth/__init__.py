"""FLX Authentication System with Python 3.13 advanced patterns.

Zero boilerplate JWT authentication using reflection and modern cryptography.
"""

from flx_auth.jwt_service import JWTService, TokenPair
from flx_auth.models import Permission, Role, User
from flx_auth.security import PasswordHasher, SecurityHeaders
from flx_auth.service import AuthenticationService

__all__ = [
    "AuthenticationService",
    "JWTService",
    "PasswordHasher",
    "Permission",
    "Role",
    "SecurityHeaders",
    "TokenPair",
    "User",
]
