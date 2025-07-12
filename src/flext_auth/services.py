"""Consolidated authentication services using Python 3.13 patterns."""

from __future__ import annotations

from flext_auth.authorization_service import DefaultRoleManager
from flext_auth.authorization_service import RoleBasedAuthorizationService
from flext_auth.jwt_service import JWTConfig
from flext_auth.jwt_service import JWTService
from flext_auth.tokens import InMemoryTokenStorage
from flext_auth.tokens import RedisTokenStorage
from flext_auth.tokens import TokenBlacklist
from flext_auth.tokens import TokenManager
from flext_auth.tokens import TokenMetadata
from flext_auth.user_service import AuthenticationResponse
from flext_auth.user_service import PasswordHasherImpl
from flext_auth.user_service import SecurityAuditorImpl
from flext_auth.user_service import UserCreationRequest
from flext_auth.user_service import UserService

# Rate limiting will be implemented when flext_core.security is available
# TODO: Implement rate limiting when security module is added to flext-core

__all__ = [
    "AuthenticationResponse",
    "DefaultRoleManager",
    "InMemoryTokenStorage",
    # "InMemoryUserRepository", # Not imported
    "JWTConfig",
    # JWT Services
    "JWTService",
    # "LoginRequest", # Not imported
    "PasswordHasherImpl",
    # Modern Rate Limiting
    "RedisRateLimitManager",
    "RedisSlidingWindowLimiter",
    "RedisTokenBucketLimiter",
    "RedisTokenStorage",
    # Authorization Services
    "RoleBasedAuthorizationService",
    "SecurityAuditorImpl",
    "TokenBlacklist",
    # Token Management
    "TokenManager",
    "TokenMetadata",
    "UserCreationRequest",
    # User Services
    "UserService",
]


# ZERO TOLERANCE: NO LAZY IMPORTS - All imports at module level as required
# This eliminates the lazy loading __getattr__ function completely
