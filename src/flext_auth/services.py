"""Consolidated authentication services using Python 3.13 patterns."""

from __future__ import annotations

# ZERO TOLERANCE: Import modern rate limiting from canonical location
from flext_core.security.redis_rate_limiting import (
    RedisRateLimitManager,
    RedisSlidingWindowLimiter,
    RedisTokenBucketLimiter,
)

from flext_auth.authorization_service import (
    DefaultRoleManager,
    RoleBasedAuthorizationService,
)
from flext_auth.jwt_service import JWTConfig, JWTService
from flext_auth.tokens import (
    InMemoryTokenStorage,
    RedisTokenStorage,
    TokenBlacklist,
    TokenManager,
    TokenMetadata,
)
from flext_auth.user_service import (
    AuthenticationResponse,
    PasswordHasherImpl,
    SecurityAuditorImpl,
    UserCreationRequest,
    UserService,
)

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
