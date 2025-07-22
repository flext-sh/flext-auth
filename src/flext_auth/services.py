"""Consolidated authentication services using Python 3.13 patterns."""

from __future__ import annotations

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

# Rate limiting using real implementation
# Rate limiting patterns using flext-core security primitives

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
    # Modern Rate Limiting Implementation
    # "RedisRateLimitManager",
    # "RedisSlidingWindowLimiter",
    # "RedisTokenBucketLimiter",
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
    # Factory Functions
    "create_user_service",
]


# ZERO TOLERANCE: NO LAZY IMPORTS - All imports at module level as required
# This eliminates the lazy loading __getattr__ function completely


def create_user_service() -> UserService:
    """Factory function to create UserService with all required dependencies.

    Returns:
        UserService: Fully configured UserService instance ready for use.

    """
    # Initialize with real database connection
    import os

    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    # Use real enterprise repository implementation
    from flext_auth.infrastructure.persistence.user_repository import (
        PostgreSQLUserRepository,
    )

    database_url = os.getenv(
        "FLEXT_AUTH_DATABASE_URL",
        "postgresql+asyncpg://localhost/flext_auth",
    )

    engine = create_async_engine(database_url, echo=False)
    async_session_maker = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    user_repository = PostgreSQLUserRepository(async_session_maker)

    # Use real enterprise implementations with full functionality
    from flext_auth.infrastructure.implementations.authentication_implementation import (
        EnterpriseJWTService,
        EnterprisePasswordHasher,
        EnterpriseSecurityAuditor,
        EnterpriseTokenManager,
    )

    # Initialize real enterprise services with proper configuration
    password_hasher = EnterprisePasswordHasher(
        rounds=int(os.getenv("FLEXT_AUTH_BCRYPT_ROUNDS", "12")),
    )

    security_auditor = EnterpriseSecurityAuditor(database_session=async_session_maker)

    jwt_config = {
        "secret_key": os.getenv("FLEXT_AUTH_JWT_SECRET_KEY", "dev-secret-key"),
        "algorithm": os.getenv("FLEXT_AUTH_JWT_ALGORITHM", "HS256"),
        "access_token_expire_minutes": int(
            os.getenv("FLEXT_AUTH_ACCESS_TOKEN_EXPIRE_MINUTES", "30"),
        ),
        "refresh_token_expire_days": int(
            os.getenv("FLEXT_AUTH_REFRESH_TOKEN_EXPIRE_DAYS", "7"),
        ),
    }

    jwt_service = EnterpriseJWTService(jwt_config)

    # Initialize Redis connection for token management
    import redis.asyncio as redis

    redis_url = os.getenv("FLEXT_AUTH_REDIS_URL", "redis://localhost:6379/0")
    redis_client = redis.from_url(redis_url)

    token_manager = EnterpriseTokenManager(
        redis_client=redis_client,
        jwt_service=jwt_service,
    )

    # Create and return UserService
    from typing import cast
    return UserService(
        user_repository=user_repository,
        password_hasher=password_hasher,
        security_auditor=cast("object", security_auditor),
        jwt_service=cast("object", jwt_service),
        token_manager=cast("object", token_manager),
    )
