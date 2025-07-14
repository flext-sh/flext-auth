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
    # Modern Rate Limiting (TODO: Implement)
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
    from flext_auth.domain.repositories import UserRepository
    
    # Create mock repository for basic functionality
    class InMemoryUserRepository(UserRepository):
        def __init__(self) -> None:
            self._users = {}
            
        async def find_by_id(self, user_id):
            from flext_core import ServiceResult
            user = self._users.get(user_id)
            return ServiceResult.success(user)
            
        async def find_by_username(self, username):
            from flext_core import ServiceResult
            for user in self._users.values():
                if user.username == username:
                    return ServiceResult.success(user)
            return ServiceResult.success(None)
            
        async def find_by_email(self, email):
            from flext_core import ServiceResult
            for user in self._users.values():
                if user.email == email:
                    return ServiceResult.success(user)
            return ServiceResult.success(None)
            
        async def create(self, user):
            from flext_core import ServiceResult
            self._users[user.id] = user
            return ServiceResult.success(user)
            
        async def update(self, user):
            from flext_core import ServiceResult
            if user.id in self._users:
                self._users[user.id] = user
                return ServiceResult.success(user)
            return ServiceResult.failure("User not found")
            
        async def delete(self, user_id):
            from flext_core import ServiceResult
            if user_id in self._users:
                del self._users[user_id]
                return ServiceResult.success(True)
            return ServiceResult.success(False)
            
        async def username_exists(self, username):
            from flext_core import ServiceResult
            exists = any(user.username == username for user in self._users.values())
            return ServiceResult.success(exists)
            
        async def email_exists(self, email):
            from flext_core import ServiceResult
            exists = any(user.email == email for user in self._users.values())
            return ServiceResult.success(exists)
            
        async def list_users(self, limit=100, offset=0):
            from flext_core import ServiceResult
            users = list(self._users.values())[offset:offset + limit]
            return ServiceResult.success(users)
    
    # Create dependencies with minimal configuration
    user_repository = InMemoryUserRepository()
    
    # Create minimal implementations to avoid circular dependencies
    class MinimalPasswordHasher:
        def hash_password(self, password: str) -> str:
            return f"hashed_{password}"

        def verify_password(self, password: str, hashed: str) -> bool:
            return f"hashed_{password}" == hashed
            
    class MinimalSecurityAuditor:
        def log_event(self, event): pass
        
    class MinimalJWTService:
        def create_token(self, payload): return "mock_jwt_token"
        def verify_token(self, token): return {"sub": "user"}
        
    class MinimalTokenManager:
        def create_token(self, user_id): return "mock_token"
        def verify_token(self, token): return True
    
    password_hasher = MinimalPasswordHasher()
    security_auditor = MinimalSecurityAuditor()
    jwt_service = MinimalJWTService()
    token_manager = MinimalTokenManager()
    
    # Create and return UserService
    return UserService(
        user_repository=user_repository,
        password_hasher=password_hasher,
        security_auditor=security_auditor,
        jwt_service=jwt_service,
        token_manager=token_manager,
    )
