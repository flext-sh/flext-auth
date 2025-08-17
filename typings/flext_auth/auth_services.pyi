from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from _typeshed import Incomplete
from flext_core import FlextResult

from flext_auth.auth_models import FlextUser, FlextUserRole, InMemoryUserRepository
from flext_auth.auth_session import InMemorySessionRepository
from flext_auth.domain_entities import FlextPermission, FlextRole, FlextSession
from flext_auth.domain_value_objects import (
    FlextHashedPassword,
    FlextJWTClaims,
    FlextPlainPassword,
)

__all__ = [
    "AdminPermissionStrategy",
    "FlextAuthenticationService",
    "FlextAuthorizationService",
    "FlextJWTService",
    "FlextPasswordService",
    "FlextSessionService",
    "PasswordStrengthValidationStrategy",
    "PermissionCheckData",
    "PermissionStrategy",
    "RoleBasedPermissionStrategy",
    "ServiceDependencies",
    "UserValidationStrategy",
    "ValidationCommand",
    "ValidationStrategy",
]

class TokenType(StrEnum):
    ACCESS = ...
    REFRESH = ...

class FlextPasswordService:
    rounds: Incomplete
    def __init__(self, rounds: int = 12) -> None: ...
    def hash_password(
        self, plain_password: str | FlextPlainPassword
    ) -> FlextResult[FlextHashedPassword]: ...
    def verify_password(
        self,
        plain_password: str | FlextPlainPassword,
        hashed_password: str | FlextHashedPassword,
    ) -> FlextResult[bool]: ...
    def generate_secure_password(
        self, length: int = 16
    ) -> FlextResult[FlextPlainPassword]: ...
    def check_password_strength(
        self, password: str | FlextPlainPassword
    ) -> FlextResult[dict[str, object]]: ...
    def generate_password_reset_token(self) -> FlextResult[str]: ...
    def is_password_compromised(self, password: str) -> FlextResult[bool]: ...

class FlextJWTService:
    secret_key: Incomplete
    algorithm: Incomplete
    access_token_expire_minutes: Incomplete
    refresh_token_expire_days: Incomplete
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
    ) -> None: ...
    def generate_access_token(
        self,
        user_id: str,
        username: str,
        role: str,
        session_id: str | None = None,
        extra_claims: dict[str, str] | None = None,
    ) -> FlextResult[str]: ...
    def generate_refresh_token(
        self, user_id: str, session_id: str | None = None
    ) -> FlextResult[str]: ...
    def generate_token_pair(
        self,
        user_id: str,
        username: str,
        role: str,
        session_id: str,
        extra_claims: dict[str, str] | None = None,
    ) -> FlextResult[dict[str, str]]: ...
    def verify_token(self, token: str) -> FlextResult[FlextJWTClaims]: ...
    def refresh_access_token(self, refresh_token: str) -> FlextResult[str]: ...
    def extract_user_id(self, token: str) -> FlextResult[str]: ...
    def get_token_claims(self, token: str) -> FlextResult[FlextJWTClaims]: ...
    def get_token_expiry(self, token: str) -> FlextResult[datetime]: ...
    def is_token_expired(self, token: str) -> FlextResult[bool]: ...

@dataclass
class ValidationCommand:
    condition: bool
    error_message: str
    def execute(self) -> FlextResult[None]: ...

class ValidationStrategy(ABC):
    @abstractmethod
    def validate(self, **kwargs: object) -> FlextResult[None]: ...

class PasswordStrengthValidationStrategy(ValidationStrategy):
    MIN_PASSWORD_LENGTH: int
    def validate(self, **kwargs: object) -> FlextResult[None]: ...

class UserValidationStrategy(ValidationStrategy):
    MIN_USERNAME_LENGTH: int
    def validate(self, **kwargs: object) -> FlextResult[None]: ...

class PermissionStrategy(ABC):
    @abstractmethod
    def check_permission(
        self, check_data: PermissionCheckData
    ) -> FlextResult[bool]: ...

@dataclass(frozen=True)
class PermissionCheckData:
    user: FlextUser
    resource: str
    action: str
    roles: dict[str, FlextRole] | None = ...

class AdminPermissionStrategy(PermissionStrategy):
    def check_permission(
        self, check_data: PermissionCheckData
    ) -> FlextResult[bool]: ...

class RoleBasedPermissionStrategy(PermissionStrategy):
    def check_permission(
        self, check_data: PermissionCheckData
    ) -> FlextResult[bool]: ...

@dataclass
class ServiceDependencies:
    user_repo: InMemoryUserRepository
    session_repo: InMemorySessionRepository
    password_service: FlextPasswordService
    jwt_service: FlextJWTService
    password_validation_strategy: PasswordStrengthValidationStrategy
    user_validation_strategy: UserValidationStrategy
    REDACTED_LDAP_BIND_PASSWORD_permission_strategy: AdminPermissionStrategy
    role_permission_strategy: RoleBasedPermissionStrategy

class FlextAuthenticationService:
    def __init__(self) -> None: ...
    def create_user(
        self, username: str, email: str, password: str, role: FlextUserRole = ...
    ) -> FlextResult[FlextUser]: ...
    def authenticate_user(
        self, username: str, password: str, users: dict[str, FlextUser]
    ) -> FlextResult[FlextUser]: ...
    def change_password(
        self, user: FlextUser, current_password: str, new_password: str
    ) -> FlextResult[bool]: ...

class FlextAuthorizationService:
    def __init__(self) -> None: ...
    def create_role(
        self,
        name: str,
        description: str,
        permissions: list[FlextPermission] | None = None,
    ) -> FlextResult[FlextRole]: ...
    def check_permission(
        self,
        check_data: PermissionCheckData | FlextUser,
        resource: str | None = None,
        action: str | None = None,
        roles: dict[str, FlextRole] | None = None,
    ) -> FlextResult[bool]: ...
    def check_permission_legacy(
        self,
        user: FlextUser,
        resource: str,
        action: str,
        roles: dict[str, FlextRole] | None = None,
    ) -> FlextResult[bool]: ...
    def get_user_permissions(self, user: FlextUser) -> list[str]: ...

class FlextSessionService:
    def __init__(self) -> None: ...
    def create_session(
        self,
        user: FlextUser,
        expires_minutes: int = 60,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[FlextSession]: ...
    def validate_session(self, session: FlextSession) -> FlextResult[bool]: ...
    def revoke_session(self, session_id: str) -> FlextResult[bool]: ...
