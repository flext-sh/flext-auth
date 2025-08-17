from abc import ABC, abstractmethod
from dataclasses import dataclass

from flext_core import FlextResult

from flext_auth.auth import (
    FlextAuthService as FlextAuthService,
    FlextAuthServiceConfig as FlextAuthServiceConfig,
    FlextAuthServiceDependencies as FlextAuthServiceDependencies,
)
from flext_auth.constants import TEST_JWT_SECRET as TEST_JWT_SECRET
from flext_auth.domain_entities import (
    FlextPermission as FlextPermission,
    FlextRole as FlextRole,
    FlextSession as FlextSession,
    FlextSessionStatus as FlextSessionStatus,
    FlextUser as FlextUser,
    FlextUserRole as FlextUserRole,
    FlextUserStatus as FlextUserStatus,
)
from flext_auth.jwt import FlextJWTService as FlextJWTService
from flext_auth.services_password_service import (
    FlextPasswordService as FlextPasswordService,
)
from flext_auth.session import InMemorySessionRepository as InMemorySessionRepository
from flext_auth.user import InMemoryUserRepository as InMemoryUserRepository

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
    auth_service: FlextAuthService
    password_validation_strategy: PasswordStrengthValidationStrategy
    user_validation_strategy: UserValidationStrategy
    REDACTED_LDAP_BIND_PASSWORD_permission_strategy: AdminPermissionStrategy
    role_permission_strategy: RoleBasedPermissionStrategy

@dataclass(frozen=True)
class PermissionCheckData:
    user: FlextUser
    resource: str
    action: str
    roles: dict[str, FlextRole] | None = ...

PASSWORD_CHANGE_SUCCESS: bool
PERMISSION_GRANTED: bool
PERMISSION_DENIED: bool
SESSION_VALID: bool
SESSION_INVALID: bool
LOGOUT_SUCCESS: bool

class FlextAuthenticationService:
    def __init__(self) -> None: ...
    def create_user(
        self, username: str, email: str, password: str, role: FlextUserRole = ...
    ) -> FlextResult[FlextUser]: ...
    def authenticate_user(
        self, username: str, password: str, users: dict[str, FlextUser]
    ) -> FlextResult[FlextUser]: ...
    def change_password(
        self, user: FlextUser, _current_password: str, new_password: str
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
