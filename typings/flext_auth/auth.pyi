from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from _typeshed import Incomplete
from flext_core import FlextResult

from flext_auth.constants import FlextAuthConstants as FlextAuthConstants
from flext_auth.domain_entities import (
    FlextSession as Session,
    FlextUser as User,
    FlextUserRole as UserRole,
)
from flext_auth.domain_value_objects import (
    FlextJWTClaims as JWTClaims,
    FlextSecurityContext as SecurityContext,
)
from flext_auth.jwt import FlextJWTService as JWTService
from flext_auth.services_password_service import FlextPasswordService as PasswordService
from flext_auth.session import SessionRepository as SessionRepository
from flext_auth.user import UserRepository as UserRepository

type TokenValidator = Callable[[str], Awaitable[FlextResult[JWTClaims]]]
type UserValidator = Callable[[JWTClaims], Awaitable[FlextResult[User]]]
type SessionValidator = Callable[[JWTClaims], Awaitable[FlextResult[None]]]
type ResultCreator = Callable[
    [User, JWTClaims], Awaitable[FlextResult[SecurityContext | dict[str, str]]]
]
type SecurityContextCreator = Callable[
    [User, JWTClaims], Awaitable[FlextResult[SecurityContext]]
]
type TokenCreator = Callable[[User, JWTClaims], Awaitable[FlextResult[dict[str, str]]]]
REFRESH_TOKEN_TYPE: Incomplete
logger: Incomplete

@dataclass(frozen=True)
class LoginAttemptData:
    username: str
    ip_address: str
    user_agent: str | None
    success: bool
    failure_reason: str | None

@dataclass
class FlextAuthServiceConfig:
    max_failed_attempts: int = ...
    lockout_duration_minutes: int = ...
    session_expire_hours: int = ...
    max_concurrent_sessions: int = ...

@dataclass
class FlextAuthServiceDependencies:
    user_repository: UserRepository
    session_repository: SessionRepository
    password_service: PasswordService
    jwt_service: JWTService
    config: FlextAuthServiceConfig | None = ...
    auth_strategy: AuthenticationStrategy | None = ...
    token_strategy: TokenManagementStrategy | None = ...
    session_strategy: SessionManagementStrategy | None = ...
    user_strategy: UserManagementStrategy | None = ...

@dataclass
class FlextUserRegistrationData:
    username: str
    email: str
    password: str
    role: UserRole = ...
    ip_address: str | None = ...
    user_agent: str | None = ...

class AuthenticationStrategy(ABC):
    @abstractmethod
    async def authenticate(
        self, username: str, password: str, ip_address: str, user_agent: str | None
    ) -> FlextResult[dict[str, object]]: ...

class TokenManagementStrategy(ABC):
    @abstractmethod
    async def validate_token(self, token: str) -> FlextResult[SecurityContext]: ...
    @abstractmethod
    async def refresh_token(
        self, refresh_token: str
    ) -> FlextResult[dict[str, str]]: ...

class SessionManagementStrategy(ABC):
    @abstractmethod
    async def create_session(
        self, user: User, ip_address: str, user_agent: str | None
    ) -> FlextResult[Session]: ...

class UserManagementStrategy(ABC):
    @abstractmethod
    async def register_user(
        self, registration_data: FlextUserRegistrationData
    ) -> FlextResult[User]: ...

class ResultValidator:
    @staticmethod
    async def chain_async_results(*operations: object) -> FlextResult[bool]: ...
    @staticmethod
    def chain_sync_results(*operations: object) -> FlextResult[bool]: ...
    @staticmethod
    def validate_or_fail(
        *, condition: bool, error_message: str
    ) -> FlextResult[None]: ...

class DefaultAuthenticationStrategy(AuthenticationStrategy):
    user_repo: Incomplete
    password_service: Incomplete
    jwt_service: Incomplete
    session_repo: Incomplete
    config: Incomplete
    def __init__(
        self,
        user_repo: UserRepository,
        password_service: PasswordService,
        jwt_service: JWTService,
        session_repo: SessionRepository,
        config: FlextAuthServiceConfig,
    ) -> None: ...
    async def authenticate(
        self, username: str, password: str, ip_address: str, user_agent: str | None
    ) -> FlextResult[dict[str, object]]: ...

class DefaultTokenManagementStrategy(TokenManagementStrategy):
    jwt_service: Incomplete
    user_repo: Incomplete
    session_repo: Incomplete
    def __init__(
        self,
        jwt_service: JWTService,
        user_repo: UserRepository,
        session_repo: SessionRepository,
    ) -> None: ...
    async def validate_token(self, token: str) -> FlextResult[SecurityContext]: ...
    async def refresh_token(
        self, _refresh_token: str
    ) -> FlextResult[dict[str, str]]: ...

class DefaultSessionManagementStrategy(SessionManagementStrategy):
    session_repo: Incomplete
    config: Incomplete
    def __init__(
        self, session_repo: SessionRepository, config: FlextAuthServiceConfig
    ) -> None: ...
    async def create_session(
        self, user: User, ip_address: str, user_agent: str | None
    ) -> FlextResult[Session]: ...

class DefaultUserManagementStrategy(UserManagementStrategy):
    user_repo: Incomplete
    password_service: Incomplete
    def __init__(
        self, user_repo: UserRepository, password_service: PasswordService
    ) -> None: ...
    async def register_user(
        self, registration_data: FlextUserRegistrationData
    ) -> FlextResult[User]: ...

@dataclass
class ValidationPipelineStrategies:
    token_validator: TokenValidator
    user_validator: UserValidator
    session_validator: SessionValidator
    result_creator: ResultCreator
    validation_context: str

@dataclass
class SecurityContextPipelineStrategies:
    token_validator: TokenValidator
    user_validator: UserValidator
    session_validator: SessionValidator
    result_creator: SecurityContextCreator
    validation_context: str

@dataclass
class TokenRefreshPipelineStrategies:
    token_validator: TokenValidator
    user_validator: UserValidator
    session_validator: SessionValidator
    result_creator: TokenCreator
    validation_context: str

class FlextAuthService:
    user_repo: Incomplete
    session_repo: Incomplete
    password_service: Incomplete
    jwt_service: Incomplete
    config: Incomplete
    max_failed_attempts: Incomplete
    lockout_duration_minutes: Incomplete
    session_expire_hours: Incomplete
    max_concurrent_sessions: Incomplete
    auth_strategy: Incomplete
    token_strategy: Incomplete
    session_strategy: Incomplete
    user_strategy: Incomplete
    def __init__(self, dependencies: FlextAuthServiceDependencies) -> None: ...
    @classmethod
    def create_default(
        cls,
        user_repository: UserRepository,
        session_repository: SessionRepository,
        password_service: PasswordService,
        jwt_service: JWTService,
        config: FlextAuthServiceConfig | None = None,
    ) -> FlextAuthService: ...
    async def register_user(
        self, registration_data: FlextUserRegistrationData
    ) -> FlextResult[User]: ...
    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str,
        user_agent: str | None = None,
    ) -> FlextResult[dict[str, object]]: ...
    async def validate_token(self, token: str) -> FlextResult[SecurityContext]: ...
    async def refresh_token(
        self, refresh_token: str
    ) -> FlextResult[dict[str, str]]: ...
    async def logout_user(self, token: str) -> FlextResult[bool]: ...
    async def logout_all_sessions(self, user_id: str) -> FlextResult[int]: ...
    async def change_password(
        self, user_id: str, current_password: str, new_password: str
    ) -> FlextResult[bool]: ...
    async def cleanup_expired_sessions(self) -> FlextResult[int]: ...
    async def get_user_sessions(
        self, user_id: str
    ) -> FlextResult[list[dict[str, object]]]: ...
