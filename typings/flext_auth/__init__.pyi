from typing import ClassVar as ClassVar

from _typeshed import Incomplete
from flext_core import FlextResult as FlextResult
from flext_core.loggings import FlextLoggerFactory as FlextLoggerFactory

from flext_auth.auth import (
    FlextAuthService as FlextAuthService,
    FlextAuthService as _CoreAuthService,
    FlextAuthServiceConfig as FlextAuthServiceConfig,
    FlextAuthServiceDependencies as FlextAuthServiceDependencies,
)
from flext_auth.auth_app import create_auth_service as create_auth_service
from flext_auth.auth_config import (
    FlextAuthApplicationConfig as FlextAuthApplicationConfig,
    FlextAuthConfig as FlextAuthConfig,
    create_auth_config as create_auth_config,
    create_development_config as create_development_config,
    create_production_config as create_production_config,
)
from flext_auth.auth_decorators import (
    FlextAuthMixin as FlextAuthMixin,
    FlextAuthSessionMixin as FlextAuthSessionMixin,
    FlextAuthUserMixin as FlextAuthUserMixin,
    flext_auth_permission_required as flext_auth_permission_required,
    flext_auth_required as flext_auth_required,
    flext_auth_role_required as flext_auth_role_required,
)
from flext_auth.auth_exceptions import (
    FlextAccountInactiveError as FlextAccountInactiveError,
    FlextAccountLockedError as FlextAccountLockedError,
    FlextAuthenticationError as FlextAuthenticationError,
    FlextAuthError as FlextAuthError,
    FlextAuthorizationError as FlextAuthorizationError,
    FlextExpiredSessionError as FlextExpiredSessionError,
    FlextExpiredTokenError as FlextExpiredTokenError,
    FlextInsufficientPermissionError as FlextInsufficientPermissionError,
    FlextInvalidCredentialsError as FlextInvalidCredentialsError,
    FlextInvalidSessionError as FlextInvalidSessionError,
    FlextInvalidTokenError as FlextInvalidTokenError,
    FlextPasswordValidationError as FlextPasswordValidationError,
    FlextPermissionError as FlextPermissionError,
    FlextRoleRequiredError as FlextRoleRequiredError,
    FlextSessionError as FlextSessionError,
    FlextTokenError as FlextTokenError,
    FlextValidationError as FlextValidationError,
)
from flext_auth.auth_models import (
    FlextHashedPassword as FlextHashedPassword,
    FlextJWTClaims as FlextJWTClaims,
    FlextLoginAttempt as FlextLoginAttempt,
    FlextPlainPassword as FlextPlainPassword,
    FlextSecurityContext as FlextSecurityContext,
    FlextSession as FlextSession,
    FlextSessionStatus as FlextSessionStatus,
    FlextUser as FlextUser,
    FlextUserEmail as FlextUserEmail,
    FlextUsername as FlextUsername,
    FlextUserStatus as FlextUserStatus,
)
from flext_auth.auth_services import (
    FlextAuthenticationService as FlextAuthenticationService,
    FlextAuthorizationService as FlextAuthorizationService,
    FlextSessionService as FlextSessionService,
)
from flext_auth.auth_utilities import (
    generate_secure_password as generate_secure_password,
    generate_secure_token as generate_secure_token,
    get_utc_now as get_utc_now,
    is_strong_password as is_strong_password,
    mask_sensitive_data as mask_sensitive_data,
)
from flext_auth.auth_validation import (
    FlextAuthFieldSchema as FlextAuthFieldSchema,
    FlextAuthValidators as FlextAuthValidators,
    validate_complete_user_registration as validate_complete_user_registration,
    validate_email as validate_email,
    validate_password as validate_password,
    validate_password_strength as validate_password_strength,
    validate_username as validate_username,
)
from flext_auth.constants import (
    DEFAULT_DEV_SECRET as DEFAULT_DEV_SECRET,
    DEFAULT_JWT_SECRET as DEFAULT_JWT_SECRET,
)
from flext_auth.domain_entities import (
    FlextPermission as FlextPermission,
    FlextRole as FlextRole,
    FlextUserRole as FlextUserRole,
)
from flext_auth.helpers import (
    FlextAuthBatchOperations as FlextAuthBatchOperations,
    FlextAuthUser as FlextAuthUser,
    flext_auth_batch_operations as flext_auth_batch_operations,
    flext_auth_build_response as flext_auth_build_response,
    flext_auth_check_token as flext_auth_check_token,
    flext_auth_complete_workflow as flext_auth_complete_workflow,
    flext_auth_create_api_key as flext_auth_create_api_key,
    flext_auth_create_auth_context as flext_auth_create_auth_context,
    flext_auth_create_multi_factor_token as flext_auth_create_multi_factor_token,
    flext_auth_create_role_hierarchy as flext_auth_create_role_hierarchy,
    flext_auth_create_secure_session as flext_auth_create_secure_session,
    flext_auth_create_service_token as flext_auth_create_service_token,
    flext_auth_create_user_payload as flext_auth_create_user_payload,
    flext_auth_decode_jwt as flext_auth_decode_jwt,
    flext_auth_extract_token_claims as flext_auth_extract_token_claims,
    flext_auth_extract_user_context as flext_auth_extract_user_context,
    flext_auth_filter_user_data as flext_auth_filter_user_data,
    flext_auth_generate_jwt as flext_auth_generate_jwt,
    flext_auth_hash_password as flext_auth_hash_password,
    flext_auth_instant_api as flext_auth_instant_api,
    flext_auth_merge_configs as flext_auth_merge_configs,
    flext_auth_middleware_factory as flext_auth_middleware_factory,
    flext_auth_one_liner as flext_auth_one_liner,
    flext_auth_rate_limit as flext_auth_rate_limit,
    flext_auth_validate_api_key as flext_auth_validate_api_key,
    flext_auth_validate_email as flext_auth_validate_email,
    flext_auth_validate_jwt as flext_auth_validate_jwt,
    flext_auth_validate_password_strength as flext_auth_validate_password_strength,
    flext_auth_validate_permissions as flext_auth_validate_permissions,
    flext_auth_verify_password as flext_auth_verify_password,
)
from flext_auth.jwt import FlextJWTService as FlextJWTService
from flext_auth.services_password_service import (
    FlextPasswordService as FlextPasswordService,
)
from flext_auth.session import (
    InMemorySessionRepository as InMemorySessionRepository,
    SessionRepository as SessionRepository,
)
from flext_auth.user import (
    InMemoryUserRepository as InMemoryUserRepository,
    UserRepository as UserRepository,
)

__all__ = [
    "ADMIN_ROLE",
    "DEFAULT_DEV_SECRET",
    "DEFAULT_JWT_SECRET",
    "FLEXT_AUTH_ADMIN",
    "FLEXT_AUTH_GUEST",
    "FLEXT_AUTH_USER",
    "USER_ROLE",
    "ClassVar",
    "FlextAccountInactiveError",
    "FlextAccountLockedError",
    "FlextAuth",
    "FlextAuthApplicationConfig",
    "FlextAuthBatchOperations",
    "FlextAuthClaims",
    "FlextAuthConfig",
    "FlextAuthConfig",
    "FlextAuthError",
    "FlextAuthFieldSchema",
    "FlextAuthGlobalConfig",
    "FlextAuthHeaders",
    "FlextAuthMixin",
    "FlextAuthPermissions",
    "FlextAuthRole",
    "FlextAuthService",
    "FlextAuthServiceConfig",
    "FlextAuthServiceDependencies",
    "FlextAuthSessionData",
    "FlextAuthSessionMixin",
    "FlextAuthTokenData",
    "FlextAuthUser",
    "FlextAuthUserData",
    "FlextAuthUserMixin",
    "FlextAuthValidators",
    "FlextAuthenticationError",
    "FlextAuthenticationService",
    "FlextAuthorizationError",
    "FlextAuthorizationService",
    "FlextExpiredSessionError",
    "FlextExpiredTokenError",
    "FlextHashedPassword",
    "FlextInsufficientPermissionError",
    "FlextInvalidCredentialsError",
    "FlextInvalidSessionError",
    "FlextInvalidTokenError",
    "FlextJWTClaims",
    "FlextJWTService",
    "FlextLoggerFactory",
    "FlextLoginAttempt",
    "FlextPasswordService",
    "FlextPasswordValidationError",
    "FlextPermission",
    "FlextPermissionError",
    "FlextPlainPassword",
    "FlextResult",
    "FlextRole",
    "FlextRoleRequiredError",
    "FlextSecurityContext",
    "FlextSession",
    "FlextSessionError",
    "FlextSessionService",
    "FlextSessionStatus",
    "FlextTokenError",
    "FlextUser",
    "FlextUserEmail",
    "FlextUserRole",
    "FlextUserStatus",
    "FlextUsername",
    "FlextValidationError",
    "InMemorySessionRepository",
    "InMemoryUserRepository",
    "SessionRepository",
    "UserRepository",
    "__version__",
    "__version_info__",
    "create_auth_config",
    "create_auth_service",
    "create_development_config",
    "create_production_config",
    "flext_auth_batch_operations",
    "flext_auth_build_response",
    "flext_auth_check_token",
    "flext_auth_complete_workflow",
    "flext_auth_create_api_key",
    "flext_auth_create_auth_context",
    "flext_auth_create_development_service",
    "flext_auth_create_multi_factor_token",
    "flext_auth_create_role_hierarchy",
    "flext_auth_create_secure_session",
    "flext_auth_create_service_token",
    "flext_auth_create_user_payload",
    "flext_auth_decode_jwt",
    "flext_auth_extract_token_claims",
    "flext_auth_extract_user_context",
    "flext_auth_filter_user_data",
    "flext_auth_generate_jwt",
    "flext_auth_hash_password",
    "flext_auth_instant_api",
    "flext_auth_merge_configs",
    "flext_auth_middleware_factory",
    "flext_auth_one_liner",
    "flext_auth_permission_required",
    "flext_auth_quick_start",
    "flext_auth_quick_start",
    "flext_auth_rate_limit",
    "flext_auth_required",
    "flext_auth_role_required",
    "flext_auth_validate_api_key",
    "flext_auth_validate_email",
    "flext_auth_validate_jwt",
    "flext_auth_validate_password_strength",
    "flext_auth_validate_permissions",
    "flext_auth_verify_password",
    "generate_secure_password",
    "generate_secure_token",
    "get_utc_now",
    "is_strong_password",
    "mask_sensitive_data",
    "validate_complete_user_registration",
    "validate_email",
    "validate_password",
    "validate_password_strength",
    "validate_username",
]

ADMIN_ROLE: Incomplete
USER_ROLE: Incomplete
FLEXT_AUTH_ADMIN: Incomplete
FLEXT_AUTH_USER: Incomplete
FLEXT_AUTH_GUEST: Incomplete
type FlextAuthRole = str
type FlextAuthPermissions = list[str]
type FlextAuthUserData = dict[str, object]
type FlextAuthSessionData = dict[str, object]
type FlextAuthTokenData = dict[str, object]
type FlextAuthHeaders = dict[str, str]
type FlextAuthClaims = dict[str, object]

class FlextAuth:
    def __init__(
        self,
        config: dict[str, object] | None = None,
        *,
        _service: _CoreAuthService | None = None,
    ) -> None: ...
    async def register(
        self, username: str, email: str, password: str, *, role: FlextUserRole = ...
    ) -> FlextResult[object]: ...
    async def login(
        self, username: str, password: str
    ) -> FlextResult[dict[str, object]]: ...
    async def validate(self, token: str) -> FlextResult[dict[str, object]]: ...
    async def refresh(self, refresh_token: str) -> FlextResult[dict[str, str]]: ...
    async def logout(self, token: str) -> FlextResult[bool]: ...
    async def register_user_async(
        self,
        data_or_username: object,
        email: str | None = None,
        password: str | None = None,
        *,
        role: str | None = None,
    ) -> FlextResult[object]: ...
    def register_user(
        self, username: str, email: str, password: str
    ) -> dict[str, object]: ...
    def authenticate_user(
        self, username: str, password: str, ip_address: str = "127.0.0.1"
    ) -> dict[str, object]: ...
    async def validate_token(self, token: str) -> FlextResult[object]: ...
    async def login_and_validate(
        self, username: str, password: str
    ) -> FlextResult[dict[str, object]]: ...
    async def change_password(
        self, user_id: str, current_password: str, new_password: str
    ) -> FlextResult[bool]: ...
    async def get_user_sessions(
        self, user_id: str
    ) -> FlextResult[list[dict[str, object]]]: ...
    async def cleanup_sessions(self) -> FlextResult[int]: ...
    @property
    def auth_service(self) -> _CoreAuthService: ...
    @property
    def jwt_service(self) -> object: ...
    @property
    def password_service(self) -> object: ...
    @property
    def user_repository(self) -> object: ...
    @property
    def session_repository(self) -> object: ...
    def register_user_sync(
        self, username: str, email: str, password: str
    ) -> FlextResult[object]: ...
    def authenticate_user_sync(
        self, username: str, password: str
    ) -> FlextResult[dict[str, object]]: ...
    async def register_validated(
        self,
        username: str,
        email: str,
        password: str,
        *,
        role: FlextUserRole | None = None,
        require_strong_password: bool = False,
    ) -> FlextResult[dict[str, object]]: ...
    async def create_user_session(
        self, username: str, password: str, *, include_user_data: bool = True
    ) -> FlextResult[dict[str, object]]: ...

def flext_auth_quick_start(
    *,
    create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
    REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",
    REDACTED_LDAP_BIND_PASSWORD_password: str | None = None,
    config: dict[str, object] | None = None,
    **extra: object,
) -> FlextResult[FlextAuth]: ...

__version__: Incomplete
__version_info__: Incomplete

class FlextAuthGlobalConfig:
    DEFAULT_CONFIG: ClassVar[FlextAuthConfig]
    @classmethod
    def get_default_config(cls) -> FlextAuthConfig: ...
    @classmethod
    def set_default_config(cls, config: FlextAuthConfig) -> None: ...

def flext_auth_create_development_service() -> object: ...

# Names in __all__ with no definition:
#   annotations
