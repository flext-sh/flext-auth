from collections.abc import Mapping

from _typeshed import Incomplete
from flext_core import FlextResult

from flext_auth.auth import FlextAuthService
from flext_auth.mixins import FlextAuthSessionMixin as FlextAuthSessionMixin

__all__ = [
    "ADMIN_ROLE",
    "API_CONFIG",
    "FAST_CONFIG",
    "GUEST_ROLE",
    "HTTP_FORBIDDEN",
    "HTTP_UNAUTHORIZED",
    "MODERATOR_ROLE",
    "PRODUCTION_CONFIG",
    "USER_ROLE",
    "WEB_CONFIG",
    "AuthResult",
    "FlextAuthBatchOperations",
    "FlextAuthClaims",
    "FlextAuthHeaders",
    "FlextAuthPermissions",
    "FlextAuthRole",
    "FlextAuthSessionData",
    "FlextAuthSessionMixin",
    "FlextAuthTokenData",
    "FlextAuthUser",
    "FlextAuthUserData",
    "PermissionSet",
    "RoleHierarchy",
    "SessionData",
    "TokenData",
    "UserData",
    "flext_auth_api",
    "flext_auth_batch_operations",
    "flext_auth_build_response",
    "flext_auth_check_token",
    "flext_auth_complete_workflow",
    "flext_auth_create_api_key",
    "flext_auth_create_auth_context",
    "flext_auth_create_multi_factor_token",
    "flext_auth_create_role_hierarchy",
    "flext_auth_create_secure_session",
    "flext_auth_create_service_token",
    "flext_auth_create_user_payload",
    "flext_auth_decode_jwt",
    "flext_auth_dev",
    "flext_auth_extract_token_claims",
    "flext_auth_extract_user_context",
    "flext_auth_filter_user_data",
    "flext_auth_generate_jwt",
    "flext_auth_hash_password",
    "flext_auth_instant_api",
    "flext_auth_merge_configs",
    "flext_auth_middleware_factory",
    "flext_auth_one_liner",
    "flext_auth_prod",
    "flext_auth_quick_start",
    "flext_auth_rate_limit",
    "flext_auth_validate_api_key",
    "flext_auth_validate_email",
    "flext_auth_validate_jwt",
    "flext_auth_validate_password_strength",
    "flext_auth_validate_permissions",
    "flext_auth_validate_username",
    "flext_auth_verify_password",
    "flext_auth_web",
]

type AuthResult = dict[str, object]
type UserData = dict[str, object]
type TokenData = dict[str, object]
type SessionData = dict[str, object]
type PermissionSet = list[str]
type RoleHierarchy = dict[str, PermissionSet]
FAST_CONFIG: dict[str, object]
PRODUCTION_CONFIG: dict[str, object]
WEB_CONFIG: dict[str, object]
API_CONFIG: dict[str, object]
ADMIN_ROLE: str
MODERATOR_ROLE: str
USER_ROLE: str
GUEST_ROLE: str
FLEXT_AUTH_ADMIN = ADMIN_ROLE
FLEXT_AUTH_USER = USER_ROLE
FLEXT_AUTH_GUEST = GUEST_ROLE
HTTP_UNAUTHORIZED: int
HTTP_FORBIDDEN: int

def flext_auth_dev() -> FlextAuthService: ...
def flext_auth_prod() -> FlextAuthService: ...
def flext_auth_web() -> FlextAuthService: ...
def flext_auth_api() -> FlextAuthService: ...
def flext_auth_quick_start(
    *,
    create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
    REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",
    REDACTED_LDAP_BIND_PASSWORD_password: str | None = None,
    **config_overrides: object,
) -> FlextResult[FlextAuthService]: ...
def flext_auth_hash_password(password: str, rounds: int = 12) -> str: ...
def flext_auth_verify_password(password: str, hashed: str) -> bool: ...
def flext_auth_generate_jwt(
    payload: Mapping[str, object], secret: str | None = None, expires_minutes: int = 30
) -> FlextResult[str]: ...
def flext_auth_validate_jwt(
    token: str, secret: str | None = None
) -> FlextResult[dict[str, object]]: ...
def flext_auth_validate_email(email: str) -> bool: ...
def flext_auth_validate_username(username: str) -> bool: ...
def flext_auth_validate_password_strength(password: str) -> dict[str, object]: ...
def flext_auth_decode_jwt(
    token: str, secret: str | None = None
) -> dict[str, object] | None: ...
def flext_auth_check_token(
    token: str, secret: str | None = None
) -> FlextResult[dict[str, object]]: ...
def flext_auth_create_secure_session(
    user_id: str,
    username: str,
    role: str,
    expires_hours: int = 12,
    *,
    include_permissions: bool = False,
    **additional_data: object,
) -> dict[str, object]: ...
def flext_auth_create_api_key(
    user_id: str, scope: str = "api", expires_days: int = 90, secret: str | None = None
) -> str: ...
def flext_auth_validate_api_key(
    api_key: str, secret: str | None = None
) -> dict[str, object] | None: ...
def flext_auth_complete_workflow(
    username: str, email: str, password: str, **config_overrides: object
) -> FlextResult[dict[str, object]]: ...

class FlextAuthClaims:
    user_id: Incomplete
    username: Incomplete
    role: Incomplete
    permissions: Incomplete
    claims: Incomplete
    def __init__(
        self,
        user_id: str,
        username: str,
        role: str = "USER",
        permissions: list[str] | None = None,
        **claims: object,
    ) -> None: ...
    def to_dict(self) -> dict[str, object]: ...

class FlextAuthBatchOperations:
    def __init__(self, auth_service: FlextAuthService) -> None: ...
    async def register_multiple(
        self, users_data: list[dict[str, object]], *, validate_all: bool = True
    ) -> FlextResult[list[dict[str, object]]]: ...
    async def validate_multiple_tokens(
        self, tokens: list[str]
    ) -> FlextResult[dict[str, object]]: ...
    async def create_multiple_sessions(
        self,
        users: list[tuple[str, str]] | list[dict[str, str]],
        *,
        session_hours: int = 24,
    ) -> FlextResult[dict[str, object]]: ...

class FlextAuthUser:
    id: Incomplete
    username: Incomplete
    email: Incomplete
    role: Incomplete
    status: Incomplete
    def __init__(self, **kwargs: object) -> None: ...
    def to_dict(self) -> dict[str, str]: ...

def flext_auth_instant_api(
    service_name: str, scope: str, expires_days: int = 7, **_config_overrides: object
) -> FlextResult[dict[str, object]]: ...
def flext_auth_middleware_factory(
    auth_service: FlextAuthService | None = None, **config: object
) -> object: ...
def flext_auth_batch_operations(
    auth_service: FlextAuthService | None = None,
) -> FlextAuthBatchOperations: ...
def flext_auth_one_liner(
    username: str, email: str, password: str, **_config: object
) -> FlextResult[dict[str, object]]: ...
def flext_auth_create_auth_context(
    token: str, secret: str, *, include_permissions: bool = True, **context_data: object
) -> dict[str, object] | None: ...
def flext_auth_create_multi_factor_token(
    user_id: str,
    method: str = "email",
    factor_type: str | None = None,
    expires_minutes: int = 15,
    **_token_data: object,
) -> str: ...
def flext_auth_build_response(
    *,
    success: bool,
    data: object = None,
    error: str | None = None,
    status: int | None = None,
    headers: dict[str, str] | None = None,
    **response_data: object,
) -> dict[str, object]: ...
def flext_auth_create_role_hierarchy(
    roles: dict[str, list[str]] | None = None,
) -> dict[str, list[str]]: ...
def flext_auth_create_user_payload(
    first_arg: str,
    second_arg: str,
    *,
    role: str = "user",
    user_id: str | None = None,
    email: str | None = None,
    **user_data: object,
) -> dict[str, object]: ...
def flext_auth_create_service_token(
    service_name: str,
    permissions: list[str] | None = None,
    expires_hours: int = 30,
    **_token_data: object,
) -> str: ...
def flext_auth_extract_token_claims(
    token: str, secret: str | None = None
) -> dict[str, object]: ...
def flext_auth_extract_user_context(
    token: str, secret: str | None = None, **context_data: object
) -> dict[str, object] | None: ...
def flext_auth_filter_user_data(
    user_data: dict[str, object],
    fields: list[str] | None = None,
    exclude_fields: list[str] | None = None,
    *,
    exclude_sensitive: bool = False,
) -> dict[str, object]: ...
def flext_auth_validate_permissions(
    role_or_permissions: str | list[str],
    required_or_permission: str | list[str],
    hierarchy: dict[str, list[str]] | None = None,
    *,
    require_all: bool = True,
) -> bool: ...
def flext_auth_merge_configs(
    base_config: dict[str, object],
    override_config: dict[str, object],
    *,
    deep_merge: bool = True,
) -> dict[str, object]: ...
def flext_auth_rate_limit(
    max_requests: int = 60,
    window_seconds: int = 60,
    *,
    _key_func: object = None,
    error_message: str = "Rate limit exceeded",
    _max_requests: int | None = None,
    _window_seconds: int | None = None,
) -> object: ...

type FlextAuthHeaders = dict[str, str]
type FlextAuthPermissions = list[str]
FlextAuthRole = str
type FlextAuthSessionData = dict[str, object]
type FlextAuthTokenData = dict[str, object]
type FlextAuthUserData = dict[str, object]
