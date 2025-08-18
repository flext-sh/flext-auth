from collections.abc import Callable
from typing import Protocol

from _typeshed import Incomplete
from flext_core import FlextResult

from flext_auth.auth_app import FlextAuthService
from flext_auth.auth_config import FlextAuthConfig

__all__ = [
    "FlextAuthDecoratorConfig",
    "FlextAuthMixin",
    "FlextAuthSessionMixin",
    "FlextAuthUserMixin",
    "flext_auth_permission_required",
    "flext_auth_required",
    "flext_auth_role_required",
]

DecoratorReturnType = object
type SimpleAuthFunction = Callable[[object], DecoratorReturnType]
type BinaryAuthFunction = Callable[[object, object], DecoratorReturnType]
type TernaryAuthFunction = Callable[[object, object, object], DecoratorReturnType]
type NullaryAuthFunction = Callable[[], DecoratorReturnType]
type AuthenticatedFunction = (
    SimpleAuthFunction | BinaryAuthFunction | TernaryAuthFunction | NullaryAuthFunction
)

class AuthDecoratorProtocol(Protocol):
    def __call__(self, *args: object, **kwargs: object) -> object: ...

type DecoratorCallable = Callable[[AuthDecoratorProtocol], AuthDecoratorProtocol]

class FlextAuthDecoratorConfig:
    auth_service: Incomplete
    secret: Incomplete
    get_user: Incomplete
    error_response: Incomplete
    def __init__(
        self,
        auth_service: FlextAuthService | None = None,
        secret: str | None = None,
        *,
        get_user: bool = True,
        error_response: object = None,
    ) -> None: ...

def flext_auth_required(
    auth_service: FlextAuthService | None = None,
    secret: str | None = None,
    secret_key: str | None = None,
    *,
    get_user: bool = True,
    error_response: object = None,
) -> DecoratorCallable: ...
def flext_auth_role_required(
    required_role: str,
    auth_service: FlextAuthService | None = None,
    secret: str | None = None,
    secret_key: str | None = None,
    error_response: object = None,
) -> DecoratorCallable: ...
def flext_auth_permission_required(
    required_permission: str,
    auth_service: FlextAuthService | None = None,
    secret: str | None = None,
    secret_key: str | None = None,
    error_response: object = None,
) -> DecoratorCallable: ...

class FlextAuthMixin:
    def __init__(self, *args: object, **kwargs: object) -> None: ...
    def init_auth(
        self,
        auth_service: FlextAuthService | None = None,
        auth_config: FlextAuthConfig | None = None,
    ) -> FlextResult[None]: ...
    def authenticate_user(
        self, username: str, password: str
    ) -> FlextResult[dict[str, object]]: ...
    def validate_token(self, token: str) -> FlextResult[dict[str, object]]: ...
    def get_current_user(self, token: str | None) -> dict[str, object] | None: ...
    def create_session(self, username: str, password: str) -> dict[str, object]: ...
    def generate_token(self, user_data: dict[str, object]) -> FlextResult[str]: ...
    def check_permission(
        self, token_or_user_data: str | dict[str, object], required_permission: str
    ) -> FlextResult[bool]: ...
    def check_role(
        self, user_data: dict[str, object], required_role: str
    ) -> FlextResult[bool]: ...
    @property
    def is_auth_initialized(self) -> bool: ...
    def flext_auth_add_validation(self, validator: Callable[[str], bool]) -> None: ...
    def flext_auth_validate_all(self, value: str) -> bool: ...
    def flext_auth_get_headers(self, token: str) -> dict[str, str]: ...

class _AuthCompat:
    secret_key: Incomplete
    def __init__(self) -> None: ...
    async def register(
        self, _username: str, _email: str, _password: str
    ) -> FlextResult[bool]: ...

class FlextAuthUserMixin:
    def __init__(self, *args: object, **kwargs: object) -> None: ...
    def set_current_user(self, user_data: dict[str, object]) -> FlextResult[None]: ...
    def get_current_user(self) -> FlextResult[dict[str, object]]: ...
    def clear_current_user(self) -> FlextResult[None]: ...
    def is_user_in_role(self, role: str) -> FlextResult[bool]: ...
    def is_user_has_permission(self, permission: str) -> FlextResult[bool]: ...
    @property
    def has_current_user(self) -> bool: ...
    @property
    def current_user_id(self) -> str | None: ...
    def flext_auth_get_user_context(self) -> dict[str, object]: ...
    def flext_auth_has_permission(self, permission: str) -> bool: ...
    def flext_auth_can_access(self, resource: str) -> bool: ...

class FlextAuthSessionMixin:
    def __init__(self, *args: object, **kwargs: object) -> None: ...
    def flext_auth_refresh_session(self) -> dict[str, object]: ...
    def flext_auth_get_session_data(self) -> dict[str, object] | None: ...
    def flext_auth_clear_session(self) -> None: ...
    def flext_auth_is_session_valid(self) -> bool: ...
