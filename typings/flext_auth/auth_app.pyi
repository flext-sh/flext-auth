from dataclasses import dataclass

from _typeshed import Incomplete
from flext_core import FlextResult

from flext_auth.auth_models import FlextSecurityContext, FlextUser
from flext_auth.auth_services import FlextJWTService, FlextPasswordService

__all__ = [
    "FlextAuthService",
    "FlextAuthServiceConfig",
    "FlextAuthServiceDependencies",
    "create_auth_service",
    "create_auth_service_dependencies",
]

@dataclass
class FlextAuthServiceDependencies:
    user_repository: object
    session_repository: object
    password_service: FlextPasswordService
    jwt_service: FlextJWTService
    config: FlextAuthServiceConfig

@dataclass
class FlextAuthServiceConfig:
    max_login_attempts: int = ...
    lockout_duration_minutes: int = ...
    session_timeout_minutes: int = ...
    jwt_secret_key: str = ...

class FlextAuthService:
    deps: Incomplete
    def __init__(self, dependencies: FlextAuthServiceDependencies) -> None: ...
    async def authenticate_user(
        self, username: str, password: str, ip_address: str = "127.0.0.1"
    ) -> FlextResult[FlextUser]: ...
    async def validate_token(self, token: str) -> FlextResult[FlextSecurityContext]: ...
    async def logout_user(
        self, _user_id: str, _session_id: str
    ) -> FlextResult[bool]: ...

def create_auth_service_dependencies(
    jwt_secret: str | None = None,
) -> FlextAuthServiceDependencies: ...
def create_auth_service(jwt_secret: str | None = None) -> FlextAuthService: ...
