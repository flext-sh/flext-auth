from flext_core import FlextDomainService, FlextResult

from flext_auth.domain_entities import (
    FlextPermission as FlextPermission,
    FlextRole as FlextRole,
    FlextSession as FlextSession,
    FlextSessionStatus as FlextSessionStatus,
    FlextUser as FlextUser,
    FlextUserRole as FlextUserRole,
    FlextUserStatus as FlextUserStatus,
)
from flext_auth.domain_value_objects import (
    FlextPlainPassword as FlextPlainPassword,
    FlextUserEmail as FlextUserEmail,
    FlextUsername as FlextUsername,
)
from flext_auth.services_password_service import (
    FlextPasswordService as FlextPasswordService,
)

class FlextAuthenticationService(FlextDomainService[str]):
    def execute(self) -> FlextResult[str]: ...
    def authenticate_user(
        self, username: str, password: str, users: dict[str, FlextUser]
    ) -> FlextResult[FlextUser]: ...
    def create_user(
        self, username: str, email: str, password: str
    ) -> FlextResult[FlextUser]: ...
    def change_password(
        self, user: FlextUser, old_password: str, new_password: str
    ) -> FlextResult[bool]: ...

class FlextSessionService(FlextDomainService[str]):
    def execute(self) -> FlextResult[str]: ...
    def create_session(
        self,
        user: FlextUser,
        expires_minutes: int = 60,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[FlextSession]: ...
    def validate_session(self, session: FlextSession) -> FlextResult[bool]: ...
    def revoke_session(self, session: FlextSession) -> FlextResult[bool]: ...

class FlextAuthorizationService(FlextDomainService[str]):
    def execute(self) -> FlextResult[str]: ...
    def check_permission(
        self,
        user: FlextUser,
        resource: str,
        action: str,
        roles: dict[str, FlextRole] | None = None,
    ) -> FlextResult[bool]: ...
    def create_role(
        self,
        name: str,
        description: str,
        permissions: list[FlextPermission] | None = None,
    ) -> FlextResult[FlextRole]: ...

AuthenticationService = FlextAuthenticationService
SessionService = FlextSessionService
AuthorizationService = FlextAuthorizationService
