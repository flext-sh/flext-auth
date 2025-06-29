from __future__ import annotations

"""Authorization service with role-based access control using Python 3.13 patterns."""

import functools
from collections.abc import Callable
from enum import Enum

from flx_auth.interfaces import AuthorizationService, UserRepository
from flx_auth.models import Permission, Role, UserRoleEnum
from flx_auth.types import PermissionScope, UserID, UserPermissions

# Python 3.13 type alias for generic callables
type CallableT = Callable[..., object]


class PermissionCheckMode(Enum):
    """Permission check mode for multiple permission verification.

    Defines how multiple permissions should be evaluated when checking
    user authorization, replacing boolean require_all parameters with
    explicit modes for better type safety and code clarity.

    Attributes
    ----------
        REQUIRE_ALL: All permissions must be satisfied for authorization.
        REQUIRE_ANY: Any single permission satisfies authorization requirement.

    """

    REQUIRE_ALL = "require_all"
    REQUIRE_ANY = "require_any"


class RoleBasedAuthorizationService(AuthorizationService):
    """Role-based authorization service with permission inheritance."""

    def __init__(self, user_repository: UserRepository) -> None:
        """Initialize authorization service."""
        self.user_repository = user_repository
        self._permission_cache: dict[str, UserPermissions] = {}

    async def check_permission(
        self, user_id: UserID, permission: str, resource: str | None = None
    ) -> bool:
        """Check if user has specific permission."""
        user_permissions = await self.get_user_permissions(user_id)

        if resource:
            # Check for resource-specific permission
            permission_string = f"{permission}:{resource}"
            if permission_string in user_permissions:
                return True

            # Check for wildcard permissions
            wildcard_permission = f"{permission}:*"
            if wildcard_permission in user_permissions:
                return True

        # Check for general permission
        return permission in user_permissions

    async def check_role(self, user_id: UserID, role: str) -> bool:
        """Check if user has specific role."""
        user = await self.user_repository.get_user_by_id(user_id)
        if not user:
            return False

        return user.has_role(role)

    async def get_user_permissions(self, user_id: UserID) -> UserPermissions:
        """Get all permissions for a user."""
        # Check cache first
        if user_id in self._permission_cache:
            return self._permission_cache[user_id]

        user = await self.user_repository.get_user_by_id(user_id)
        if not user:
            return []

        # Get all permissions from active roles
        permissions: set[str] = set()
        for role in user.get_active_roles():
            permissions.update(role.permissions)

            # Permission hierarchy not needed for current requirements
            # Using flat permission structure for optimal performance

        user_permissions = list(permissions)

        # Cache permissions
        self._permission_cache[user_id] = user_permissions

        return user_permissions

    async def get_resource_permissions(
        self, user_id: UserID, resource: str
    ) -> UserPermissions:
        """Get permissions for a specific resource."""
        all_permissions = await self.get_user_permissions(user_id)

        # Filter permissions for the specific resource
        resource_permissions = []
        for permission in all_permissions:
            if ":" in permission:
                scope, perm_resource = permission.split(":", 1)
                if perm_resource in {resource, "*"}:
                    resource_permissions.append(scope)
            else:
                # Global permissions apply to all resources
                resource_permissions.append(permission)

        return resource_permissions

    def _get_derived_permissions(self, permission: Permission) -> set[str]:
        """Get derived permissions based on scope hierarchy."""
        derived = set()

        # Permission hierarchy: REDACTED_LDAP_BIND_PASSWORD > manage > write > read
        # execute is separate and doesn't inherit

        scope_hierarchy = {
            PermissionScope.ADMIN: [
                PermissionScope.MANAGE,
                PermissionScope.WRITE,
                PermissionScope.READ,
            ],
            PermissionScope.MANAGE: [
                PermissionScope.WRITE,
                PermissionScope.READ,
            ],
            PermissionScope.WRITE: [
                PermissionScope.READ,
            ],
        }

        if permission.scope in scope_hierarchy:
            for inherited_scope in scope_hierarchy[permission.scope]:
                inherited_permission = Permission(
                    id=f"derived_{permission.id}",
                    resource=permission.resource,
                    action=inherited_scope.value,
                    scope=inherited_scope,
                    description=f"Derived from {permission.scope.value}",
                )
                derived.add(str(inherited_permission))

        return derived

    def clear_permission_cache(self, user_id: UserID | None = None) -> None:
        """Clear permission cache for a user or all users."""
        if user_id:
            self._permission_cache.pop(user_id, None)
        else:
            self._permission_cache.clear()

    async def check_multiple_permissions(
        self,
        user_id: UserID,
        permissions: list[str],
        resource: str | None = None,
        check_mode: PermissionCheckMode = PermissionCheckMode.REQUIRE_ALL,
    ) -> bool:
        """Check multiple permissions at once."""
        results = []
        for permission in permissions:
            result = await self.check_permission(user_id, permission, resource)
            results.append(result)

        if check_mode == PermissionCheckMode.REQUIRE_ALL:
            return all(results)
        return any(results)


def require_permission(
    permission: str,
    resource: str | None = None,
    auth_service: AuthorizationService | None = None,
) -> Callable[[CallableT], CallableT]:
    """Require specific permission for a function."""

    def decorator(func: CallableT) -> CallableT:
        @functools.wraps(func)
        async def wrapper(*args: object, **kwargs: object) -> object:
            # Extract user_id from arguments or context using try/except
            user_id = kwargs.get("user_id")
            if not user_id and args:
                try:
                    user_id = args[0].user_id
                except (AttributeError, IndexError):
                    user_id = None

            if not user_id:
                msg = "User ID not found in function arguments"
                raise ValueError(msg)

            if not auth_service:
                msg = "Authorization service not provided"
                raise ValueError(msg)

            # Check permission - ensure user_id is str
            user_id_str = str(user_id) if user_id else ""
            has_permission = await auth_service.check_permission(
                user_id_str,
                permission,
                resource,
            )

            if not has_permission:
                msg = f"User {user_id} lacks permission {permission}"
                raise PermissionError(msg)

            # Call function and handle both sync and async using try/except
            result = func(*args, **kwargs)
            try:
                # Try to await the result if it's awaitable
                return await result
            except AttributeError:
                # Not awaitable, return synchronously
                return result

        return wrapper

    return decorator


def require_role(
    role: str, auth_service: AuthorizationService | None = None
) -> Callable[[CallableT], CallableT]:
    """Require specific role for a function."""

    def decorator(func: CallableT) -> CallableT:
        @functools.wraps(func)
        async def wrapper(*args: object, **kwargs: object) -> object:
            # Extract user_id from arguments or context using try/except
            user_id = kwargs.get("user_id")
            if not user_id and args:
                try:
                    user_id = args[0].user_id
                except (AttributeError, IndexError):
                    user_id = None

            if not user_id:
                msg = "User ID not found in function arguments"
                raise ValueError(msg)

            if not auth_service:
                msg = "Authorization service not provided"
                raise ValueError(msg)

            # Check role - ensure user_id is str
            user_id_str = str(user_id) if user_id else ""
            has_role = await auth_service.check_role(user_id_str, role)

            if not has_role:
                msg = f"User {user_id} lacks role {role}"
                raise PermissionError(msg)

            # Call function and handle both sync and async using try/except
            result = func(*args, **kwargs)
            try:
                # Try to await the result if it's awaitable
                return await result
            except AttributeError:
                # Not awaitable, return synchronously
                return result

        return wrapper

    return decorator


class DefaultRoleManager:
    """Default role manager with predefined enterprise roles."""

    @classmethod
    def create_REDACTED_LDAP_BIND_PASSWORD_role(cls) -> Role:
        """Create REDACTED_LDAP_BIND_PASSWORD role with full permissions."""
        permissions = [
            Permission.create("REDACTED_LDAP_BIND_PASSWORD_users", PermissionScope.ADMIN, "users"),
            Permission.create("REDACTED_LDAP_BIND_PASSWORD_pipelines", PermissionScope.ADMIN, "pipelines"),
            Permission.create("REDACTED_LDAP_BIND_PASSWORD_plugins", PermissionScope.ADMIN, "plugins"),
            Permission.create("REDACTED_LDAP_BIND_PASSWORD_system", PermissionScope.ADMIN, "system"),
            Permission.create("REDACTED_LDAP_BIND_PASSWORD_config", PermissionScope.ADMIN, "config"),
            Permission.create("execute_all", PermissionScope.EXECUTE, "*"),
        ]

        return UserRoleEnum.create(
            name="REDACTED_LDAP_BIND_PASSWORD",
            permissions=permissions,
            description="Full system REDACTED_LDAP_BIND_PASSWORDistrator access",
        )

    @classmethod
    def create_developer_role(cls) -> Role:
        """Create developer role with pipeline and plugin management."""
        permissions = [
            Permission.create("manage_pipelines", PermissionScope.MANAGE, "pipelines"),
            Permission.create("write_plugins", PermissionScope.WRITE, "plugins"),
            Permission.create("read_system", PermissionScope.READ, "system"),
            Permission.create(
                "execute_pipelines",
                PermissionScope.EXECUTE,
                "pipelines",
            ),
            Permission.create("read_logs", PermissionScope.READ, "logs"),
        ]

        return UserRoleEnum.create(
            name="developer",
            permissions=permissions,
            description="Pipeline and plugin development access",
        )

    @classmethod
    def create_user_role(cls) -> Role:
        """Create standard user role with basic access."""
        permissions = [
            Permission.create("read_pipelines", PermissionScope.READ, "pipelines"),
            Permission.create(
                "execute_own_pipelines",
                PermissionScope.EXECUTE,
                "own_pipelines",
            ),
            Permission.create("read_plugins", PermissionScope.READ, "plugins"),
            Permission.create(
                "read_basic_system",
                PermissionScope.READ,
                "basic_system",
            ),
        ]

        return UserRoleEnum.create(
            name="user",
            permissions=permissions,
            description="Standard user access",
        )

    @classmethod
    def create_readonly_role(cls) -> Role:
        """Create read-only role for auditors and monitoring."""
        permissions = [
            Permission.create("read_all_pipelines", PermissionScope.READ, "pipelines"),
            Permission.create("read_all_plugins", PermissionScope.READ, "plugins"),
            Permission.create("read_all_system", PermissionScope.READ, "system"),
            Permission.create("read_all_logs", PermissionScope.READ, "logs"),
            Permission.create("read_all_metrics", PermissionScope.READ, "metrics"),
        ]

        return UserRoleEnum.create(
            name="readonly",
            permissions=permissions,
            description="Read-only access for auditing and monitoring",
        )

    @classmethod
    def create_service_role(cls, service_name: str) -> Role:
        """Create service role for automated systems."""
        permissions = [
            Permission.create(
                f"execute_{service_name}",
                PermissionScope.EXECUTE,
                service_name,
            ),
            Permission.create(
                f"read_{service_name}_config",
                PermissionScope.READ,
                f"{service_name}_config",
            ),
            Permission.create(
                f"write_{service_name}_logs",
                PermissionScope.WRITE,
                f"{service_name}_logs",
            ),
        ]

        return UserRoleEnum.create(
            name=f"service_{service_name}",
            permissions=permissions,
            description=f"Service role for {service_name} automation",
        )

    @classmethod
    def get_all_default_roles(cls) -> list[Role]:
        """Get all default roles for enterprise setup."""
        return [
            cls.create_REDACTED_LDAP_BIND_PASSWORD_role(),
            cls.create_developer_role(),
            cls.create_user_role(),
            cls.create_readonly_role(),
        ]
