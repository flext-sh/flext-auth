"""Authorization service with role-based access control using Python 3.13 patterns."""

from __future__ import annotations

import functools
from collections.abc import Callable
from enum import Enum
from typing import TYPE_CHECKING

from flext_auth.interfaces import AuthorizationService
from flext_auth.models import Permission, UserRoleEnum
from flext_auth.types import PermissionScope

if TYPE_CHECKING:
    from flext_auth.interfaces import UserRepository
    from flext_auth.models import Role
    from flext_auth.types import UserID, UserPermissions

# Python 3.13 type alias for generic callables
CallableT = Callable[..., object]


class PermissionCheckMode(Enum):
    """Permission check mode for multiple permission verification.

    Defines how multiple permissions should be evaluated when checking
    user authorization, replacing boolean require_all parameters with
    explicit modes for better type safety and code clarity.

    Attributes
    ----------
        REQUIRE_ALL:
            All permissions must be satisfied for authorization.
        REQUIRE_ANY: Any single permission satisfies authorization requirement.

    """

    REQUIRE_ALL = "require_all"
    REQUIRE_ANY = "require_any"


class RoleBasedAuthorizationService(AuthorizationService):
    """Role-based authorization service with permission inheritance."""

    def __init__(self, user_repository: UserRepository) -> None:
        self.user_repository = user_repository
        self._permission_cache: dict[str, UserPermissions] = {}

    async def check_permission(
        self,
        user_id: UserID,
        permission: str,
        resource: str | None = None,
    ) -> bool:
        """Check if user has permission for resource.

        Args:
            user_id: User identifier
            permission: Permission to check
            resource: Optional resource identifier

        Returns:
            True if user has permission

        """
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
        """Check if user has specific role.

        Args:
            user_id: User identifier to check.
            role: Role name to verify.

        Returns:
            True if user has the role, False otherwise.

        """
        user = await self.user_repository.get_user_by_id(user_id)
        if not user:
            return False

        return user.role == role

    async def get_user_permissions(self, user_id: UserID) -> UserPermissions:
        """Get all permissions for a user based on their roles.

        Args:
            user_id: User identifier to get permissions for.

        Returns:
            List of permission strings the user has through their roles.

        """
        # Check cache first
        user_id_str = str(user_id)
        if user_id_str in self._permission_cache:
            return self._permission_cache[user_id_str]

        user = await self.user_repository.get_user_by_id(user_id)
        if not user:
            return []

        # Get all permissions from user role
        permissions: set[str] = set()

        # Get permissions based on user's role
        role_permissions = self._get_permissions_for_role(user.role)
        permissions.update(role_permissions)

        user_permissions = list(permissions)

        # Cache permissions
        self._permission_cache[user_id_str] = user_permissions

        return user_permissions

    async def get_resource_permissions(
        self,
        user_id: UserID,
        resource: str,
    ) -> UserPermissions:
        """Get user permissions specific to a resource.

        Args:
            user_id: User identifier to get permissions for.
            resource: Resource name to filter permissions by.

        Returns:
            List of permission strings specific to the resource.

        """
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

        try:
            permission_scope = PermissionScope(permission.scope)
            if permission_scope in scope_hierarchy:
                for inherited_scope in scope_hierarchy[permission_scope]:
                    inherited_permission = Permission(
                        id=f"derived_{permission.id}",
                        resource=permission.resource,
                        action=inherited_scope.value,
                        scope=inherited_scope.value,
                        description=f"Derived from {permission_scope.value}",
                    )
                    derived.add(str(inherited_permission))
        except (ValueError, TypeError):
            # Invalid scope, skip hierarchy processing
            pass

        return derived

    def clear_permission_cache(self, user_id: UserID | None = None) -> None:
        """Clear permission cache for specific user or all users.

        Args:
            user_id: Optional user ID to clear cache for. If None, clears entire cache.

        """
        if user_id:
            self._permission_cache.pop(str(user_id), None)
        else:
            self._permission_cache.clear()

    async def check_multiple_permissions(
        self,
        user_id: UserID,
        permissions: list[str],
        resource: str | None = None,
        check_mode: PermissionCheckMode = PermissionCheckMode.REQUIRE_ALL,
    ) -> bool:
        """Check multiple permissions for a user with different modes.

        Args:
            user_id: User identifier to check permissions for.
            permissions: List of permission strings to check.
            resource: Optional resource context for permissions.
            check_mode: How to evaluate multiple permissions (ALL or ANY).

        Returns:
            True if permissions are satisfied according to check_mode.

        """
        results: list[bool] = []
        for permission in permissions:
            result = await self.check_permission(user_id, permission, resource)
            results.append(result)

        if check_mode == PermissionCheckMode.REQUIRE_ALL:
            return all(results)
        return any(results)

    def _get_permissions_for_role(self, role: str) -> list[str]:
        """Get permissions for a specific role.

        Args:
            role: Role name to get permissions for.

        Returns:
            List of permission strings for the role.

        """
        # Define role-permission mapping based on standard enterprise roles
        role_permissions = {
            "REDACTED_LDAP_BIND_PASSWORD": [
                "user:create",
                "user:read",
                "user:update",
                "user:delete",
                "pipeline:create",
                "pipeline:read",
                "pipeline:update",
                "pipeline:delete",
                "plugin:install",
                "plugin:remove",
                "plugin:configure",
                "system:REDACTED_LDAP_BIND_PASSWORD",
                "config:manage",
            ],
            "operator": [
                "pipeline:read",
                "pipeline:update",
                "pipeline:execute",
                "plugin:read",
                "plugin:configure",
                "execution:create",
                "execution:read",
                "execution:cancel",
            ],
            "user": [
                "pipeline:read",
                "execution:read",
            ],
            "service": [
                "pipeline:execute",
                "execution:create",
                "execution:read",
            ],
            "readonly": [
                "pipeline:read",
                "plugin:read",
                "execution:read",
            ],
            "developer": [
                "pipeline:create",
                "pipeline:read",
                "pipeline:update",
                "plugin:read",
                "plugin:configure",
                "execution:create",
                "execution:read",
            ],
            "auditor": [
                "pipeline:read",
                "plugin:read",
                "execution:read",
                "audit:read",
                "logs:read",
            ],
        }

        return role_permissions.get(role, [])


def require_permission(
    permission: str,
    resource: str | None = None,
    auth_service: AuthorizationService | None = None,
) -> Callable[[CallableT], CallableT]:
    """Decorator to require permission for function execution.

    Args:
        permission: Required permission
        resource: Optional resource identifier
        auth_service: Authorization service instance

    Returns:
        Decorator function

    """

    def decorator(func: CallableT) -> CallableT:
        @functools.wraps(func)
        async def wrapper(*args: object, **kwargs: object) -> object:
            from uuid import UUID

            # Extract user_id from arguments or context using try/except
            user_id = kwargs.get("user_id")
            if not user_id:
                try:
                    # Try to get user_id from first argument
                    first_arg = args[0]
                    if hasattr(first_arg, "user_id"):
                        user_id = first_arg.user_id
                except (AttributeError, IndexError):
                    user_id = None

            if not user_id:
                msg = "User ID not found in arguments or context"
                raise ValueError(msg)

            if not auth_service:
                msg = "Authorization service not configured"
                raise ValueError(msg)

            # Convert user_id to UUID if needed
            if isinstance(user_id, str):
                try:
                    user_id_uuid = UUID(user_id)
                except ValueError as err:
                    msg = f"Invalid user ID format: {user_id}"
                    raise ValueError(msg) from err
            elif isinstance(user_id, UUID):
                user_id_uuid = user_id
            else:
                msg = f"User ID must be string or UUID, got {type(user_id)}"
                raise TypeError(msg)

            has_permission = await auth_service.check_permission(
                user_id_uuid,
                permission,
                resource,
            )

            if not has_permission:
                msg = f"Permission denied: {permission}"
                raise PermissionError(msg)

            # Call function and handle both sync and async
            result = func(*args, **kwargs)
            if hasattr(result, "__await__"):
                # It's awaitable, so await it
                return await result
            # It's not awaitable, return directly
            return result

        return wrapper

    return decorator


def require_role(
    role: str,
    auth_service: AuthorizationService | None = None,
) -> Callable[[CallableT], CallableT]:
    """Decorator to require role for function execution.

    Args:
        role: Required role
        auth_service: Authorization service instance

    Returns:
        Decorator function

    """

    def decorator(func: CallableT) -> CallableT:
        @functools.wraps(func)
        async def wrapper(*args: object, **kwargs: object) -> object:
            from uuid import UUID

            # Extract user_id from arguments or context using try/except
            user_id = kwargs.get("user_id")
            if not user_id:
                try:
                    # Try to get user_id from first argument
                    first_arg = args[0]
                    if hasattr(first_arg, "user_id"):
                        user_id = first_arg.user_id
                except (AttributeError, IndexError):
                    user_id = None

            if not user_id:
                msg = "User ID not found in arguments or context"
                raise ValueError(msg)

            if not auth_service:
                msg = "Authorization service not configured"
                raise ValueError(msg)

            # Convert user_id to UUID if needed
            if isinstance(user_id, str):
                try:
                    user_id_uuid = UUID(user_id)
                except ValueError as err:
                    msg = f"Invalid user ID format: {user_id}"
                    raise ValueError(msg) from err
            elif isinstance(user_id, UUID):
                user_id_uuid = user_id
            else:
                msg = f"User ID must be string or UUID, got {type(user_id)}"
                raise TypeError(msg)

            has_role = await auth_service.check_role(user_id_uuid, role)

            if not has_role:
                msg = f"Role access denied: {role}"
                raise PermissionError(msg)

            # Call function and handle both sync and async
            result = func(*args, **kwargs)
            if hasattr(result, "__await__"):
                # It's awaitable, so await it
                return await result
            # It's not awaitable, return directly
            return result

        return wrapper

    return decorator


class DefaultRoleManager:
    """Default role manager with predefined enterprise roles."""

    @classmethod
    def create_REDACTED_LDAP_BIND_PASSWORD_role(cls) -> Role:
        """Create an REDACTED_LDAP_BIND_PASSWORD role with full system permissions.

        Returns:
            Role object configured with REDACTED_LDAP_BIND_PASSWORD permissions.

        """
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
        """Create a developer role with pipeline and plugin management permissions.

        Returns:
            Role object configured with developer permissions.

        """
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
        """Create a standard user role with basic permissions.

        Returns:
            Role object configured with user permissions.

        """
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
        """Create a read-only role with view-only permissions.

        Returns:
            Role object configured with read-only permissions.

        """
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
        """Create a service role for automated systems.

        Args:
            service_name: Name of the service for role identification.

        Returns:
            Role object configured with service permissions.

        """
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
        """Get all predefined default roles.

        Returns:
            List of all default role objects.

        """
        return [
            cls.create_REDACTED_LDAP_BIND_PASSWORD_role(),
            cls.create_developer_role(),
            cls.create_user_role(),
            cls.create_readonly_role(),
        ]
