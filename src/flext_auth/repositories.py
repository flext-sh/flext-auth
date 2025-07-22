"""In-memory repositories for authentication and authorization."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_auth.models import ADMIN_ROLE, OPERATOR_ROLE, VIEWER_ROLE

if TYPE_CHECKING:
    from flext_core.domain.shared_types import EntityId

    from flext_auth.models import Role


@runtime_checkable
class AuthRoleRepositoryInterface(Protocol):
    """Interface for a repository that manages Role entities."""

    async def find_by_names(self, role_names: frozenset[str]) -> list[Role]:
        """Find roles by their names.

        Args:
            role_names: Set of role names to find.

        Returns:
            List of Role objects matching the given names.

        """
        ...

    async def find_by_id(self, entity_id: EntityId) -> Role | None:
        """Find a role by its entity ID.

        Args:
            entity_id: Unique identifier for the role.

        Returns:
            Role object if found, None otherwise.

        """
        ...


class AuthInMemoryRoleRepository(AuthRoleRepositoryInterface):
    """In-memory repository for roles."""

    def __init__(self) -> None:
        self._roles = {
            "REDACTED_LDAP_BIND_PASSWORD": ADMIN_ROLE,
            "operator": OPERATOR_ROLE,
            "viewer": VIEWER_ROLE,
        }

    async def find_by_names(self, role_names: frozenset[str]) -> list[Role]:
        """Find roles by their names from in-memory storage.

        Args:
            role_names: Set of role names to find.

        Returns:
            List of Role objects matching the given names.

        """
        return [self._roles[name] for name in role_names if name in self._roles]

    async def find_by_id(self, entity_id: EntityId) -> Role | None:
        """Find a role by its entity ID from in-memory storage.

        Args:
            entity_id: Unique identifier for the role.

        Returns:
            Role object if found, None otherwise.

        """
        return self._roles.get(str(entity_id))

    async def save(self, entity: Role) -> None:
        """Save a role entity (no-op for predefined roles).

        Args:
            entity: Role entity to save.

        Note:
            In-memory roles are predefined and not mutable.

        """
        # In-memory roles are not mutable

    async def delete(self, entity_id: EntityId) -> None:
        """Delete a role entity (no-op for predefined roles).

        Args:
            entity_id: Unique identifier for the role to delete.

        Note:
            In-memory roles are predefined and not mutable.

        """
        # In-memory roles are not mutable

    async def get_all(self) -> list[Role]:
        """Get all available roles.

        Returns:
            List of all Role objects in the repository.

        """
        return list(self._roles.values())
