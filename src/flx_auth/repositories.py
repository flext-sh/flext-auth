"""In-memory repositories for authentication and authorization."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flx_auth.models import ADMIN_ROLE, OPERATOR_ROLE, VIEWER_ROLE, Role

if TYPE_CHECKING:
    from flx_core.contracts.repository_contracts import EntityId


@runtime_checkable
class AuthRoleRepositoryInterface(Protocol):
    """Interface for a repository that manages Role entities."""

    async def find_by_names(self, role_names: frozenset[str]) -> list[Role]:
        """Find roles by their names."""
        ...

    async def find_by_id(self, entity_id: EntityId) -> Role | None:
        """Find a role by its ID (name)."""
        ...


class AuthInMemoryRoleRepository(AuthRoleRepositoryInterface):
    """In-memory repository for roles."""

    def __init__(self) -> None:
        """Initialize in-memory role repository with default roles."""
        self._roles = {
            "REDACTED_LDAP_BIND_PASSWORD": ADMIN_ROLE,
            "operator": OPERATOR_ROLE,
            "viewer": VIEWER_ROLE,
        }

    async def find_by_names(self, role_names: frozenset[str]) -> list[Role]:
        """Find roles by their names."""
        return [self._roles[name] for name in role_names if name in self._roles]

    async def find_by_id(self, entity_id: EntityId) -> Role | None:
        """Find a role by its ID (name)."""
        return self._roles.get(str(entity_id))

    async def save(self, entity: Role) -> None:
        """Save a role (not supported for in-memory)."""
        # In-memory roles are not mutable

    async def delete(self, entity_id: EntityId) -> None:
        """Delete a role (not supported for in-memory)."""
        # In-memory roles are not mutable

    async def get_all(self) -> list[Role]:
        """Get all roles."""
        return list(self._roles.values())
