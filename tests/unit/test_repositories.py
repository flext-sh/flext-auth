"""Tests for repositories module."""

from __future__ import annotations

import pytest

from flext_auth.repositories import AuthInMemoryRoleRepository
from flext_auth.repositories import AuthRoleRepositoryInterface


class TestAuthRoleRepositoryInterface:
    """Test AuthRoleRepositoryInterface protocol."""

    def test_interface_exists(self) -> None:
        """Test that the interface protocol exists."""
        assert AuthRoleRepositoryInterface is not None

    def test_interface_is_runtime_checkable(self) -> None:
        """Test that the interface is runtime checkable."""
        repo = AuthInMemoryRoleRepository()
        assert isinstance(repo, AuthRoleRepositoryInterface)


class TestAuthInMemoryRoleRepository:
    """Test AuthInMemoryRoleRepository."""

    @pytest.fixture
    def repo(self) -> AuthInMemoryRoleRepository:
        """Create repository instance."""
        return AuthInMemoryRoleRepository()

    def test_repository_creation(self, repo: AuthInMemoryRoleRepository) -> None:
        """Test repository can be created."""
        assert repo is not None
        assert hasattr(repo, "_roles")
        assert len(repo._roles) == 3  # REDACTED_LDAP_BIND_PASSWORD, operator, viewer

    @pytest.mark.asyncio
    async def test_find_by_names_found(self, repo: AuthInMemoryRoleRepository) -> None:
        """Test finding existing roles by names."""
        role_names = frozenset(["REDACTED_LDAP_BIND_PASSWORD", "viewer"])
        roles = await repo.find_by_names(role_names)

        assert len(roles) == 2
        role_names_found = {role.name for role in roles}
        assert "REDACTED_LDAP_BIND_PASSWORD" in role_names_found
        assert "viewer" in role_names_found

    @pytest.mark.asyncio
    async def test_find_by_names_not_found(
        self, repo: AuthInMemoryRoleRepository,
    ) -> None:
        """Test finding non-existent roles by names."""
        role_names = frozenset(["nonexistent", "fake"])
        roles = await repo.find_by_names(role_names)

        assert len(roles) == 0

    @pytest.mark.asyncio
    async def test_find_by_names_partial(
        self, repo: AuthInMemoryRoleRepository,
    ) -> None:
        """Test finding mix of existing and non-existent roles."""
        role_names = frozenset(["REDACTED_LDAP_BIND_PASSWORD", "nonexistent", "operator"])
        roles = await repo.find_by_names(role_names)

        assert len(roles) == 2
        role_names_found = {role.name for role in roles}
        assert "REDACTED_LDAP_BIND_PASSWORD" in role_names_found
        assert "operator" in role_names_found
        assert "nonexistent" not in role_names_found

    @pytest.mark.asyncio
    async def test_find_by_id_found(self, repo: AuthInMemoryRoleRepository) -> None:
        """Test finding role by existing ID."""
        role = await repo.find_by_id("REDACTED_LDAP_BIND_PASSWORD")

        assert role is not None
        assert role.name == "REDACTED_LDAP_BIND_PASSWORD"

    @pytest.mark.asyncio
    async def test_find_by_id_not_found(self, repo: AuthInMemoryRoleRepository) -> None:
        """Test finding role by non-existent ID."""
        role = await repo.find_by_id("nonexistent")

        assert role is None

    @pytest.mark.asyncio
    async def test_save_role(self, repo: AuthInMemoryRoleRepository) -> None:
        """Test saving role (should be no-op)."""
        # Should not raise exception
        await repo.save(None)

    @pytest.mark.asyncio
    async def test_delete_role(self, repo: AuthInMemoryRoleRepository) -> None:
        """Test deleting role (should be no-op)."""
        # Should not raise exception
        await repo.delete("REDACTED_LDAP_BIND_PASSWORD")

    @pytest.mark.asyncio
    async def test_get_all_roles(self, repo: AuthInMemoryRoleRepository) -> None:
        """Test getting all roles."""
        roles = await repo.get_all()

        assert len(roles) == 3
        role_names = {role.name for role in roles}
        assert "REDACTED_LDAP_BIND_PASSWORD" in role_names
        assert "operator" in role_names
        assert "viewer" in role_names
