"""Tests for services module."""

from __future__ import annotations

from flext_auth.services import UserService


class TestServicesUserService:
    """Test services UserService."""

    def test_user_service_import(self) -> None:
        """Test UserService can be imported."""
        assert UserService is not None

    def test_services_module_exports(self) -> None:
        """Test services module has expected exports."""
        from flext_auth import services

        # Test key services are available
        assert hasattr(services, "UserService")
        assert hasattr(services, "JWTService")
        assert hasattr(services, "TokenManager")
        assert hasattr(services, "RoleBasedAuthorizationService")
