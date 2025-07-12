"""Tests for services module."""

from __future__ import annotations

import pytest

from flext_auth.services import AuthService as ServicesAuthService


class TestServicesAuthService:
    """Test services AuthService."""

    def test_auth_service_creation(self) -> None:
        """Test AuthService can be created."""
        service = ServicesAuthService()
        assert service is not None

    @pytest.mark.asyncio
    async def test_auth_service_methods_not_implemented(self) -> None:
        """Test AuthService methods raise NotImplementedError."""
        service = ServicesAuthService()

        with pytest.raises(NotImplementedError):
            await service.authenticate(None, None)

        with pytest.raises(NotImplementedError):
            await service.create_user(None, None, None)

        with pytest.raises(NotImplementedError):
            await service.get_user(None)

        with pytest.raises(NotImplementedError):
            await service.update_user(None)