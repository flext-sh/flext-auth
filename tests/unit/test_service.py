"""Tests for service module."""

from __future__ import annotations

import pytest

from flext_auth.service import AuthService


class TestAuthService:
    """Test AuthService class."""

    def test_auth_service_creation(self) -> None:
        """Test AuthService can be created."""
        from unittest.mock import Mock

        from flext_auth.infrastructure.implementations.authentication_implementation import (
            EnterpriseAuthService,
        )

        mock_enterprise_service = Mock(spec=EnterpriseAuthService)
        service = AuthService(mock_enterprise_service)
        assert service is not None

    @pytest.mark.asyncio
    async def test_auth_service_authenticate_with_invalid_params(self) -> None:
        """Test AuthService authenticate returns None for invalid params."""
        from unittest.mock import AsyncMock, Mock

        from flext_auth.infrastructure.implementations.authentication_implementation import (
            EnterpriseAuthService,
        )

        mock_enterprise_service = Mock(spec=EnterpriseAuthService)
        mock_enterprise_service.authenticate_user = AsyncMock(return_value=None)
        service = AuthService(mock_enterprise_service)

        # Test with None parameters
        result = await service.authenticate(None, None)
        assert result is None

        # Test with empty parameters
        result = await service.authenticate("", "")
        assert result is None
