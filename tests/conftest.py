"""Modern pytest configuration for flext-auth using flext-core patterns.

This configuration provides standardized fixtures and test setup for authentication
testing using ServiceResult patterns and modern async testing approaches.
"""

from __future__ import annotations

import asyncio
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio

from flext_auth.models import AuthStatus
from flext_auth.models import UserRoleEnum
from flext_auth.tokens import TokenInclusionMode
from flext_core.domain.types import ServiceResult

# ============================================================================
# Pytest Configuration
# ============================================================================


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "unit: Unit tests for authentication components",
    )
    config.addinivalue_line(
        "markers",
        "integration: Integration tests requiring external services",
    )
    config.addinivalue_line(
        "markers",
        "auth: Authentication-specific tests",
    )
    config.addinivalue_line(
        "markers",
        "security: Security-focused tests",
    )
    config.addinivalue_line(
        "markers",
        "token: JWT token-related tests",
    )
    config.addinivalue_line(
        "markers",
        "password: Password-related tests",
    )
    config.addinivalue_line(
        "markers",
        "session: Session management tests",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    for item in items:
        # Auto-mark based on test location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Auto-mark based on test name patterns
        if "auth" in item.name.lower():
            item.add_marker(pytest.mark.auth)
        if "token" in item.name.lower():
            item.add_marker(pytest.mark.token)
        if "password" in item.name.lower():
            item.add_marker(pytest.mark.password)
        if "security" in item.name.lower():
            item.add_marker(pytest.mark.security)
        if "session" in item.name.lower():
            item.add_marker(pytest.mark.session)


# ============================================================================
# Async Configuration
# ============================================================================


@pytest.fixture(scope="session")
def event_loop_policy() -> asyncio.AbstractEventLoopPolicy:
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# ============================================================================
# Core Authentication Fixtures
# ============================================================================


@pytest.fixture
def sample_user_id() -> str:
    return str(uuid4())


@pytest.fixture
def sample_username() -> str:
    return "test_user"


@pytest.fixture
def sample_email() -> str:
    return "test.user@example.com"


@pytest.fixture
def sample_password() -> str:
    return "SecurePassword123!"


@pytest.fixture
def sample_user_data(
    sample_user_id: str,
    sample_username: str,
    sample_email: str,
) -> dict[str, str | datetime | UserRoleEnum | AuthStatus]:
    return {
        "id": sample_user_id,
        "username": sample_username,
        "email": sample_email,
        "role": UserRoleEnum.USER,
        "status": AuthStatus.ACTIVE,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }


# ============================================================================
# Service Mocks
# ============================================================================


@pytest.fixture
def mock_user_service() -> AsyncMock:
    service = AsyncMock()
    service.authenticate.return_value = ServiceResult.success(True)
    service.create_user.return_value = ServiceResult.success({"id": str(uuid4())})
    service.get_user.return_value = ServiceResult.success({"id": str(uuid4())})
    return service


@pytest.fixture
def mock_jwt_service() -> AsyncMock:
    service = AsyncMock()
    service.generate_tokens.return_value = ServiceResult.success(
        {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
        },
    )
    service.verify_token.return_value = ServiceResult.success({"user_id": str(uuid4())})
    return service
