"""Simple pytest configuration for flext-auth basic functionality.

This configuration provides basic fixtures for testing the simple authentication
functions.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

# Import working components only

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
# Basic Test Fixtures
# ============================================================================


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
) -> dict[str, str | bool]:
    return {
        "user_id": sample_user_id,
        "username": sample_username,
        "email": sample_email,
        "active": True,
    }


# ============================================================================
# Simple Test Utilities
# ============================================================================


@pytest.fixture
def sample_users_dict(
    sample_user_data: dict[str, str | bool],
) -> dict[str, dict[str, str | bool]]:
    """Create a simple users dictionary for testing authentication."""
    from flext_auth.domain.value_objects import PlainPassword
    from flext_auth.services.password_service import PasswordService

    # Create user with hashed password using proper services
    password_service = PasswordService()
    hash_result = password_service.hash_password(
        PlainPassword(value="SecurePassword123!"),
    )

    if not hash_result.is_success:
        msg = f"Password hashing failed: {hash_result.error}"
        raise ValueError(msg)

    password_hash = hash_result.data.value if hash_result.data else ""

    # Create user dictionary manually
    user = {
        "user_id": "test-user-id",
        "username": sample_user_data["username"],
        "email": sample_user_data["email"],
        "password_hash": password_hash,
        "active": True,
    }

    return {user["username"]: user}
