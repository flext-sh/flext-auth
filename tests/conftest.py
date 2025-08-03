"""FLEXT Auth Test Configuration - Comprehensive pytest setup and fixtures.

This module provides enterprise-grade test configuration for FLEXT Auth following
pytest best practices and flext-core testing patterns. It includes shared fixtures,
test markers, and configuration for consistent testing across all test categories.

Architecture:
    - Test Configuration: Centralized pytest setup and marker definitions
    - Fixture Pattern: Reusable test fixtures with proper scope management
    - Test Categorization: Comprehensive test markers for organized test execution
    - Clean Setup/Teardown: Proper resource management for test isolation

Test Markers:
    - unit: Fast, isolated unit tests for individual components
    - integration: Service interaction tests with external dependencies
    - auth: Authentication workflow and security tests
    - security: Security-focused tests for vulnerabilities and policies
    - token: JWT token generation, validation, and lifecycle tests
    - password: Password hashing, validation, and security tests
    - session: Session management and lifecycle tests

Current Status:
    ✅ Basic test configuration established with pytest markers
    🔄 Enhanced fixtures being added as test coverage is restored
    🔄 Integration with flext-core testing patterns in progress

Design Patterns:
    - Fixture Pattern: Shared test dependencies with proper scoping
    - Factory Pattern: Test data creation utilities
    - Builder Pattern: Complex test scenario construction
    - Template Method: Common test setup and teardown workflows

Example Usage:
    >>> pytest -m unit           # Run only unit tests
    >>> pytest -m "auth and not integration"  # Run auth unit tests only
    >>> pytest -m security      # Run security-focused tests

Configuration Features:
    - Test marker registration for organized test execution
    - Shared fixture definitions for common test dependencies
    - Test environment setup and teardown
    - Integration with coverage reporting and quality gates

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from uuid import uuid4

import pytest

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
