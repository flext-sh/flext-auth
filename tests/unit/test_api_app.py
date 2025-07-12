"""Tests for FastAPI application."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from flext_auth.api.app import app
from flext_auth.api.dependencies import get_auth_service
from flext_core.domain.types import ServiceResult


class TestFastAPIApp:
    """Test FastAPI application endpoints."""

    @pytest.fixture
    def mock_auth_service(self) -> AsyncMock:
        """Create mock authentication service."""
        return AsyncMock()

    @pytest.fixture
    def client(self, mock_auth_service: AsyncMock) -> TestClient:
        """Create test client with mocked dependencies."""
        app.dependency_overrides[get_auth_service] = lambda: mock_auth_service
        client = TestClient(app)
        yield client
        app.dependency_overrides.clear()

    def test_health_endpoint(self, client: TestClient) -> None:
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy", "service": "flext-auth"}

    def test_register_user_success(
        self,
        client: TestClient,
        mock_auth_service: AsyncMock,
    ) -> None:
        """Test successful user registration."""
        user_id = uuid4()
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.username = "testuser"
        mock_user.email = "test@example.com"
        mock_user.is_active = True
        mock_user.created_at = "2023-01-01T00:00:00"

        mock_auth_service.create_user.return_value = ServiceResult.success(mock_user)

        response = client.post(
            "/auth/register",
            json={
                "username": "testuser",
                "email": "test@example.com",
                "password": "password123",
                "roles": ["user"],
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert data["is_active"] is True

    def test_register_user_failure(
        self,
        client: TestClient,
        mock_auth_service: AsyncMock,
    ) -> None:
        """Test failed user registration."""
        mock_auth_service.create_user.return_value = ServiceResult.failure(
            "Username already exists",
        )

        response = client.post(
            "/auth/register",
            json={
                "username": "testuser",
                "email": "test@example.com",
                "password": "password123",
            },
        )

        assert response.status_code == 400
        assert "Username already exists" in response.json()["detail"]

    def test_register_user_validation_error(self, client: TestClient) -> None:
        """Test user registration with validation errors."""
        response = client.post(
            "/auth/register",
            json={
                "username": "ab",  # Too short
                "email": "invalid-email",  # Invalid email
                "password": "123",  # Too short
            },
        )

        assert response.status_code == 422

    def test_login_success(
        self,
        client: TestClient,
        mock_auth_service: AsyncMock,
    ) -> None:
        """Test successful user login."""
        auth_response = {
            "access_token": "access_token_here",
            "refresh_token": "refresh_token_here",
            "token_type": "bearer",
            "expires_in": 3600,
        }

        mock_auth_service.authenticate.return_value = ServiceResult.success(
            auth_response,
        )

        response = client.post(
            "/auth/login",
            json={
                "username": "testuser",
                "password": "password123",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == "access_token_here"
        assert data["refresh_token"] == "refresh_token_here"
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 3600

    def test_login_failure(
        self,
        client: TestClient,
        mock_auth_service: AsyncMock,
    ) -> None:
        """Test failed user login."""
        mock_auth_service.authenticate.return_value = ServiceResult.failure(
            "Invalid credentials",
        )

        response = client.post(
            "/auth/login",
            json={
                "username": "testuser",
                "password": "wrongpassword",
            },
        )

        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

    def test_get_me_success(
        self,
        client: TestClient,
        mock_auth_service: AsyncMock,
    ) -> None:
        """Test getting current user info."""
        user_data = {
            "sub": str(uuid4()),
            "username": "testuser",
            "token_type": "access",
        }

        mock_auth_service.validate_token.return_value = ServiceResult.success(user_data)

        response = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer valid_token"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == user_data["sub"]
        assert data["username"] == user_data["username"]
        assert data["token_type"] == user_data["token_type"]

    def test_get_me_unauthorized(
        self,
        client: TestClient,
        mock_auth_service: AsyncMock,
    ) -> None:
        """Test getting current user info without valid token."""
        mock_auth_service.validate_token.return_value = ServiceResult.failure(
            "Invalid token",
        )

        response = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer invalid_token"},
        )

        assert response.status_code == 401

    def test_get_me_no_auth_header(self, client: TestClient) -> None:
        """Test getting current user info without auth header."""
        response = client.get("/auth/me")
        assert response.status_code == 403

    def test_change_password_success(
        self,
        client: TestClient,
        mock_auth_service: AsyncMock,
    ) -> None:
        """Test successful password change."""
        user_data = {
            "sub": str(uuid4()),
            "username": "testuser",
            "token_type": "access",
        }

        # Mock token validation
        mock_auth_service.validate_token.return_value = ServiceResult.success(user_data)
        # Mock password change
        mock_auth_service.change_password.return_value = ServiceResult.success(None)

        response = client.post(
            "/auth/change-password",
            headers={"Authorization": "Bearer valid_token"},
            json={
                "current_password": "oldpassword",
                "new_password": "newpassword123",
            },
        )

        assert response.status_code == 200
        assert response.json() == {"message": "Password changed successfully"}

    def test_change_password_failure(
        self,
        client: TestClient,
        mock_auth_service: AsyncMock,
    ) -> None:
        """Test failed password change."""
        user_data = {
            "sub": str(uuid4()),
            "username": "testuser",
            "token_type": "access",
        }

        # Mock token validation
        mock_auth_service.validate_token.return_value = ServiceResult.success(user_data)
        # Mock password change failure
        mock_auth_service.change_password.return_value = ServiceResult.failure(
            "Current password is incorrect",
        )

        response = client.post(
            "/auth/change-password",
            headers={"Authorization": "Bearer valid_token"},
            json={
                "current_password": "wrongpassword",
                "new_password": "newpassword123",
            },
        )

        assert response.status_code == 400
        assert "Current password is incorrect" in response.json()["detail"]

    def test_change_password_unauthorized(
        self,
        client: TestClient,
        mock_auth_service: AsyncMock,
    ) -> None:
        """Test password change without valid token."""
        mock_auth_service.validate_token.return_value = ServiceResult.failure(
            "Invalid token",
        )

        response = client.post(
            "/auth/change-password",
            headers={"Authorization": "Bearer invalid_token"},
            json={
                "current_password": "oldpassword",
                "new_password": "newpassword123",
            },
        )

        assert response.status_code == 401

    def test_change_password_validation_error(
        self,
        client: TestClient,
        mock_auth_service: AsyncMock,
    ) -> None:
        """Test password change with validation errors."""
        user_data = {
            "sub": str(uuid4()),
            "username": "testuser",
            "token_type": "access",
        }

        mock_auth_service.validate_token.return_value = ServiceResult.success(user_data)

        response = client.post(
            "/auth/change-password",
            headers={"Authorization": "Bearer valid_token"},
            json={
                "current_password": "oldpassword",
                "new_password": "123",  # Too short
            },
        )

        assert response.status_code == 422


class TestAPIModels:
    """Test API model validations."""

    def test_create_user_request_valid(self) -> None:
        """Test valid user creation request."""
        from flext_auth.api.models import CreateUserRequest

        request = CreateUserRequest(
            username="testuser",
            email="test@example.com",
            password="password123",
            roles=["user"],
        )

        assert request.username == "testuser"
        assert request.email == "test@example.com"
        assert request.password == "password123"
        assert request.roles == ["user"]

    def test_create_user_request_minimal(self) -> None:
        """Test minimal user creation request."""
        from flext_auth.api.models import CreateUserRequest

        request = CreateUserRequest(
            username="testuser",
            email="test@example.com",
            password="password123",
        )

        assert request.username == "testuser"
        assert request.email == "test@example.com"
        assert request.password == "password123"
        assert request.roles is None

    def test_authenticate_request_valid(self) -> None:
        """Test valid authentication request."""
        from flext_auth.api.models import AuthenticateRequest

        request = AuthenticateRequest(
            username="testuser",
            password="password123",
        )

        assert request.username == "testuser"
        assert request.password == "password123"

    def test_change_password_request_valid(self) -> None:
        """Test valid password change request."""
        from flext_auth.api.models import ChangePasswordRequest

        request = ChangePasswordRequest(
            current_password="oldpassword",
            new_password="newpassword123",
        )

        assert request.current_password == "oldpassword"
        assert request.new_password == "newpassword123"

    def test_user_response_valid(self) -> None:
        """Test valid user response."""
        from datetime import datetime

        from flext_auth.api.models import UserResponse

        user_response = UserResponse(
            id=str(uuid4()),
            username="testuser",
            email="test@example.com",
            is_active=True,
            created_at=datetime.now(),
        )

        assert user_response.username == "testuser"
        assert user_response.email == "test@example.com"
        assert user_response.is_active is True

    def test_authenticate_response_valid(self) -> None:
        """Test valid authentication response."""
        from flext_auth.api.models import AuthenticateResponse

        response = AuthenticateResponse(
            access_token="access_token",
            refresh_token="refresh_token",
            expires_in=3600,
        )

        assert response.access_token == "access_token"
        assert response.refresh_token == "refresh_token"
        assert response.token_type == "bearer"
        assert response.expires_in == 3600

    def test_error_response_valid(self) -> None:
        """Test valid error response."""
        from flext_auth.api.models import ErrorResponse

        error_response = ErrorResponse(
            message="An error occurred",
            error_type="validation",
            details={"field": "username", "issue": "too short"},
        )

        assert error_response.message == "An error occurred"
        assert error_response.error_type == "validation"
        assert error_response.details == {"field": "username", "issue": "too short"}


class TestDependencies:
    """Test dependency injection."""

    def test_get_container(self) -> None:
        """Test getting container."""
        from flext_auth.api.dependencies import get_container

        container = get_container()
        assert container is not None

        # Should return same instance (cached)
        container2 = get_container()
        assert container is container2

    def test_get_auth_service(self) -> None:
        """Test getting auth service."""
        from flext_auth.api.dependencies import get_auth_service

        auth_service = get_auth_service()
        assert auth_service is not None
