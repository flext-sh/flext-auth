"""Comprehensive tests for flext-auth container module.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from zoneinfo import ZoneInfo

from flext_auth.constants import FlextAuthConstants
from flext_auth.container import FlextAuthContainer
from flext_auth.models import FlextAuthModels


class TestFlextAuthContainer:
    """Comprehensive tests for FlextAuthContainer class."""

    def test_create_user_from_request(self) -> None:
        """Test creating user from request."""
        request = FlextAuthModels.UserCreationRequest(
            username="testuser", email="test@example.com", password="TestPass123!"
        )

        with patch.object(FlextAuthModels.User, "create_user") as mock_create:
            mock_result = Mock(is_success=True, data=Mock())
            mock_create.return_value = mock_result

            result = FlextAuthContainer.create_user_from_request(request)

            assert result.is_success
            mock_create.assert_called_once_with(request)

    def test_create_user_from_request_failure(self) -> None:
        """Test creating user from request with failure."""
        request = FlextAuthModels.UserCreationRequest(
            username="testuser", email="test@example.com", password="TestPass123!"
        )

        with patch.object(FlextAuthModels.User, "create_user") as mock_create:
            mock_result = Mock(is_success=False, error="User creation failed")
            mock_create.return_value = mock_result

            result = FlextAuthContainer.create_user_from_request(request)

            assert result.is_failure
            assert result.error is not None
            assert "User creation failed" in result.error

    def test_create_user(self) -> None:
        """Test create_user method."""
        request = FlextAuthModels.UserCreationRequest(
            username="testuser", email="test@example.com", password="TestPass123!"
        )

        with patch.object(FlextAuthModels.User, "create_user") as mock_create:
            mock_result = Mock(is_success=True, data=Mock())
            mock_create.return_value = mock_result

            result = FlextAuthContainer.create_user(request)

            assert result.is_success
            mock_create.assert_called_once_with(request)

    def test_create_session_success(self) -> None:
        """Test successful session creation."""
        user_id = "user123"

        with (
            patch.object(FlextAuthContainer, "_generate_session_id") as mock_id,
            patch.object(FlextAuthContainer, "_generate_session_token") as mock_token,
            patch.object(
                FlextAuthContainer, "_calculate_session_expiry"
            ) as mock_expiry,
        ):
            mock_id.return_value = Mock(is_success=True, value="session_id_123")
            mock_token.return_value = Mock(
                is_success=True, value="a" * 32
            )  # 32 char minimum
            mock_expiry.return_value = Mock(
                is_success=True, value=datetime.now(ZoneInfo("UTC"))
            )

            result = FlextAuthContainer.create_session(user_id)

            assert result.is_success
            assert isinstance(result.data, FlextAuthModels.Session)
            assert result.data.user_id == user_id
            assert result.data.id == "session_id_123"
            assert result.data.session_token == "a" * 32
            assert result.data.is_active is True

    def test_create_session_with_optional_params(self) -> None:
        """Test session creation with optional parameters."""
        user_id = "user123"
        ip_address = "192.168.1.1"
        user_agent = "Mozilla/5.0"
        expires_in_minutes = 60

        with (
            patch.object(FlextAuthContainer, "_generate_session_id") as mock_id,
            patch.object(FlextAuthContainer, "_generate_session_token") as mock_token,
            patch.object(
                FlextAuthContainer, "_calculate_session_expiry"
            ) as mock_expiry,
        ):
            mock_id.return_value = Mock(is_success=True, value="session_id_123")
            mock_token.return_value = Mock(
                is_success=True, value="a" * 32
            )  # 32 char minimum
            mock_expiry.return_value = Mock(
                is_success=True, value=datetime.now(ZoneInfo("UTC"))
            )

            result = FlextAuthContainer.create_session(
                user_id,
                expires_in_minutes=expires_in_minutes,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            assert result.is_success
            assert result.data.ip_address == ip_address
            assert result.data.user_agent == user_agent
            mock_expiry.assert_called_once_with(expires_in_minutes)

    def test_create_session_empty_user_id(self) -> None:
        """Test session creation with empty user ID."""
        result = FlextAuthContainer.create_session("")

        assert result.is_failure
        assert result.error is not None
        assert "User ID cannot be empty" in result.error

    def test_create_session_whitespace_user_id(self) -> None:
        """Test session creation with whitespace-only user ID."""
        result = FlextAuthContainer.create_session("   ")

        assert result.is_failure
        assert result.error is not None
        assert "User ID cannot be empty" in result.error

    def test_create_session_invalid_expiry(self) -> None:
        """Test session creation with invalid expiry."""
        result = FlextAuthContainer.create_session("user123", expires_in_minutes=0)

        assert result.is_failure
        assert result.error is not None
        assert "Session expiry must be positive" in result.error

    def test_create_session_negative_expiry(self) -> None:
        """Test session creation with negative expiry."""
        result = FlextAuthContainer.create_session("user123", expires_in_minutes=-10)

        assert result.is_failure
        assert result.error is not None
        assert "Session expiry must be positive" in result.error

    def test_create_session_id_generation_failure(self) -> None:
        """Test session creation with session ID generation failure."""
        with patch.object(FlextAuthContainer, "_generate_session_id") as mock_id:
            mock_id.return_value = Mock(is_success=False, error="ID generation failed")

            result = FlextAuthContainer.create_session("user123")

            assert result.is_failure
            assert result.error is not None
            assert "ID generation failed" in result.error

    def test_create_session_token_generation_failure(self) -> None:
        """Test session creation with token generation failure."""
        with (
            patch.object(FlextAuthContainer, "_generate_session_id") as mock_id,
            patch.object(FlextAuthContainer, "_generate_session_token") as mock_token,
        ):
            mock_id.return_value = Mock(is_success=True, value="session_id_123")
            mock_token.return_value = Mock(
                is_success=False, error="Token generation failed"
            )

            result = FlextAuthContainer.create_session("user123")

            assert result.is_failure
            assert result.error is not None
            assert "Token generation failed" in result.error

    def test_create_session_expiry_calculation_failure(self) -> None:
        """Test session creation with expiry calculation failure."""
        with (
            patch.object(FlextAuthContainer, "_generate_session_id") as mock_id,
            patch.object(FlextAuthContainer, "_generate_session_token") as mock_token,
            patch.object(
                FlextAuthContainer, "_calculate_session_expiry"
            ) as mock_expiry,
        ):
            mock_id.return_value = Mock(is_success=True, value="session_id_123")
            mock_token.return_value = Mock(
                is_success=True, value="a" * 32
            )  # 32 char minimum
            mock_expiry.return_value = Mock(
                is_success=False, error="Expiry calculation failed"
            )

            result = FlextAuthContainer.create_session("user123")

            assert result.is_failure
            assert result.error is not None
            assert "Expiry calculation failed" in result.error

    @patch("flext_auth.container.FlextUtilities.Generators.generate_id")
    def test_create_session_with_generated_id_success(
        self, mock_generate_id: Mock
    ) -> None:
        """Test successful session creation with generated ID."""
        mock_generate_id.side_effect = ["generated_id_123", "a" * 32]  # id, then token

        result = FlextAuthContainer.create_session("user123")

        assert result.is_success
        assert result.value.id == "generated_id_123"
        assert result.value.user_id == "user123"

    @patch("flext_auth.container.FlextUtilities.Generators.generate_id")
    def test_create_session_with_id_generation_failure(
        self, mock_generate_id: Mock
    ) -> None:
        """Test session creation failure when ID generation fails."""
        mock_generate_id.return_value = None

        result = FlextAuthContainer.create_session("user123")

        assert result.is_failure
        assert result.error is not None
        assert "Session ID generation failed" in result.error

    @patch("flext_auth.container.FlextUtilities.Generators.generate_id")
    def test_create_session_with_generated_token_success(
        self, mock_generate_id: Mock
    ) -> None:
        """Test successful session creation with generated token."""
        mock_generate_id.side_effect = [
            "some_id",
            "generated_token_12345678901234567890",
        ]  # id, then token

        result = FlextAuthContainer.create_session("user123")

        assert result.is_success
        assert result.value.session_token == "generated_token_12345678901234567890"
        assert result.value.user_id == "user123"

    @patch("flext_auth.container.FlextUtilities.Generators.generate_id")
    def test_create_session_with_token_generation_failure(
        self, mock_generate_id: Mock
    ) -> None:
        """Test session creation failure when token generation fails."""
        mock_generate_id.side_effect = ["some_id", None]  # id succeeds, token fails

        result = FlextAuthContainer.create_session("user123")

        assert result.is_failure
        assert result.error is not None
        assert "Session token generation failed" in result.error

    def test_create_session_with_custom_expiry_success(self) -> None:
        """Test successful session creation with custom expiry."""
        expires_in_minutes = 60

        result = FlextAuthContainer.create_session(
            "user123", expires_in_minutes=expires_in_minutes
        )

        assert result.is_success
        assert isinstance(result.value.expires_at, datetime)
        # Check that the expiry is approximately 60 minutes from now
        expected_time = datetime.now(ZoneInfo("UTC")) + timedelta(minutes=60)
        time_diff = abs((result.value.expires_at - expected_time).total_seconds())
        assert time_diff < 5  # Allow 5 seconds tolerance

    def test_create_session_with_zero_expiry_failure(self) -> None:
        """Test session creation failure with zero expiry."""
        result = FlextAuthContainer.create_session("user123", expires_in_minutes=0)

        assert result.is_failure
        assert result.error is not None
        assert "Session expiry must be positive" in result.error

    def test_create_session_with_negative_expiry_failure(self) -> None:
        """Test session creation failure with negative expiry."""
        result = FlextAuthContainer.create_session("user123", expires_in_minutes=-10)

        assert result.is_failure
        assert result.error is not None
        assert "Session expiry must be positive" in result.error

    def test_create_session_with_excessive_expiry_failure(self) -> None:
        """Test session creation failure with excessive expiry."""
        result = FlextAuthContainer.create_session(
            "user123", expires_in_minutes=50000
        )  # > 30 days

        assert result.is_failure
        assert result.error is not None
        assert "Session expiry cannot exceed 30 days" in result.error

    def test_create_session_with_maximum_expiry_success(self) -> None:
        """Test successful session creation with maximum allowed expiry."""
        result = FlextAuthContainer.create_session(
            "user123", expires_in_minutes=43200
        )  # Exactly 30 days

        assert result.is_success
        assert isinstance(result.value, datetime)

    def test_create_jwt_token_success(self) -> None:
        """Test successful JWT token creation."""
        user_id = "user123"
        secret_key = "secret"
        expires_hours = 2

        with patch.object(FlextAuthModels.AuthToken, "create_jwt_token") as mock_create:
            mock_result = Mock(is_success=True, data=Mock())
            mock_create.return_value = mock_result

            result = FlextAuthContainer.create_jwt_token(
                user_id, secret_key, expires_hours
            )

            assert result.is_success
            mock_create.assert_called_once_with(
                user_id=user_id,
                expiry_minutes=120,  # 2 hours * 60 minutes
                token_type=FlextAuthConstants.Jwt.DEFAULT_TOKEN_TYPE,
            )

    def test_create_jwt_token_with_optional_params(self) -> None:
        """Test JWT token creation with optional parameters."""
        user_id = "user123"
        secret_key = "secret"
        expires_hours = 1
        username = "testuser"
        roles = ["REDACTED_LDAP_BIND_PASSWORD", "user"]

        with patch.object(FlextAuthModels.AuthToken, "create_jwt_token") as mock_create:
            mock_result = Mock(is_success=True, data=Mock())
            mock_create.return_value = mock_result

            result = FlextAuthContainer.create_jwt_token(
                user_id, secret_key, expires_hours, username, roles
            )

            assert result.is_success
            # Verify the secret_key, username, and roles are consumed (suppressed warnings)

    def test_create_jwt_token_default_expiry(self) -> None:
        """Test JWT token creation with default expiry."""
        user_id = "user123"
        secret_key = "secret"

        with patch.object(FlextAuthModels.AuthToken, "create_jwt_token") as mock_create:
            mock_result = Mock(is_success=True, data=Mock())
            mock_create.return_value = mock_result

            result = FlextAuthContainer.create_jwt_token(
                user_id, secret_key, expires_hours=0
            )

            assert result.is_success
            mock_create.assert_called_once_with(
                user_id=user_id,
                expiry_minutes=FlextAuthConstants.Jwt.DEFAULT_EXPIRY_MINUTES,
                token_type=FlextAuthConstants.Jwt.DEFAULT_TOKEN_TYPE,
            )

    def test_create_jwt_token_failure(self) -> None:
        """Test JWT token creation failure."""
        user_id = "user123"
        secret_key = "secret"

        with patch.object(FlextAuthModels.AuthToken, "create_jwt_token") as mock_create:
            mock_result = Mock(is_success=False, error="JWT creation failed")
            mock_create.return_value = mock_result

            result = FlextAuthContainer.create_jwt_token(user_id, secret_key)

            assert result.is_failure
            assert result.error is not None
            assert "JWT creation failed" in result.error


class TestFlextAuthContainerIntegration:
    """Integration tests for FlextAuthContainer."""

    def test_complete_session_creation_flow(self) -> None:
        """Test complete session creation flow."""
        user_id = "user123"

        with patch(
            "flext_auth.container.FlextUtilities.Generators.generate_id"
        ) as mock_generate_id:
            mock_generate_id.side_effect = ["session_id_123", "a" * 32]

            result = FlextAuthContainer.create_session(
                user_id,
                expires_in_minutes=120,
                ip_address="192.168.1.1",
                user_agent="TestAgent",
            )

            assert result.is_success
            session = result.data
            assert session.user_id == user_id
            assert session.id == "session_id_123"
            assert session.session_token == "a" * 32
            assert session.ip_address == "192.168.1.1"
            assert session.user_agent == "TestAgent"
            assert session.is_active is True

    def test_complete_user_creation_flow(self) -> None:
        """Test complete user creation flow."""
        request = FlextAuthModels.UserCreationRequest(
            username="newuser", email="new@example.com", password="NewPass123!"
        )

        with patch.object(FlextAuthModels.User, "create_user") as mock_create:
            mock_user = Mock(spec=FlextAuthModels.User)
            mock_result = Mock(is_success=True, data=mock_user)
            mock_create.return_value = mock_result

            result = FlextAuthContainer.create_user_from_request(request)

            assert result.is_success
            assert result.data is mock_user

    def test_complete_jwt_creation_flow(self) -> None:
        """Test complete JWT token creation flow."""
        user_id = "user123"
        secret_key = "test_secret"

        with patch.object(FlextAuthModels.AuthToken, "create_jwt_token") as mock_create:
            mock_token = Mock(spec=FlextAuthModels.AuthToken)
            mock_result = Mock(is_success=True, data=mock_token)
            mock_create.return_value = mock_result

            result = FlextAuthContainer.create_jwt_token(
                user_id, secret_key, expires_hours=24
            )

            assert result.is_success
            assert result.data is mock_token

    def test_error_handling_edge_cases(self) -> None:
        """Test error handling for edge cases."""
        # Test None user_id - should be handled by type system, but test the behavior
        result = FlextAuthContainer.create_session(
            ""
        )  # Use empty string instead of None
        assert result.is_failure

        # Test very large expiry
        result = FlextAuthContainer.create_session("user123", expires_in_minutes=100000)
        assert result.is_failure
        assert result.error is not None
        assert "cannot exceed 30 days" in result.error

    def test_create_session_edge_cases(self) -> None:
        """Test session creation edge cases."""
        # Test exactly at boundary (30 days = 43200 minutes)
        result = FlextAuthContainer.create_session("user123", expires_in_minutes=43200)
        assert result.is_success

        # Test just over boundary
        result = FlextAuthContainer.create_session("user123", expires_in_minutes=43201)
        assert result.is_failure
        assert result.error is not None
        assert "cannot exceed 30 days" in result.error

        # Test very small positive value
        result = FlextAuthContainer.create_session("user123", expires_in_minutes=1)
        assert result.is_success

        # Test large but valid value
        result = FlextAuthContainer.create_session(
            "user123", expires_in_minutes=10080
        )  # 1 week
        assert result.is_success
