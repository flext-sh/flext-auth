"""Test JWT service functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from flext_auth.domain.value_objects import FlextJWTClaims
from flext_auth.jwt import FlextJWTService

# Constants
EXPECTED_BULK_SIZE = 2


class TestJWTService:
    """Test JWTService functionality."""

    def test_jwt_service_creation(self) -> None:
        """Test JWT service creation."""
        service = FlextJWTService(
            secret_key="test-secret-key-at-least-32-chars",
            algorithm="HS256",
            access_token_expire_minutes=30,
            refresh_token_expire_days=7,
        )
        assert service is not None

    def test_jwt_service_creation_minimal(self) -> None:
        """Test JWT service creation with minimal parameters."""
        service = FlextJWTService(secret_key="test-secret-key-at-least-32-chars")
        assert service is not None

    def test_generate_access_token_success(self) -> None:
        """Test successful access token creation."""
        service = FlextJWTService(
            secret_key="test-secret-key-at-least-32-chars",
            algorithm="HS256",
            access_token_expire_minutes=30,
        )

        result = service.generate_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )

        assert result.success
        token = result.data
        assert isinstance(token, str)
        assert len(token) > 0
        if (
            token.count(".") != EXPECTED_BULK_SIZE
        ):  # JWT format: header.payload.signature
            raise AssertionError(f"Expected {2}, got {token.count('.')}")

    def test_generate_access_token_with_extra_claims(self) -> None:
        """Test access token creation with extra claims."""
        service = FlextJWTService(secret_key="test-secret-key-at-least-32-chars")

        extra_claims = {"custom_field": "custom_value"}
        result = service.generate_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
            extra_claims=extra_claims,
        )

        assert result.success
        token = result.data
        assert isinstance(token, str)

    def test_generate_refresh_token_success(self) -> None:
        """Test successful refresh token creation."""
        service = FlextJWTService(
            secret_key="test-secret-key-at-least-32-chars",
            refresh_token_expire_days=7,
        )

        result = service.generate_refresh_token(user_id="user-123")

        assert result.success
        token = result.data
        assert isinstance(token, str)
        assert len(token) > 0
        if token.count(".") != EXPECTED_BULK_SIZE:  # JWT format
            raise AssertionError(f"Expected {2}, got {token.count('.')}")

    def test_verify_token_success(self) -> None:
        """Test successful token verification."""
        service = FlextJWTService(secret_key="test-secret-key-at-least-32-chars")

        # Create token first
        create_result = service.generate_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )
        assert create_result.success
        token = create_result.data

        # Verify token
        verify_result = service.verify_token(token)
        assert verify_result.success
        claims = verify_result.data
        assert isinstance(claims, FlextJWTClaims)
        if claims.sub != "user-123":
            raise AssertionError(f"Expected {'user-123'}, got {claims.sub}")
        assert claims.username == "testuser"
        if claims.role != "user":
            raise AssertionError(f"Expected {'user'}, got {claims.role}")
        assert claims.token_type == "access"

    def test_verify_token_invalid(self) -> None:
        """Test verification of invalid token."""
        service = FlextJWTService(secret_key="test-secret-key-at-least-32-chars")

        result = service.verify_token("invalid.token.here")
        assert not result.success
        if "Failed to verify token" not in result.error:
            raise AssertionError(
                f"Expected {'Failed to verify token'} in {result.error}"
            )

    def test_verify_token_expired(self) -> None:
        """Test verification of expired token."""
        service = FlextJWTService(
            secret_key="test-secret-key-at-least-32-chars",
            access_token_expire_minutes=0,  # Expire immediately
        )

        # Create token that expires immediately
        create_result = service.generate_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )
        assert create_result.success
        token = create_result.data

        # Wait a moment to ensure expiration (not practical in real tests)
        # Instead, we'll test with a token that has past expiration

        time.sleep(1)

        # Verify expired token
        verify_result = service.verify_token(token)
        assert not verify_result.success
        if "expired" not in verify_result.error.lower():
            raise AssertionError(f"Expected 'expired' in {verify_result.error}")

    def test_verify_token_wrong_secret(self) -> None:
        """Test verification with wrong secret key."""
        service1 = FlextJWTService(secret_key="secret-key-1-at-least-32-chars-long")
        service2 = FlextJWTService(secret_key="secret-key-2-at-least-32-chars-long")

        # Create token with service1
        create_result = service1.generate_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )
        assert create_result.success
        token = create_result.data

        # Try to verify with service2 (different secret)
        verify_result = service2.verify_token(token)
        assert not verify_result.success
        if "Failed to verify token" not in verify_result.error:
            raise AssertionError(
                f"Expected {'Failed to verify token'} in {verify_result.error}"
            )

    def test_refresh_token_flow(self) -> None:
        """Test refresh token flow."""
        service = FlextJWTService(secret_key="test-secret-key-at-least-32-chars")

        # Create refresh token
        refresh_result = service.generate_refresh_token(user_id="user-123")
        assert refresh_result.success
        refresh_token = refresh_result.data

        # Verify refresh token
        verify_result = service.verify_token(refresh_token)
        assert verify_result.success
        claims = verify_result.data
        if claims.sub != "user-123":
            raise AssertionError(f"Expected {'user-123'}, got {claims.sub}")
        assert claims.token_type == "refresh"

    def test_get_token_claims_success(self) -> None:
        """Test getting token claims without verification."""
        service = FlextJWTService(secret_key="test-secret-key-at-least-32-chars")

        # Create token
        create_result = service.generate_access_token(
            user_id="user-123",
            username="testuser",
            role="REDACTED_LDAP_BIND_PASSWORD",
        )
        assert create_result.success
        token = create_result.data

        # Get claims
        claims_result = service.get_token_claims(token)
        assert claims_result.success
        claims = claims_result.data
        if claims.sub != "user-123":
            raise AssertionError(f"Expected {'user-123'}, got {claims.sub}")
        assert claims.username == "testuser"
        if claims.role != "REDACTED_LDAP_BIND_PASSWORD":
            raise AssertionError(f"Expected {'REDACTED_LDAP_BIND_PASSWORD'}, got {claims.role}")

    def test_get_token_claims_invalid_token(self) -> None:
        """Test getting claims from invalid token."""
        service = FlextJWTService(secret_key="test-secret-key-at-least-32-chars")

        result = service.get_token_claims("invalid.token")
        assert not result.success
        if "Failed to decode token" not in result.error:
            raise AssertionError(
                f"Expected {'Failed to decode token'} in {result.error}"
            )

    def test_token_expiration_validation(self) -> None:
        """Test token expiration validation."""
        service = FlextJWTService(
            secret_key="test-secret-key-at-least-32-chars",
            access_token_expire_minutes=60,
        )

        # Create token
        create_result = service.generate_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )
        assert create_result.success
        token = create_result.data

        # Verify token and check expiration is in the future
        verify_result = service.verify_token(token)
        assert verify_result.success
        claims = verify_result.data

        # Expiration should be approximately 60 minutes from now
        expected_exp = datetime.now(UTC) + timedelta(minutes=60)
        actual_exp = datetime.fromtimestamp(claims.exp, UTC)

        # Allow 1 minute tolerance
        assert abs((actual_exp - expected_exp).total_seconds()) < 60

    def test_different_algorithms(self) -> None:
        """Test JWT service with different algorithms."""
        algorithms = ["HS256", "HS384", "HS512"]

        for algorithm in algorithms:
            service = FlextJWTService(
                secret_key="test-secret-key-at-least-32-chars",
                algorithm=algorithm,
            )

            # Create and verify token
            create_result = service.generate_access_token(
                user_id="user-123",
                username="testuser",
                role="user",
            )
            assert create_result.success

            verify_result = service.verify_token(create_result.data)
            assert verify_result.success

    def test_jwt_claims_validation(self) -> None:
        """Test JWT claims validation."""
        service = FlextJWTService(secret_key="test-secret-key-at-least-32-chars")

        # Create token
        create_result = service.generate_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )
        assert create_result.success

        # Verify and validate claims
        verify_result = service.verify_token(create_result.data)
        assert verify_result.success
        claims = verify_result.data

        # Claims should be valid
        claims.validate_business_rules()  # Should not raise
