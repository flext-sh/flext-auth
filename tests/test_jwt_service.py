"""Test JWT service functionality."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flext_auth.domain.value_objects import JWTClaims
from flext_auth.services.jwt_service import JWTService


class TestJWTService:
    """Test JWTService functionality."""

    def test_jwt_service_creation(self) -> None:
        """Test JWT service creation."""
        service = JWTService(
            secret_key="test-secret-key-at-least-32-chars",
            algorithm="HS256",
            access_token_expire_minutes=30,
            refresh_token_expire_days=7,
        )
        assert service is not None

    def test_jwt_service_creation_minimal(self) -> None:
        """Test JWT service creation with minimal parameters."""
        service = JWTService(secret_key="test-secret-key-at-least-32-chars")
        assert service is not None

    def test_create_access_token_success(self) -> None:
        """Test successful access token creation."""
        service = JWTService(
            secret_key="test-secret-key-at-least-32-chars",
            algorithm="HS256",
            access_token_expire_minutes=30,
        )

        result = service.create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )

        assert result.is_success
        token = result.data
        assert isinstance(token, str)
        assert len(token) > 0
        assert token.count(".") == 2  # JWT format: header.payload.signature

    def test_create_access_token_with_extra_claims(self) -> None:
        """Test access token creation with extra claims."""
        service = JWTService(secret_key="test-secret-key-at-least-32-chars")

        extra_claims = {"custom_field": "custom_value"}
        result = service.create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
            extra_claims=extra_claims,
        )

        assert result.is_success
        token = result.data
        assert isinstance(token, str)

    def test_create_refresh_token_success(self) -> None:
        """Test successful refresh token creation."""
        service = JWTService(
            secret_key="test-secret-key-at-least-32-chars",
            refresh_token_expire_days=7,
        )

        result = service.create_refresh_token(user_id="user-123")

        assert result.is_success
        token = result.data
        assert isinstance(token, str)
        assert len(token) > 0
        assert token.count(".") == 2  # JWT format

    def test_verify_token_success(self) -> None:
        """Test successful token verification."""
        service = JWTService(secret_key="test-secret-key-at-least-32-chars")

        # Create token first
        create_result = service.create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )
        assert create_result.is_success
        token = create_result.data

        # Verify token
        verify_result = service.verify_token(token)
        assert verify_result.is_success
        claims = verify_result.data
        assert isinstance(claims, JWTClaims)
        assert claims.sub == "user-123"
        assert claims.username == "testuser"
        assert claims.role == "user"
        assert claims.token_type == "access"

    def test_verify_token_invalid(self) -> None:
        """Test verification of invalid token."""
        service = JWTService(secret_key="test-secret-key-at-least-32-chars")

        result = service.verify_token("invalid.token.here")
        assert not result.is_success
        assert "Failed to verify token" in result.error

    def test_verify_token_expired(self) -> None:
        """Test verification of expired token."""
        service = JWTService(
            secret_key="test-secret-key-at-least-32-chars",
            access_token_expire_minutes=0,  # Expire immediately
        )

        # Create token that expires immediately
        create_result = service.create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )
        assert create_result.is_success
        token = create_result.data

        # Wait a moment to ensure expiration (not practical in real tests)
        # Instead, we'll test with a token that has past expiration
        import time

        time.sleep(1)

        # Verify expired token
        verify_result = service.verify_token(token)
        assert not verify_result.is_success
        assert "Failed to verify token" in verify_result.error

    def test_verify_token_wrong_secret(self) -> None:
        """Test verification with wrong secret key."""
        service1 = JWTService(secret_key="secret-key-1-at-least-32-chars-long")
        service2 = JWTService(secret_key="secret-key-2-at-least-32-chars-long")

        # Create token with service1
        create_result = service1.create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )
        assert create_result.is_success
        token = create_result.data

        # Try to verify with service2 (different secret)
        verify_result = service2.verify_token(token)
        assert not verify_result.is_success
        assert "Failed to verify token" in verify_result.error

    def test_refresh_token_flow(self) -> None:
        """Test refresh token flow."""
        service = JWTService(secret_key="test-secret-key-at-least-32-chars")

        # Create refresh token
        refresh_result = service.create_refresh_token(user_id="user-123")
        assert refresh_result.is_success
        refresh_token = refresh_result.data

        # Verify refresh token
        verify_result = service.verify_token(refresh_token)
        assert verify_result.is_success
        claims = verify_result.data
        assert claims.sub == "user-123"
        assert claims.token_type == "refresh"

    def test_get_token_claims_success(self) -> None:
        """Test getting token claims without verification."""
        service = JWTService(secret_key="test-secret-key-at-least-32-chars")

        # Create token
        create_result = service.create_access_token(
            user_id="user-123",
            username="testuser",
            role="REDACTED_LDAP_BIND_PASSWORD",
        )
        assert create_result.is_success
        token = create_result.data

        # Get claims
        claims_result = service.get_token_claims(token)
        assert claims_result.is_success
        claims = claims_result.data
        assert claims.sub == "user-123"
        assert claims.username == "testuser"
        assert claims.role == "REDACTED_LDAP_BIND_PASSWORD"

    def test_get_token_claims_invalid_token(self) -> None:
        """Test getting claims from invalid token."""
        service = JWTService(secret_key="test-secret-key-at-least-32-chars")

        result = service.get_token_claims("invalid.token")
        assert not result.is_success
        assert "Failed to decode token" in result.error

    def test_token_expiration_validation(self) -> None:
        """Test token expiration validation."""
        service = JWTService(
            secret_key="test-secret-key-at-least-32-chars",
            access_token_expire_minutes=60,
        )

        # Create token
        create_result = service.create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )
        assert create_result.is_success
        token = create_result.data

        # Verify token and check expiration is in the future
        verify_result = service.verify_token(token)
        assert verify_result.is_success
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
            service = JWTService(
                secret_key="test-secret-key-at-least-32-chars",
                algorithm=algorithm,
            )

            # Create and verify token
            create_result = service.create_access_token(
                user_id="user-123",
                username="testuser",
                role="user",
            )
            assert create_result.is_success

            verify_result = service.verify_token(create_result.data)
            assert verify_result.is_success

    def test_jwt_claims_validation(self) -> None:
        """Test JWT claims validation."""
        service = JWTService(secret_key="test-secret-key-at-least-32-chars")

        # Create token
        create_result = service.create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )
        assert create_result.is_success

        # Verify and validate claims
        verify_result = service.verify_token(create_result.data)
        assert verify_result.is_success
        claims = verify_result.data

        # Claims should be valid
        claims.validate_domain_rules()  # Should not raise
