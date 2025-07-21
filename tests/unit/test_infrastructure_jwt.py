"""Comprehensive tests for flext_auth.infrastructure.jwt module."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import jwt
import pytest

from flext_auth.infrastructure.config import AuthConfig

if TYPE_CHECKING:
    from flext_auth.infrastructure.jwt import JWTService


def create_jwt_service_from_config(config: AuthConfig) -> JWTService:
    """Helper function to create JWTService using dependency injection."""
    from flext_auth.infrastructure.adapters import (
        create_filesystem,
        create_jwt_adapter,
        create_logger,
        create_time_provider,
    )
    from flext_auth.infrastructure.jwt import create_jwt_service

    # Create dependency adapters
    jwt_library = create_jwt_adapter()
    filesystem = create_filesystem()
    time_provider = create_time_provider()
    logger = create_logger("flext_auth.jwt")

    # Create a mock configuration adapter from AuthConfig
    class MockConfigurationAdapter:
        def __init__(self, config: AuthConfig) -> None:
            self._config = config

        def get_string(self, key: str, default: str | None = None) -> str:
            if key == "jwt_algorithm":
                return self._config.jwt_algorithm
            if key == "jwt_secret_key":
                return self._config.jwt_secret_key
            if key == "jwt_private_key_path":
                return getattr(self._config, "jwt_private_key_path", "")
            if key == "jwt_public_key_path":
                return getattr(self._config, "jwt_public_key_path", "")
            return default or ""

        def get_int(self, key: str, default: int | None = None) -> int:
            if key == "jwt_access_token_expire_minutes":
                return self._config.jwt_access_token_expire_minutes
            if key == "jwt_refresh_token_expire_days":
                return self._config.jwt_refresh_token_expire_days
            return default or 0

        def get_bool(self, key: str, default: bool | None = None) -> bool:
            return default or False

        def get_timedelta(self, key: str, default: timedelta | None = None) -> timedelta:
            return default or timedelta(seconds=0)

    config_adapter = MockConfigurationAdapter(config)

    return create_jwt_service(
        jwt_library=jwt_library,
        config=config_adapter,
        filesystem=filesystem,
        time_provider=time_provider,
        logger=logger,
    )


class TestJWTService:
    """Test JWTService functionality."""

    @pytest.fixture
    def auth_config_hs256(self) -> AuthConfig:
        """Create AuthConfig for HS256 algorithm."""
        return AuthConfig(
            jwt_secret_key="test-secret-key",
            jwt_algorithm="HS256",
            jwt_access_token_expire_minutes=30,
            jwt_refresh_token_expire_days=7,
        )

    @pytest.fixture
    def auth_config_rs256(self) -> AuthConfig:
        """Create AuthConfig for RS256 algorithm."""
        return AuthConfig(
            jwt_algorithm="RS256",
            jwt_private_key_path="path/to/private.pem",
            jwt_public_key_path="path/to/public.pem",
            jwt_access_token_expire_minutes=15,
            jwt_refresh_token_expire_days=30,
        )

    @pytest.fixture
    def jwt_service_hs256(self, auth_config_hs256: AuthConfig) -> JWTService:
        """Create JWTService with HS256 algorithm."""
        return create_jwt_service_from_config(auth_config_hs256)

    @pytest.fixture
    def rsa_key_pair(self) -> tuple[str, str]:
        """Generate RSA key pair for testing."""
        # Mock RSA keys for testing
        private_key = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wjKqxGYV9v7YdZEoEH5Kz9h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7s
P+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7s
P+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7s
P+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7s
P+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7s
P+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7sP+2Hq7h4m7jE8k7s
AgMBAAECggEBAKZqZ8W6x8JZN8Q5k5Q5k5Q5k5Q5k5Q5k5Q5k5Q5k5Q5k5Q5k5Q5
-----END PRIVATE KEY-----"""

        public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1L7VLPHCgcIyqsRm
Ffb+2HWRKBh+Ss/YeJu4xPJO7D/th6u4eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4
eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4
eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4
eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4
eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4eJu4xPJO7D/th6u4
QIDAQAB
-----END PUBLIC KEY-----"""

        return private_key, public_key

    def test_jwt_service_initialization_hs256(
        self,
        auth_config_hs256: AuthConfig,
    ) -> None:
        """Test JWTService initialization with HS256 algorithm."""
        service = create_jwt_service_from_config(auth_config_hs256)

        assert service._algorithm == "HS256"
        assert service._private_key == "test-secret-key"
        assert service._public_key == "test-secret-key"

    def test_jwt_service_initialization_rs256_with_key_paths(
        self,
        rsa_key_pair: tuple[str, str],
    ) -> None:
        """Test JWTService initialization with RS256 and key file paths."""
        private_key, public_key = rsa_key_pair

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create temporary key files
            private_key_path = Path(temp_dir) / "private.pem"
            public_key_path = Path(temp_dir) / "public.pem"

            private_key_path.write_text(private_key, encoding="utf-8")
            public_key_path.write_text(public_key, encoding="utf-8")

            config = AuthConfig(
                jwt_algorithm="RS256",
                jwt_private_key_path=str(private_key_path),
                jwt_public_key_path=str(public_key_path),
            )

            service = create_jwt_service_from_config(config)

            assert service._algorithm == "RS256"
            assert service._private_key == private_key
            assert service._public_key == public_key

    def test_jwt_service_initialization_rs256_without_keys(self) -> None:
        """Test JWTService initialization with RS256 but no key paths."""
        config = AuthConfig(
            jwt_algorithm="RS256",
            jwt_private_key_path=None,
            jwt_public_key_path=None,
        )

        service = create_jwt_service_from_config(config)

        assert service._algorithm == "RS256"
        assert service._private_key is None
        assert service._public_key is None

    def test_create_token_hs256(self, jwt_service_hs256: JWTService) -> None:
        """Test token creation with HS256 algorithm."""
        user_id = "user123"
        username = "testuser"
        expires_delta = timedelta(minutes=30)

        token = jwt_service_hs256.create_token(
            user_id=user_id,
            username=username,
            expires_delta=expires_delta,
        )

        # Verify token is a string
        assert isinstance(token, str)
        assert len(token) > 0

        # Decode and verify claims
        decoded = jwt.decode(
            token,
            "test-secret-key",
            algorithms=["HS256"],
            options={"verify_exp": False},  # Don't verify expiration for testing
        )

        assert decoded["sub"] == user_id
        assert decoded["username"] == username
        assert decoded["token_type"] == "access"  # Default
        assert "exp" in decoded
        assert "iat" in decoded

    def test_create_token_with_custom_token_type(
        self,
        jwt_service_hs256: JWTService,
    ) -> None:
        """Test token creation with custom token type."""
        user_id = "user123"
        username = "testuser"
        expires_delta = timedelta(minutes=15)

        token = jwt_service_hs256.create_token(
            user_id=user_id,
            username=username,
            token_type="refresh",
            expires_delta=expires_delta,
        )

        # Decode and verify token type
        decoded = jwt.decode(
            token,
            "test-secret-key",
            algorithms=["HS256"],
            options={"verify_exp": False},
        )

        assert decoded["token_type"] == "refresh"
        assert decoded["sub"] == user_id
        assert decoded["username"] == username

    def test_create_token_with_additional_claims(
        self,
        jwt_service_hs256: JWTService,
    ) -> None:
        """Test token creation with additional claims."""
        user_id = "user123"
        username = "testuser"
        expires_delta = timedelta(minutes=15)
        additional_claims = {
            "role": "REDACTED_LDAP_BIND_PASSWORD",
            "permissions": ["read", "write", "delete"],
            "tenant_id": "tenant123",
        }

        token = jwt_service_hs256.create_token(
            user_id=user_id,
            username=username,
            expires_delta=expires_delta,
            additional_claims=additional_claims,
        )

        # Decode and verify additional claims
        decoded = jwt.decode(
            token,
            "test-secret-key",
            algorithms=["HS256"],
            options={"verify_exp": False},
        )

        assert decoded["role"] == "REDACTED_LDAP_BIND_PASSWORD"
        assert decoded["permissions"] == ["read", "write", "delete"]
        assert decoded["tenant_id"] == "tenant123"

    def test_create_token_default_expiration_access(
        self,
        jwt_service_hs256: JWTService,
    ) -> None:
        """Test token creation with default access token expiration."""
        user_id = "user123"
        username = "testuser"

        before_creation = datetime.now(UTC)
        token = jwt_service_hs256.create_token(
            user_id=user_id,
            username=username,
            token_type="access",
        )
        datetime.now(UTC)

        # Decode token to check expiration
        decoded = jwt.decode(
            token,
            "test-secret-key",
            algorithms=["HS256"],
            options={"verify_exp": False},
        )

        exp_timestamp = decoded["exp"]
        exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=UTC)

        # Should expire in 30 minutes (default for access tokens)
        expected_exp = before_creation + timedelta(minutes=30)
        assert abs((exp_datetime - expected_exp).total_seconds()) < 60

    def test_create_token_default_expiration_refresh(
        self,
        jwt_service_hs256: JWTService,
    ) -> None:
        """Test token creation with default refresh token expiration."""
        user_id = "user123"
        username = "testuser"

        before_creation = datetime.now(UTC)
        token = jwt_service_hs256.create_token(
            user_id=user_id,
            username=username,
            token_type="refresh",
        )
        datetime.now(UTC)

        # Decode token to check expiration
        decoded = jwt.decode(
            token,
            "test-secret-key",
            algorithms=["HS256"],
            options={"verify_exp": False},
        )

        exp_timestamp = decoded["exp"]
        exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=UTC)

        # Should expire in 7 days (default for refresh tokens)
        expected_exp = before_creation + timedelta(days=7)
        assert abs((exp_datetime - expected_exp).total_seconds()) < 60

    def test_create_token_without_private_key(self) -> None:
        """Test token creation fails without private key."""
        config = AuthConfig(
            jwt_algorithm="RS256",
            jwt_private_key_path=None,
            jwt_public_key_path=None,
        )
        service = create_jwt_service_from_config(config)

        with pytest.raises(ValueError, match="Private key not configured"):
            service.create_token(
                user_id="user123",
                username="testuser",
            )

    def test_decode_token_valid(self, jwt_service_hs256: JWTService) -> None:
        """Test token decoding with valid token."""
        user_id = "user123"
        username = "testuser"
        expires_delta = timedelta(minutes=30)

        # Create token
        token = jwt_service_hs256.create_token(
            user_id=user_id,
            username=username,
            expires_delta=expires_delta,
        )

        # Decode token
        claims = jwt_service_hs256.decode_token(token)

        assert claims is not None
        assert claims["sub"] == user_id
        assert claims["username"] == username
        assert claims["token_type"] == "access"

    def test_decode_token_invalid_signature(
        self,
        jwt_service_hs256: JWTService,
    ) -> None:
        """Test token decoding with invalid signature."""
        # Create token with different secret
        fake_token = jwt.encode(
            {"sub": "user123", "exp": datetime.now(UTC) + timedelta(minutes=30)},
            "wrong-secret",
            algorithm="HS256",
        )

        # Should raise ValueError for invalid signature
        with pytest.raises(ValueError, match="Invalid token"):
            jwt_service_hs256.decode_token(str(fake_token))

    def test_decode_token_expired(self, jwt_service_hs256: JWTService) -> None:
        """Test token decoding with expired token."""
        # Create expired token
        expired_payload = {
            "sub": "user123",
            "username": "testuser",
            "token_type": "access",
            "exp": datetime.now(UTC) - timedelta(minutes=30),  # Expired
            "iat": datetime.now(UTC) - timedelta(minutes=35),
            "nbf": datetime.now(UTC) - timedelta(minutes=35),
        }
        expired_token = jwt.encode(
            expired_payload,
            "test-secret-key",
            algorithm="HS256",
        )

        # Should raise ValueError for expired token
        with pytest.raises(ValueError, match="Token has expired"):
            jwt_service_hs256.decode_token(str(expired_token))

    def test_decode_token_malformed(self, jwt_service_hs256: JWTService) -> None:
        """Test token decoding with malformed token."""
        # Test various malformed tokens
        malformed_tokens = [
            "invalid.token.format",
            "not-a-jwt-token",
            "",
            "header.payload",  # Missing signature
            "too.many.parts.here.invalid",
        ]

        for malformed_token in malformed_tokens:
            with pytest.raises(ValueError, match="Invalid token"):
                jwt_service_hs256.decode_token(malformed_token)

    def test_decode_token_without_public_key(self) -> None:
        """Test token decoding fails without public key."""
        config = AuthConfig(
            jwt_algorithm="RS256",
            jwt_private_key_path=None,
            jwt_public_key_path=None,
        )
        service = create_jwt_service_from_config(config)

        with pytest.raises(ValueError, match="Public key not configured"):
            service.decode_token("some.jwt.token")

    @patch("flext_auth.infrastructure.jwt.Path.read_text")
    def test_jwt_service_rs256_file_not_found(self, mock_read_text: MagicMock) -> None:
        """Test JWTService with RS256 when key files don't exist."""
        mock_read_text.side_effect = FileNotFoundError("Key file not found")

        config = AuthConfig(
            jwt_algorithm="RS256",
            jwt_private_key_path="nonexistent/private.pem",
            jwt_public_key_path="nonexistent/public.pem",
        )

        with pytest.raises(FileNotFoundError):
            create_jwt_service_from_config(config)

    def test_jwt_service_algorithm_variants(self) -> None:
        """Test JWTService with various JWT algorithms."""
        # Test different HMAC algorithms
        hmac_algorithms = ["HS256", "HS384", "HS512"]
        for algorithm in hmac_algorithms:
            config = AuthConfig(
                jwt_secret_key="test-secret",
                jwt_algorithm=algorithm,
            )
            service = create_jwt_service_from_config(config)
            assert service._algorithm == algorithm
            assert service._private_key == "test-secret"
            assert service._public_key == "test-secret"

        # Test different RSA algorithms
        rsa_algorithms = ["RS256", "RS384", "RS512"]
        for algorithm in rsa_algorithms:
            config = AuthConfig(
                jwt_algorithm=algorithm,
                jwt_private_key_path=None,
                jwt_public_key_path=None,
            )
            service = create_jwt_service_from_config(config)
            assert service._algorithm == algorithm
            assert service._private_key is None
            assert service._public_key is None


class TestJWTServiceIntegration:
    """Test JWTService integration scenarios."""

    def test_full_token_lifecycle(self) -> None:
        """Test complete token lifecycle: create and decode."""
        config = AuthConfig(
            jwt_secret_key="integration-test-secret",
            jwt_algorithm="HS256",
            jwt_access_token_expire_minutes=30,
            jwt_refresh_token_expire_days=7,
        )
        service = create_jwt_service_from_config(config)

        user_id = "user123"
        username = "testuser"

        # 1. Create access token
        access_token = service.create_token(
            user_id=user_id,
            username=username,
            token_type="access",
            expires_delta=timedelta(minutes=30),
        )

        # 2. Decode access token
        access_claims = service.decode_token(access_token)
        assert access_claims is not None
        assert access_claims["sub"] == user_id
        assert access_claims["username"] == username
        assert access_claims["token_type"] == "access"

        # 3. Create refresh token
        refresh_token = service.create_token(
            user_id=user_id,
            username=username,
            token_type="refresh",
            expires_delta=timedelta(days=7),
        )

        # 4. Decode refresh token
        refresh_claims = service.decode_token(refresh_token)
        assert refresh_claims is not None
        assert refresh_claims["sub"] == user_id
        assert refresh_claims["username"] == username
        assert refresh_claims["token_type"] == "refresh"

    def test_token_with_additional_metadata(self) -> None:
        """Test token creation and decoding with additional metadata."""
        config = AuthConfig(
            jwt_secret_key="test-secret",
            jwt_algorithm="HS256",
        )
        service = create_jwt_service_from_config(config)

        token = service.create_token(
            user_id="user123",
            username="testuser",
            expires_delta=timedelta(minutes=30),
            additional_claims={
                "iss": "auth-service",
                "scope": "api:read api:write",
                "client_id": "webapp",
            },
        )

        claims = service.decode_token(token)
        assert claims is not None
        assert claims["iss"] == "auth-service"
        assert claims["scope"] == "api:read api:write"
        assert claims["client_id"] == "webapp"

    def test_token_with_jti_for_blacklisting(self) -> None:
        """Test token creation with unique identifier for blacklisting."""
        config = AuthConfig(
            jwt_secret_key="test-secret",
            jwt_algorithm="HS256",
        )
        service = create_jwt_service_from_config(config)

        # Create token with unique identifier
        token = service.create_token(
            user_id="user123",
            username="testuser",
            expires_delta=timedelta(minutes=30),
            additional_claims={
                "jti": "unique-token-id-123",  # JWT ID for blacklisting
            },
        )

        # Verify token initially works
        claims = service.decode_token(token)
        assert claims is not None
        assert claims["jti"] == "unique-token-id-123"

        # In real implementation, you'd check the jti against a blacklist
        # This test demonstrates the structure needed for blacklisting

    def test_different_token_types(self) -> None:
        """Test creating different types of tokens."""
        config = AuthConfig(
            jwt_secret_key="test-secret",
            jwt_algorithm="HS256",
        )
        service = create_jwt_service_from_config(config)

        user_id = "user123"
        username = "testuser"

        # Access token
        access_token = service.create_token(
            user_id=user_id,
            username=username,
            token_type="access",
            expires_delta=timedelta(minutes=15),
        )

        # Refresh token
        refresh_token = service.create_token(
            user_id=user_id,
            username=username,
            token_type="refresh",
            expires_delta=timedelta(days=30),
        )

        # Email verification token
        email_token = service.create_token(
            user_id=user_id,
            username=username,
            token_type="email_verification",
            expires_delta=timedelta(hours=24),
        )

        # Verify all tokens have correct types
        access_claims = service.decode_token(access_token)
        refresh_claims = service.decode_token(refresh_token)
        email_claims = service.decode_token(email_token)

        assert access_claims["token_type"] == "access"
        assert refresh_claims["token_type"] == "refresh"
        assert email_claims["token_type"] == "email_verification"
