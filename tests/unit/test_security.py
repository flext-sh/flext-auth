"""Tests for security module."""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from datetime import timedelta
from unittest.mock import patch

import pytest

from flext_auth.security import PasswordHasher
from flext_auth.security import SecurityManager
from flext_auth.security import TokenGenerator
from flext_auth.security import generate_secure_token


class TestPasswordHasher:
    """Test PasswordHasher class."""

    @pytest.fixture
    def hasher(self) -> PasswordHasher:
        """Create PasswordHasher instance."""
        return PasswordHasher()

    def test_password_hasher_creation(self, hasher: PasswordHasher) -> None:
        """Test PasswordHasher can be created."""
        assert hasher is not None
        assert hasattr(hasher, "argon2_hasher")

    def test_hash_password(self, hasher: PasswordHasher) -> None:
        """Test password hashing."""
        password = "test_password_123"
        hashed = hasher.hash(password)

        assert isinstance(hashed, str)
        assert hashed != password
        assert len(hashed) > 0
        assert hashed.startswith("$argon2")

    def test_verify_password_correct(self, hasher: PasswordHasher) -> None:
        """Test password verification with correct password."""
        password = "test_password_123"
        hashed = hasher.hash(password)

        assert hasher.verify(password, hashed) is True

    def test_verify_password_incorrect(self, hasher: PasswordHasher) -> None:
        """Test password verification with incorrect password."""
        password = "test_password_123"
        wrong_password = "wrong_password"
        hashed = hasher.hash(password)

        assert hasher.verify(wrong_password, hashed) is False

    def test_verify_password_invalid_hash(self, hasher: PasswordHasher) -> None:
        """Test password verification with invalid hash."""
        password = "test_password_123"
        invalid_hash = "invalid_hash"

        assert hasher.verify(password, invalid_hash) is False

    def test_hash_consistency(self, hasher: PasswordHasher) -> None:
        """Test that same password produces different hashes."""
        password = "test_password_123"
        hash1 = hasher.hash(password)
        hash2 = hasher.hash(password)

        # Should be different due to salt
        assert hash1 != hash2

        # But both should verify correctly
        assert hasher.verify(password, hash1) is True
        assert hasher.verify(password, hash2) is True


class TestTokenGenerator:
    """Test TokenGenerator class."""

    @pytest.fixture
    def generator(self) -> TokenGenerator:
        """Create TokenGenerator instance."""
        return TokenGenerator()

    def test_token_generator_creation(self, generator: TokenGenerator) -> None:
        """Test TokenGenerator can be created."""
        assert generator is not None

    def test_generate_token(self, generator: TokenGenerator) -> None:
        """Test token generation."""
        token = generator.generate(length=32)

        assert isinstance(token, str)
        assert len(token) == 64  # 32 bytes = 64 hex chars

    def test_generate_token_different_lengths(self, generator: TokenGenerator) -> None:
        """Test token generation with different lengths."""
        token16 = generator.generate(length=16)
        token32 = generator.generate(length=32)
        token64 = generator.generate(length=64)

        assert len(token16) == 32  # 16 bytes = 32 hex chars
        assert len(token32) == 64  # 32 bytes = 64 hex chars
        assert len(token64) == 128  # 64 bytes = 128 hex chars

    def test_generate_unique_tokens(self, generator: TokenGenerator) -> None:
        """Test that generated tokens are unique."""
        tokens = [generator.generate() for _ in range(10)]

        # All tokens should be unique
        assert len(set(tokens)) == len(tokens)

    def test_generate_jwt_token(self, generator: TokenGenerator) -> None:
        """Test JWT token generation."""
        payload = {"user_id": "123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        secret = "test_secret"
        algorithm = "HS256"

        token = generator.generate_jwt(payload, secret, algorithm)

        assert isinstance(token, str)
        assert len(token.split(".")) == 3  # JWT has 3 parts

    def test_verify_jwt_token(self, generator: TokenGenerator) -> None:
        """Test JWT token verification."""
        payload = {"user_id": "123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        secret = "test_secret"
        algorithm = "HS256"

        token = generator.generate_jwt(payload, secret, algorithm)
        decoded = generator.verify_jwt(token, secret, algorithm)

        assert decoded["user_id"] == "123"

    def test_verify_jwt_token_invalid(self, generator: TokenGenerator) -> None:
        """Test JWT token verification with invalid token."""
        secret = "test_secret"
        algorithm = "HS256"

        with pytest.raises(Exception):  # JWT verification should raise exception
            generator.verify_jwt("invalid.jwt.token", secret, algorithm)


class TestSecurityManager:
    """Test SecurityManager class."""

    @pytest.fixture
    def security_manager(self) -> SecurityManager:
        """Create SecurityManager instance."""
        return SecurityManager()

    def test_security_manager_creation(self, security_manager: SecurityManager) -> None:
        """Test SecurityManager can be created."""
        assert security_manager is not None
        assert hasattr(security_manager, "password_hasher")
        assert hasattr(security_manager, "token_generator")

    def test_hash_password(self, security_manager: SecurityManager) -> None:
        """Test password hashing through security manager."""
        password = "test_password_123"
        hashed = security_manager.hash_password(password)

        assert isinstance(hashed, str)
        assert hashed != password

    def test_verify_password(self, security_manager: SecurityManager) -> None:
        """Test password verification through security manager."""
        password = "test_password_123"
        hashed = security_manager.hash_password(password)

        assert security_manager.verify_password(password, hashed) is True
        assert security_manager.verify_password("wrong_password", hashed) is False

    def test_generate_token(self, security_manager: SecurityManager) -> None:
        """Test token generation through security manager."""
        token = security_manager.generate_token(length=32)

        assert isinstance(token, str)
        assert len(token) == 64  # 32 bytes = 64 hex chars

    def test_generate_jwt(self, security_manager: SecurityManager) -> None:
        """Test JWT generation through security manager."""
        payload = {"user_id": "123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        secret = "test_secret"

        token = security_manager.generate_jwt(payload, secret)

        assert isinstance(token, str)
        assert len(token.split(".")) == 3

    def test_verify_jwt(self, security_manager: SecurityManager) -> None:
        """Test JWT verification through security manager."""
        payload = {"user_id": "123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        secret = "test_secret"

        token = security_manager.generate_jwt(payload, secret)
        decoded = security_manager.verify_jwt(token, secret)

        assert decoded["user_id"] == "123"


class TestSecureTokenGeneration:
    """Test secure token generation function."""

    def test_generate_secure_token(self) -> None:
        """Test standalone secure token generation."""
        token = generate_secure_token()

        assert isinstance(token, str)
        assert len(token) == 64  # Default 32 bytes = 64 hex chars

    def test_generate_secure_token_custom_length(self) -> None:
        """Test secure token generation with custom length."""
        token = generate_secure_token(length=16)

        assert isinstance(token, str)
        assert len(token) == 32  # 16 bytes = 32 hex chars

    def test_generate_secure_token_uniqueness(self) -> None:
        """Test that secure tokens are unique."""
        tokens = [generate_secure_token() for _ in range(10)]

        # All tokens should be unique
        assert len(set(tokens)) == len(tokens)


class TestSecurityProtocols:
    """Test security protocols and interfaces."""

    def test_hashing_protocol_exists(self) -> None:
        """Test that HashingProtocol can be imported."""
        from flext_auth.security import HashingProtocol

        assert HashingProtocol is not None

    def test_password_hasher_implements_protocol(self) -> None:
        """Test that PasswordHasher implements HashingProtocol."""
        from flext_auth.security import HashingProtocol

        hasher = PasswordHasher()
        assert isinstance(hasher, HashingProtocol)

    def test_security_types_exist(self) -> None:
        """Test that security types are defined."""
        from flext_auth.security import Hash
        from flext_auth.security import Salt
        from flext_auth.security import Token

        # These should be type aliases
        assert Hash is not None
        assert Salt is not None
        assert Token is not None
