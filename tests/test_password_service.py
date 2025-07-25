"""Test password service functionality."""

from __future__ import annotations

from flext_auth.domain.value_objects import FlextHashedPassword, FlextPlainPassword
from flext_auth.services.password_service import FlextPasswordService


class TestPasswordService:
    """Test PasswordService functionality."""

    def test_password_service_creation(self) -> None:
        """Test password service creation."""
        service = FlextPasswordService()
        assert service is not None

    def test_hash_password_success(self) -> None:
        """Test successful password hashing."""
        service = FlextPasswordService()
        plain_password = FlextPlainPassword(value="TestPassword123!")

        result = service.hash_password(plain_password)

        assert result.is_success
        hashed = result.data
        assert isinstance(hashed, FlextHashedPassword)
        assert hashed.value.startswith("$2b$")
        assert len(hashed.value) >= 60  # bcrypt hashes are at least 60 chars

    def test_hash_password_different_results(self) -> None:
        """Test that hashing same password produces different results (due to salt)."""
        service = FlextPasswordService()
        plain_password = FlextPlainPassword(value="TestPassword123!")

        result1 = service.hash_password(plain_password)
        result2 = service.hash_password(plain_password)

        assert result1.is_success
        assert result2.is_success
        assert result1.data.value != result2.data.value  # Different due to salt

    def test_verify_password_success(self) -> None:
        """Test successful password verification."""
        service = FlextPasswordService()
        plain_password = FlextPlainPassword(value="TestPassword123!")

        # Hash password first
        hash_result = service.hash_password(plain_password)
        assert hash_result.is_success
        hashed_password = hash_result.data

        # Verify password
        verify_result = service.verify_password(plain_password, hashed_password)
        assert verify_result.is_success
        assert verify_result.data is True

    def test_verify_password_failure(self) -> None:
        """Test password verification failure."""
        service = FlextPasswordService()
        correct_password = FlextPlainPassword(value="TestPassword123!")
        wrong_password = FlextPlainPassword(value="WrongPassword123!")

        # Hash correct password
        hash_result = service.hash_password(correct_password)
        assert hash_result.is_success
        hashed_password = hash_result.data

        # Verify wrong password
        verify_result = service.verify_password(wrong_password, hashed_password)
        assert verify_result.is_success
        assert verify_result.data is False

    def test_verify_password_invalid_hash_format(self) -> None:
        """Test password verification with invalid hash format."""
        service = FlextPasswordService()
        plain_password = FlextPlainPassword(value="TestPassword123!")
        invalid_hash = FlextHashedPassword(value="invalid-hash-format")

        # Verify password with invalid hash
        verify_result = service.verify_password(plain_password, invalid_hash)
        assert not verify_result.is_success
        assert "Failed to verify password" in verify_result.error

    def test_generate_password_valid(self) -> None:
        """Test password generation produces valid passwords."""
        service = FlextPasswordService()

        generated = service.generate_password()

        assert generated.is_success
        password = generated.data
        assert isinstance(password, FlextPlainPassword)
        assert len(password.value) >= 12  # Default length

        # Validate the generated password meets requirements
        password.validate_domain_rules()  # Should not raise

    def test_generate_password_custom_length(self) -> None:
        """Test password generation with custom length."""
        service = FlextPasswordService()

        generated = service.generate_password(length=16)

        assert generated.is_success
        password = generated.data
        assert len(password.value) == 16

    def test_generate_password_minimum_length(self) -> None:
        """Test password generation with minimum length."""
        service = FlextPasswordService()

        # Test minimum valid length
        generated = service.generate_password(length=8)
        assert generated.is_success
        assert len(generated.data.value) == 8

    def test_generate_password_invalid_length(self) -> None:
        """Test password generation with invalid length."""
        service = FlextPasswordService()

        # Test too short
        generated = service.generate_password(length=7)
        assert not generated.is_success
        assert "Password length must be at least 8" in generated.error

        # Test too long
        generated = service.generate_password(length=129)
        assert not generated.is_success
        assert "Password length must be at most 128" in generated.error

    def test_check_password_strength_strong(self) -> None:
        """Test password strength checking for strong password."""
        service = FlextPasswordService()
        strong_password = FlextPlainPassword(value="StrongP@ssw0rd123!")

        result = service.check_password_strength(strong_password)

        assert result.is_success
        strength = result.data
        assert strength["score"] >= 4  # Strong password
        assert strength["is_strong"] is True
        assert len(strength["feedback"]) == 0  # No negative feedback

    def test_check_password_strength_weak(self) -> None:
        """Test password strength checking for weak password."""
        service = FlextPasswordService()
        weak_password = FlextPlainPassword(value="password")

        result = service.check_password_strength(weak_password)

        assert result.is_success
        strength = result.data
        assert strength["score"] < 3  # Weak password
        assert strength["is_strong"] is False
        assert len(strength["feedback"]) > 0  # Has feedback

    def test_check_password_strength_medium(self) -> None:
        """Test password strength checking for medium password."""
        service = FlextPasswordService()
        medium_password = FlextPlainPassword(value="Password123")

        result = service.check_password_strength(medium_password)

        assert result.is_success
        strength = result.data
        assert strength["score"] >= 2  # Medium password
        assert isinstance(strength["is_strong"], bool)

    def test_hash_multiple_passwords(self) -> None:
        """Test hashing multiple different passwords."""
        service = FlextPasswordService()

        passwords = [
            "TestPassword1!",
            "AnotherPass2@",
            "ThirdPassword3#",
        ]

        hashes = []
        for pwd in passwords:
            plain = FlextPlainPassword(value=pwd)
            result = service.hash_password(plain)
            assert result.is_success
            hashes.append(result.data.value)

        # All hashes should be different
        assert len(set(hashes)) == len(hashes)

        # All hashes should be valid bcrypt format
        for hash_val in hashes:
            assert hash_val.startswith("$2b$")

    def test_verify_multiple_passwords(self) -> None:
        """Test verifying multiple passwords against their hashes."""
        service = FlextPasswordService()

        test_cases = [
            ("TestPassword1!", True),
            ("AnotherPass2@", True),
            ("WrongPassword!", False),
        ]

        # Hash the first password
        correct_password = FlextPlainPassword(value="TestPassword1!")
        hash_result = service.hash_password(correct_password)
        assert hash_result.is_success
        hashed = hash_result.data

        for password_str, expected in test_cases:
            password = FlextPlainPassword(value=password_str)
            result = service.verify_password(password, hashed)
            assert result.is_success

            if expected:
                assert result.data is True
            else:
                assert result.data is False
