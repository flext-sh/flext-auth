"""Test password service functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth.domain.value_objects import FlextHashedPassword, FlextPlainPassword
from flext_auth.services.password_service import FlextPasswordService

# Constants
EXPECTED_TOTAL_PAGES = 8


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

        assert result.success
        hashed = result.data
        assert isinstance(hashed, FlextHashedPassword)
        assert hashed.value.startswith("$2b$")
        if len(hashed.value) < 60:  # bcrypt hashes are at least 60 chars
            msg: str = f"Expected {len(hashed.value)} >= 60"
            raise AssertionError(msg)

    def test_hash_password_different_results(self) -> None:
        """Test that hashing same password produces different results (due to salt)."""
        service = FlextPasswordService()
        plain_password = FlextPlainPassword(value="TestPassword123!")

        result1 = service.hash_password(plain_password)
        result2 = service.hash_password(plain_password)

        assert result1.success
        assert result2.success
        assert result1.data.value != result2.data.value  # Different due to salt

    def test_verify_password_success(self) -> None:
        """Test successful password verification."""
        service = FlextPasswordService()
        plain_password = FlextPlainPassword(value="TestPassword123!")

        # Hash password first
        hash_result = service.hash_password(plain_password)
        assert hash_result.success
        hashed_password = hash_result.data

        # Verify password
        verify_result = service.verify_password(plain_password, hashed_password)
        assert verify_result.success
        if not verify_result.data:
            msg: str = f"Expected True, got {verify_result.data}"
            raise AssertionError(msg)

    def test_verify_password_failure(self) -> None:
        """Test password verification failure."""
        service = FlextPasswordService()
        correct_password = FlextPlainPassword(value="TestPassword123!")
        wrong_password = FlextPlainPassword(value="WrongPassword123!")

        # Hash correct password
        hash_result = service.hash_password(correct_password)
        assert hash_result.success
        hashed_password = hash_result.data

        # Verify wrong password
        verify_result = service.verify_password(wrong_password, hashed_password)
        assert verify_result.success
        if verify_result.data:
            msg: str = f"Expected False, got {verify_result.data}"
            raise AssertionError(msg)

    def test_verify_password_invalid_hash_format(self) -> None:
        """Test password verification with invalid hash format."""
        service = FlextPasswordService()
        plain_password = FlextPlainPassword(value="TestPassword123!")
        invalid_hash = "invalid-hash-format"  # Use string directly to bypass validation

        # Verify password with invalid hash
        verify_result = service.verify_password(plain_password, invalid_hash)
        assert not verify_result.success
        if "Failed to verify password" not in verify_result.error:
            msg: str = f"Expected 'Failed to verify password' in {verify_result.error}"
            raise AssertionError(msg)

    def test_generate_secure_password_valid(self) -> None:
        """Test password generation produces valid passwords."""
        service = FlextPasswordService()

        generated = service.generate_secure_password()

        assert generated.success
        password = generated.data
        assert isinstance(password, FlextPlainPassword)
        if len(password.value) < 12:  # Default length
            msg: str = f"Expected {len(password.value)} >= 12"
            raise AssertionError(msg)

        # Validate the generated password meets requirements
        password.validate_domain_rules()  # Should not raise

    def test_generate_secure_password_custom_length(self) -> None:
        """Test password generation with custom length."""
        service = FlextPasswordService()

        generated = service.generate_secure_password(length=16)

        assert generated.success
        password = generated.data
        if len(password.value) != 16:
            msg: str = f"Expected 16, got {len(password.value)}"
            raise AssertionError(msg)

    def test_generate_secure_password_minimum_length(self) -> None:
        """Test password generation with minimum length."""
        service = FlextPasswordService()

        # Test minimum valid length
        generated = service.generate_secure_password(length=8)
        assert generated.success
        if len(generated.data.value) != 8:
            msg: str = f"Expected 8, got {len(generated.data.value)}"
            raise AssertionError(msg)

        # Test too short
        generated = service.generate_secure_password(length=7)
        assert not generated.success
        if "Password length must be at least 8" not in generated.error:
            msg: str = (
                f"Expected 'Password length must be at least 8' in {generated.error}"
            )
            raise AssertionError(msg)

        # Test too long
        generated = service.generate_secure_password(length=129)
        assert not generated.success
        if "Password length must be at most 128" not in generated.error:
            msg: str = (
                f"Expected 'Password length must be at most 128' in {generated.error}"
            )
            raise AssertionError(msg)

    def test_check_password_strength_strong(self) -> None:
        """Test password strength checking for strong password."""
        service = FlextPasswordService()
        # Use a truly strong password without common patterns
        strong_password = FlextPlainPassword(value="MyV3ryStr0ngP@ssw0rd!")

        result = service.check_password_strength(strong_password)

        assert result.success
        strength = result.data
        if strength["score"] < 6:  # Strong password (STRONG_STRENGTH_SCORE = 6)
            msg: str = f"Expected {strength['score']} >= 6"
            raise AssertionError(msg)
        if not strength["is_strong"]:
            msg: str = f"Expected True, got {strength['is_strong']}"
            raise AssertionError(msg)
        # Strong passwords should have positive feedback, not zero feedback
        assert (
            len(strength["feedback"]) > 0
        )  # Will have positive feedback like "Good password strength"

    def test_check_password_strength_weak(self) -> None:
        """Test password strength checking for weak password."""
        service = FlextPasswordService()
        # Use a truly weak password (string interface to bypass domain validation)
        # that should get low strength score (short + no variety)
        weak_password_str = "weak"  # Very weak: only 4 chars, no variety

        result = service.check_password_strength(weak_password_str)

        assert result.success
        strength = result.data
        assert strength["score"] < 3  # Weak password
        if strength["is_strong"]:
            msg: str = f"Expected False, got {strength['is_strong']}"
            raise AssertionError(msg)
        assert len(strength["feedback"]) > 0  # Has feedback

    def test_check_password_strength_medium(self) -> None:
        """Test password strength checking for medium password."""
        service = FlextPasswordService()
        medium_password = FlextPlainPassword(value="MediumPass123!")

        result = service.check_password_strength(medium_password)

        assert result.success
        strength = result.data
        if strength["score"] < 2:  # Medium password
            msg: str = f"Expected {strength['score']} >= 2"
            raise AssertionError(msg)
        assert isinstance(strength["is_strong"], bool)

    def test_hash_multiple_passwords(self) -> None:
        """Test hashing multiple passwords."""
        service = FlextPasswordService()
        passwords = [
            FlextPlainPassword(value="Password1!"),
            FlextPlainPassword(value="Password2!"),
            FlextPlainPassword(value="Password3!"),
        ]

        results = []
        for password in passwords:
            result = service.hash_password(password)
            assert result.success
            results.append(result.data)

        # All hashes should be different
        hash_values = [r.value for r in results]
        assert len(set(hash_values)) == len(hash_values)

        # All hashes should be valid bcrypt hashes
        for hash_value in hash_values:
            assert hash_value.startswith("$2b$")
            assert len(hash_value) >= 60

        # Verify all passwords
        for i, password in enumerate(passwords):
            verify_result = service.verify_password(password, results[i])
            assert verify_result.success
            if not verify_result.data:
                msg: str = f"Expected True, got {verify_result.data}"
                raise AssertionError(msg)

        # Verify wrong passwords
        for i, _password in enumerate(passwords):
            wrong_password = FlextPlainPassword(value="WrongPassword123!")
            verify_result = service.verify_password(wrong_password, results[i])
            assert verify_result.success
            if verify_result.data:
                msg: str = f"Expected False, got {verify_result.data}"
                raise AssertionError(msg)
