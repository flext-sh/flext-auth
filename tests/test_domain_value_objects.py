"""Test domain value objects following flext-core patterns."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from flext_auth.domain.value_objects import (
    FlextAuthToken,
    FlextHashedPassword,
    FlextIPAddress,
    FlextJWTClaims,
    FlextPlainPassword,
    FlextRefreshToken,
    FlextSecurityContext,
    FlextSessionToken,
    FlextUserAgent,
    FlextUserEmail,
    FlextUsername,
)


class TestUsername:
    """Test Username value object."""

    def test_username_creation(self) -> None:
        """Test username creation."""
        username = FlextUsername(value="testuser")
        if username.value != "testuser":
            raise AssertionError(f"Expected {'testuser'}, got {username.value}")
        assert str(username) == "testuser"

    def test_username_validation(self) -> None:
        """Test username validation rules."""
        valid_username = FlextUsername(value="ValidUser123")
        valid_username.validate_domain_rules()  # Should not raise

        # Test minimum length
        with pytest.raises(ValueError, match="Username must be at least 3 characters"):
            FlextUsername(value="ab").validate_domain_rules()

        # Test maximum length
        with pytest.raises(ValueError, match="Username must be at most 50 characters"):
            FlextUsername(value="a" * 51).validate_domain_rules()

        # Test invalid characters
        with pytest.raises(
            ValueError,
            match="Username can only contain letters, numbers, underscores, and hyphens",
        ):
            FlextUsername(value="user@domain").validate_domain_rules()


class TestUserEmail:
    """Test UserEmail value object."""

    def test_email_creation(self) -> None:
        """Test email creation."""
        email = FlextUserEmail(value="test@example.com")
        if str(email) != "test@example.com":
            raise AssertionError(f"Expected {'test@example.com'}, got {email!s}")

    def test_email_validation(self) -> None:
        """Test email validation rules."""
        valid_email = FlextUserEmail(value="valid@example.com")
        valid_email.validate_domain_rules()  # Should not raise


class TestPlainPassword:
    """Test PlainPassword value object."""

    def test_password_creation(self) -> None:
        """Test password creation."""
        password = FlextPlainPassword(value="StrongP@ssw0rd!")
        if str(password) != "[PROTECTED]":
            raise AssertionError(f"Expected {'[PROTECTED]'}, got {password!s}")
        assert repr(password) == "FlextPlainPassword([PROTECTED])"

    def test_password_validation(self) -> None:
        """Test password validation rules."""
        valid_password = FlextPlainPassword(value="ValidP@ssw0rd123")
        valid_password.validate_domain_rules()  # Should not raise

        # Test minimum length
        with pytest.raises(ValueError, match="Password must be at least 8 characters"):
            FlextPlainPassword(value="Short1!").validate_domain_rules()

        # Test maximum length
        with pytest.raises(ValueError, match="Password must be at most 128 characters"):
            FlextPlainPassword(value="a" * 129).validate_domain_rules()

        # Test missing uppercase
        with pytest.raises(
            ValueError,
            match="Password must contain at least one uppercase letter",
        ):
            FlextPlainPassword(value="lowercase123!").validate_domain_rules()

        # Test missing lowercase
        with pytest.raises(
            ValueError,
            match="Password must contain at least one lowercase letter",
        ):
            FlextPlainPassword(value="UPPERCASE123!").validate_domain_rules()

        # Test missing number
        with pytest.raises(
            ValueError,
            match="Password must contain at least one number",
        ):
            FlextPlainPassword(value="NoNumbers!").validate_domain_rules()

        # Test missing special character
        with pytest.raises(
            ValueError,
            match="Password must contain at least one special character",
        ):
            FlextPlainPassword(value="NoSpecial123").validate_domain_rules()


class TestHashedPassword:
    """Test HashedPassword value object."""

    def test_hashed_password_creation(self) -> None:
        """Test hashed password creation."""
        hash_value = "$2b$12$" + "a" * 50  # Valid bcrypt hash format
        hashed = FlextHashedPassword(value=hash_value)
        if str(hashed) != "[HASHED]":
            raise AssertionError(f"Expected {'[HASHED]'}, got {hashed!s}")
        assert repr(hashed) == "FlextHashedPassword([HASHED])"

    def test_hashed_password_validation(self) -> None:
        """Test hashed password validation rules."""
        valid_hash = "$2b$12$" + "a" * 50
        hashed = FlextHashedPassword(value=valid_hash)
        hashed.validate_domain_rules()  # Should not raise

        # Test invalid length
        with pytest.raises(ValueError, match="Invalid bcrypt hash length"):
            FlextHashedPassword(value="$2b$12$short").validate_domain_rules()

        # Test invalid format
        with pytest.raises(ValueError, match="Invalid bcrypt hash format"):
            FlextHashedPassword(value="invalid" + "a" * 54).validate_domain_rules()


class TestAuthToken:
    """Test AuthToken value object."""

    def test_auth_token_creation(self) -> None:
        """Test auth token creation."""
        token = FlextAuthToken(value="valid_token_123", token_type="Bearer")
        if str(token) != "Bearer valid_token_123":
            raise AssertionError(f"Expected {'Bearer valid_token_123'}, got {token!s}")

    def test_auth_token_validation(self) -> None:
        """Test auth token validation rules."""
        valid_token = FlextAuthToken(value="valid_token_123")
        valid_token.validate_domain_rules()  # Should not raise

        # Test empty value
        with pytest.raises(ValueError, match="Auth token value cannot be empty"):
            FlextAuthToken(value="").validate_domain_rules()

        # Test short token
        with pytest.raises(
            ValueError,
            match="Auth token must be at least 10 characters",
        ):
            FlextAuthToken(value="short").validate_domain_rules()


class TestRefreshToken:
    """Test RefreshToken value object."""

    def test_refresh_token_creation(self) -> None:
        """Test refresh token creation."""
        token = FlextRefreshToken(value="a" * 32)
        if str(token) != "[REFRESH_TOKEN]":
            raise AssertionError(f"Expected {'[REFRESH_TOKEN]'}, got {token!s}")
        assert repr(token) == "FlextRefreshToken([PROTECTED])"

    def test_refresh_token_validation(self) -> None:
        """Test refresh token validation rules."""
        valid_token = FlextRefreshToken(value="a" * 32)
        valid_token.validate_domain_rules()  # Should not raise

        # Test empty value - fails at Pydantic validation level
        with pytest.raises(ValueError, match="String should have at least 1 character"):
            FlextRefreshToken(value="")

        # Test short token
        with pytest.raises(
            ValueError,
            match="Refresh token must be at least 32 characters",
        ):
            FlextRefreshToken(value="short").validate_domain_rules()


class TestSessionToken:
    """Test SessionToken value object."""

    def test_session_token_creation(self) -> None:
        """Test session token creation."""
        token = FlextSessionToken(value="session_token_123")
        if str(token) != "[SESSION_TOKEN]":
            raise AssertionError(f"Expected {'[SESSION_TOKEN]'}, got {token!s}")
        assert repr(token) == "FlextSessionToken([PROTECTED])"

    def test_session_token_validation(self) -> None:
        """Test session token validation rules."""
        valid_token = FlextSessionToken(value="session_token_123")
        valid_token.validate_domain_rules()  # Should not raise

        # Test empty value
        with pytest.raises(ValueError, match="Session token value cannot be empty"):
            FlextSessionToken(value="").validate_domain_rules()

        # Test short token
        with pytest.raises(
            ValueError,
            match="Session token must be at least 16 characters",
        ):
            FlextSessionToken(value="short").validate_domain_rules()


class TestIPAddress:
    """Test IPAddress value object."""

    def test_ipaddress_creation(self) -> None:
        """Test IP address creation."""
        ipaddr = FlextIPAddress(value="192.168.1.1")
        if str(ipaddr) != "192.168.1.1":
            raise AssertionError(f"Expected {'192.168.1.1'}, got {ipaddr!s}")

    def test_ipaddress_validation(self) -> None:
        """Test IP address validation rules."""
        # Valid IPv4
        valid_ipv4 = FlextIPAddress(value="192.168.1.1")
        valid_ipv4.validate_domain_rules()  # Should not raise

        # Valid IPv6
        valid_ipv6 = FlextIPAddress(value="2001:db8::1")
        valid_ipv6.validate_domain_rules()  # Should not raise

        # Invalid IP
        with pytest.raises(ValueError, match="Invalid IP address"):
            FlextIPAddress(value="invalid.ip").validate_domain_rules()


class TestUserAgent:
    """Test UserAgent value object."""

    def test_user_agent_creation(self) -> None:
        """Test user agent creation."""
        ua = FlextUserAgent(value="Mozilla/5.0 (Chrome)")
        if str(ua) != "Mozilla/5.0 (Chrome)":
            raise AssertionError(f"Expected {'Mozilla/5.0 (Chrome)'}, got {ua!s}")

    def test_user_agent_validation(self) -> None:
        """Test user agent validation rules."""
        valid_ua = FlextUserAgent(value="Mozilla/5.0 (Chrome)")
        valid_ua.validate_domain_rules()  # Should not raise

        # Test empty value
        with pytest.raises(ValueError, match="User agent cannot be empty"):
            FlextUserAgent(value="").validate_domain_rules()

        # Test too long
        with pytest.raises(
            ValueError,
            match="User agent must be at most 500 characters",
        ):
            FlextUserAgent(value="a" * 501).validate_domain_rules()

    def test_user_agent_browser_detection(self) -> None:
        """Test browser detection methods."""
        chrome_ua = FlextUserAgent(value="Mozilla/5.0 Chrome/91.0")
        if chrome_ua.get_browser() != "Chrome":
            raise AssertionError(f"Expected {'Chrome'}, got {chrome_ua.get_browser()}")

        firefox_ua = FlextUserAgent(value="Mozilla/5.0 Firefox/89.0")
        if firefox_ua.get_browser() != "Firefox":
            raise AssertionError(
                f"Expected {'Firefox'}, got {firefox_ua.get_browser()}"
            )

        safari_ua = FlextUserAgent(value="Mozilla/5.0 Safari/537.36")
        if safari_ua.get_browser() != "Safari":
            raise AssertionError(f"Expected {'Safari'}, got {safari_ua.get_browser()}")

        edge_ua = FlextUserAgent(value="Mozilla/5.0 Edge/91.0")
        if edge_ua.get_browser() != "Edge":
            raise AssertionError(f"Expected {'Edge'}, got {edge_ua.get_browser()}")

        unknown_ua = FlextUserAgent(value="CustomBrowser/1.0")
        if unknown_ua.get_browser() != "Unknown":
            raise AssertionError(
                f"Expected {'Unknown'}, got {unknown_ua.get_browser()}"
            )

    def test_user_agent_mobile_detection(self) -> None:
        """Test mobile device detection."""
        mobile_ua = FlextUserAgent(value="Mozilla/5.0 Mobile Safari")
        if not (mobile_ua.is_mobile()):
            raise AssertionError(f"Expected True, got {mobile_ua.is_mobile()}")

        desktop_ua = FlextUserAgent(value="Mozilla/5.0 Chrome/91.0")
        if desktop_ua.is_mobile():
            raise AssertionError(f"Expected False, got {desktop_ua.is_mobile()}")


class TestJWTClaims:
    """Test JWTClaims value object."""

    def test_jwt_claims_creation(self) -> None:
        """Test JWT claims creation."""
        claims = FlextJWTClaims(
            sub="user-123",
            username="testuser",
            role="user",
            iat=int(datetime.now(UTC).timestamp()),
            exp=int(datetime.now(UTC).timestamp()) + 3600,
            token_type="access",
        )
        if claims.sub != "user-123":
            raise AssertionError(f"Expected {'user-123'}, got {claims.sub}")
        assert claims.username == "testuser"
        if claims.role != "user":
            raise AssertionError(f"Expected {'user'}, got {claims.role}")
        assert claims.token_type == "access"

    def test_jwt_claims_validation(self) -> None:
        """Test JWT claims validation rules."""
        now = int(datetime.now(UTC).timestamp())
        valid_claims = FlextJWTClaims(
            sub="user-123",
            iat=now,
            exp=now + 3600,
            token_type="access",
        )
        valid_claims.validate_domain_rules()  # Should not raise

        # Test empty subject
        with pytest.raises(ValueError, match="JWT subject \\(sub\\) cannot be empty"):
            FlextJWTClaims(
                sub="",
                iat=now,
                exp=now + 3600,
                token_type="access",
            ).validate_domain_rules()

        # Test invalid expiration
        with pytest.raises(
            ValueError,
            match="JWT expiration must be after issued time",
        ):
            FlextJWTClaims(
                sub="user-123",
                iat=now,
                exp=now - 3600,  # Expired
                token_type="access",
            ).validate_domain_rules()

        # Test invalid token type
        with pytest.raises(
            ValueError,
            match="JWT token type must be 'access' or 'refresh'",
        ):
            FlextJWTClaims(
                sub="user-123",
                iat=now,
                exp=now + 3600,
                token_type="invalid",
            ).validate_domain_rules()


class TestSecurityContext:
    """Test SecurityContext value object."""

    def test_security_context_creation(self) -> None:
        """Test security context creation."""
        context = FlextSecurityContext(
            user_id="user-123",
            username="testuser",
            role="REDACTED_LDAP_BIND_PASSWORD",
            session_id="session-123",
            permissions=["read", "write"],
        )
        if context.user_id != "user-123":
            raise AssertionError(f"Expected {'user-123'}, got {context.user_id}")
        assert context.username == "testuser"
        if context.role != "REDACTED_LDAP_BIND_PASSWORD":
            raise AssertionError(f"Expected {'REDACTED_LDAP_BIND_PASSWORD'}, got {context.role}")
        assert context.session_id == "session-123"
        if context.permissions != ["read", "write"]:
            raise AssertionError(
                f"Expected {['read', 'write']}, got {context.permissions}"
            )

    def test_security_context_validation(self) -> None:
        """Test security context validation rules."""
        valid_context = FlextSecurityContext(
            user_id="user-123",
            username="testuser",
            role="user",
            session_id="session-123",
        )
        valid_context.validate_domain_rules()  # Should not raise

        # Test empty user_id
        with pytest.raises(ValueError, match="User ID cannot be empty"):
            FlextSecurityContext(
                user_id="",
                username="testuser",
                role="user",
                session_id="session-123",
            ).validate_domain_rules()

        # Test invalid role
        with pytest.raises(
            ValueError,
            match="Role must be one of: user, REDACTED_LDAP_BIND_PASSWORD, moderator",
        ):
            FlextSecurityContext(
                user_id="user-123",
                username="testuser",
                role="invalid",
                session_id="session-123",
            ).validate_domain_rules()

    def test_security_context_permissions(self) -> None:
        """Test security context permission methods."""
        context = FlextSecurityContext(
            user_id="user-123",
            username="testuser",
            role="REDACTED_LDAP_BIND_PASSWORD",
            session_id="session-123",
            permissions=["read", "write"],
        )

        if not (context.has_permission("read")):
            raise AssertionError(f"Expected True, got {context.has_permission('read')}")
        if context.has_permission("delete"):
            raise AssertionError(
                f"Expected False, got {context.has_permission('delete')}"
            )
        if not (context.is_REDACTED_LDAP_BIND_PASSWORD()):
            raise AssertionError(f"Expected True, got {context.is_REDACTED_LDAP_BIND_PASSWORD()}")

        user_context = FlextSecurityContext(
            user_id="user-123",
            username="testuser",
            role="user",
            session_id="session-123",
        )
        if user_context.is_REDACTED_LDAP_BIND_PASSWORD():
            raise AssertionError(f"Expected False, got {user_context.is_REDACTED_LDAP_BIND_PASSWORD()}")
