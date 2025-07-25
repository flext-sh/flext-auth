"""Test domain value objects following flext-core patterns."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from flext_auth.domain.value_objects import (
    AuthToken,
    HashedPassword,
    IPAddress,
    JWTClaims,
    PlainPassword,
    RefreshToken,
    SecurityContext,
    SessionToken,
    UserAgent,
    UserEmail,
    Username,
)


class TestUsername:
    """Test Username value object."""

    def test_username_creation(self) -> None:
        """Test username creation."""
        username = Username(value="testuser")
        assert username.value == "testuser"
        assert str(username) == "testuser"

    def test_username_validation(self) -> None:
        """Test username validation rules."""
        valid_username = Username(value="ValidUser123")
        valid_username.validate_domain_rules()  # Should not raise

        # Test minimum length
        with pytest.raises(ValueError, match="Username must be at least 3 characters"):
            Username(value="ab").validate_domain_rules()

        # Test maximum length
        with pytest.raises(ValueError, match="Username must be at most 50 characters"):
            Username(value="a" * 51).validate_domain_rules()

        # Test invalid characters
        with pytest.raises(
            ValueError,
            match="Username can only contain letters, numbers, underscores, and hyphens",
        ):
            Username(value="user@domain").validate_domain_rules()


class TestUserEmail:
    """Test UserEmail value object."""

    def test_email_creation(self) -> None:
        """Test email creation."""
        email = UserEmail(value="test@example.com")
        assert str(email) == "test@example.com"

    def test_email_validation(self) -> None:
        """Test email validation rules."""
        valid_email = UserEmail(value="valid@example.com")
        valid_email.validate_domain_rules()  # Should not raise


class TestPlainPassword:
    """Test PlainPassword value object."""

    def test_password_creation(self) -> None:
        """Test password creation."""
        password = PlainPassword(value="StrongP@ssw0rd!")
        assert str(password) == "[PROTECTED]"
        assert repr(password) == "PlainPassword([PROTECTED])"

    def test_password_validation(self) -> None:
        """Test password validation rules."""
        valid_password = PlainPassword(value="ValidP@ssw0rd123")
        valid_password.validate_domain_rules()  # Should not raise

        # Test minimum length
        with pytest.raises(ValueError, match="Password must be at least 8 characters"):
            PlainPassword(value="Short1!").validate_domain_rules()

        # Test maximum length
        with pytest.raises(ValueError, match="Password must be at most 128 characters"):
            PlainPassword(value="a" * 129).validate_domain_rules()

        # Test missing uppercase
        with pytest.raises(
            ValueError,
            match="Password must contain at least one uppercase letter",
        ):
            PlainPassword(value="lowercase123!").validate_domain_rules()

        # Test missing lowercase
        with pytest.raises(
            ValueError,
            match="Password must contain at least one lowercase letter",
        ):
            PlainPassword(value="UPPERCASE123!").validate_domain_rules()

        # Test missing number
        with pytest.raises(
            ValueError,
            match="Password must contain at least one number",
        ):
            PlainPassword(value="NoNumbers!").validate_domain_rules()

        # Test missing special character
        with pytest.raises(
            ValueError,
            match="Password must contain at least one special character",
        ):
            PlainPassword(value="NoSpecial123").validate_domain_rules()


class TestHashedPassword:
    """Test HashedPassword value object."""

    def test_hashed_password_creation(self) -> None:
        """Test hashed password creation."""
        hash_value = "$2b$12$" + "a" * 50  # Valid bcrypt hash format
        hashed = HashedPassword(value=hash_value)
        assert str(hashed) == "[HASHED]"
        assert repr(hashed) == "HashedPassword([HASHED])"

    def test_hashed_password_validation(self) -> None:
        """Test hashed password validation rules."""
        valid_hash = "$2b$12$" + "a" * 50
        hashed = HashedPassword(value=valid_hash)
        hashed.validate_domain_rules()  # Should not raise

        # Test invalid length
        with pytest.raises(ValueError, match="Invalid bcrypt hash length"):
            HashedPassword(value="$2b$12$short").validate_domain_rules()

        # Test invalid format
        with pytest.raises(ValueError, match="Invalid bcrypt hash format"):
            HashedPassword(value="invalid" + "a" * 54).validate_domain_rules()


class TestAuthToken:
    """Test AuthToken value object."""

    def test_auth_token_creation(self) -> None:
        """Test auth token creation."""
        token = AuthToken(value="valid_token_123", token_type="Bearer")
        assert str(token) == "Bearer valid_token_123"

    def test_auth_token_validation(self) -> None:
        """Test auth token validation rules."""
        valid_token = AuthToken(value="valid_token_123")
        valid_token.validate_domain_rules()  # Should not raise

        # Test empty value
        with pytest.raises(ValueError, match="Auth token value cannot be empty"):
            AuthToken(value="").validate_domain_rules()

        # Test short token
        with pytest.raises(
            ValueError,
            match="Auth token must be at least 10 characters",
        ):
            AuthToken(value="short").validate_domain_rules()


class TestRefreshToken:
    """Test RefreshToken value object."""

    def test_refresh_token_creation(self) -> None:
        """Test refresh token creation."""
        token = RefreshToken(value="a" * 32)
        assert str(token) == "[REFRESH_TOKEN]"
        assert repr(token) == "RefreshToken([PROTECTED])"

    def test_refresh_token_validation(self) -> None:
        """Test refresh token validation rules."""
        valid_token = RefreshToken(value="a" * 32)
        valid_token.validate_domain_rules()  # Should not raise

        # Test empty value - fails at Pydantic validation level
        with pytest.raises(ValueError, match="String should have at least 1 character"):
            RefreshToken(value="")

        # Test short token
        with pytest.raises(
            ValueError,
            match="Refresh token must be at least 32 characters",
        ):
            RefreshToken(value="short").validate_domain_rules()


class TestSessionToken:
    """Test SessionToken value object."""

    def test_session_token_creation(self) -> None:
        """Test session token creation."""
        token = SessionToken(value="session_token_123")
        assert str(token) == "[SESSION_TOKEN]"
        assert repr(token) == "SessionToken([PROTECTED])"

    def test_session_token_validation(self) -> None:
        """Test session token validation rules."""
        valid_token = SessionToken(value="session_token_123")
        valid_token.validate_domain_rules()  # Should not raise

        # Test empty value
        with pytest.raises(ValueError, match="Session token value cannot be empty"):
            SessionToken(value="").validate_domain_rules()

        # Test short token
        with pytest.raises(
            ValueError,
            match="Session token must be at least 16 characters",
        ):
            SessionToken(value="short").validate_domain_rules()


class TestIPAddress:
    """Test IPAddress value object."""

    def test_ipaddress_creation(self) -> None:
        """Test IP address creation."""
        ipaddr = IPAddress(value="192.168.1.1")
        assert str(ipaddr) == "192.168.1.1"

    def test_ipaddress_validation(self) -> None:
        """Test IP address validation rules."""
        # Valid IPv4
        valid_ipv4 = IPAddress(value="192.168.1.1")
        valid_ipv4.validate_domain_rules()  # Should not raise

        # Valid IPv6
        valid_ipv6 = IPAddress(value="2001:db8::1")
        valid_ipv6.validate_domain_rules()  # Should not raise

        # Invalid IP
        with pytest.raises(ValueError, match="Invalid IP address"):
            IPAddress(value="invalid.ip").validate_domain_rules()


class TestUserAgent:
    """Test UserAgent value object."""

    def test_user_agent_creation(self) -> None:
        """Test user agent creation."""
        ua = UserAgent(value="Mozilla/5.0 (Chrome)")
        assert str(ua) == "Mozilla/5.0 (Chrome)"

    def test_user_agent_validation(self) -> None:
        """Test user agent validation rules."""
        valid_ua = UserAgent(value="Mozilla/5.0 (Chrome)")
        valid_ua.validate_domain_rules()  # Should not raise

        # Test empty value
        with pytest.raises(ValueError, match="User agent cannot be empty"):
            UserAgent(value="").validate_domain_rules()

        # Test too long
        with pytest.raises(
            ValueError,
            match="User agent must be at most 500 characters",
        ):
            UserAgent(value="a" * 501).validate_domain_rules()

    def test_user_agent_browser_detection(self) -> None:
        """Test browser detection methods."""
        chrome_ua = UserAgent(value="Mozilla/5.0 Chrome/91.0")
        assert chrome_ua.get_browser() == "Chrome"

        firefox_ua = UserAgent(value="Mozilla/5.0 Firefox/89.0")
        assert firefox_ua.get_browser() == "Firefox"

        safari_ua = UserAgent(value="Mozilla/5.0 Safari/537.36")
        assert safari_ua.get_browser() == "Safari"

        edge_ua = UserAgent(value="Mozilla/5.0 Edge/91.0")
        assert edge_ua.get_browser() == "Edge"

        unknown_ua = UserAgent(value="CustomBrowser/1.0")
        assert unknown_ua.get_browser() == "Unknown"

    def test_user_agent_mobile_detection(self) -> None:
        """Test mobile device detection."""
        mobile_ua = UserAgent(value="Mozilla/5.0 Mobile Safari")
        assert mobile_ua.is_mobile() is True

        desktop_ua = UserAgent(value="Mozilla/5.0 Chrome/91.0")
        assert desktop_ua.is_mobile() is False


class TestJWTClaims:
    """Test JWTClaims value object."""

    def test_jwt_claims_creation(self) -> None:
        """Test JWT claims creation."""
        claims = JWTClaims(
            sub="user-123",
            username="testuser",
            role="user",
            iat=int(datetime.now(UTC).timestamp()),
            exp=int(datetime.now(UTC).timestamp()) + 3600,
            token_type="access",
        )
        assert claims.sub == "user-123"
        assert claims.username == "testuser"
        assert claims.role == "user"
        assert claims.token_type == "access"

    def test_jwt_claims_validation(self) -> None:
        """Test JWT claims validation rules."""
        now = int(datetime.now(UTC).timestamp())
        valid_claims = JWTClaims(
            sub="user-123",
            iat=now,
            exp=now + 3600,
            token_type="access",
        )
        valid_claims.validate_domain_rules()  # Should not raise

        # Test empty subject
        with pytest.raises(ValueError, match="JWT subject \\(sub\\) cannot be empty"):
            JWTClaims(
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
            JWTClaims(
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
            JWTClaims(
                sub="user-123",
                iat=now,
                exp=now + 3600,
                token_type="invalid",
            ).validate_domain_rules()


class TestSecurityContext:
    """Test SecurityContext value object."""

    def test_security_context_creation(self) -> None:
        """Test security context creation."""
        context = SecurityContext(
            user_id="user-123",
            username="testuser",
            role="REDACTED_LDAP_BIND_PASSWORD",
            session_id="session-123",
            permissions=["read", "write"],
        )
        assert context.user_id == "user-123"
        assert context.username == "testuser"
        assert context.role == "REDACTED_LDAP_BIND_PASSWORD"
        assert context.session_id == "session-123"
        assert context.permissions == ["read", "write"]

    def test_security_context_validation(self) -> None:
        """Test security context validation rules."""
        valid_context = SecurityContext(
            user_id="user-123",
            username="testuser",
            role="user",
            session_id="session-123",
        )
        valid_context.validate_domain_rules()  # Should not raise

        # Test empty user_id
        with pytest.raises(ValueError, match="User ID cannot be empty"):
            SecurityContext(
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
            SecurityContext(
                user_id="user-123",
                username="testuser",
                role="invalid",
                session_id="session-123",
            ).validate_domain_rules()

    def test_security_context_permissions(self) -> None:
        """Test security context permission methods."""
        context = SecurityContext(
            user_id="user-123",
            username="testuser",
            role="REDACTED_LDAP_BIND_PASSWORD",
            session_id="session-123",
            permissions=["read", "write"],
        )

        assert context.has_permission("read") is True
        assert context.has_permission("delete") is False
        assert context.is_REDACTED_LDAP_BIND_PASSWORD() is True

        user_context = SecurityContext(
            user_id="user-123",
            username="testuser",
            role="user",
            session_id="session-123",
        )
        assert user_context.is_REDACTED_LDAP_BIND_PASSWORD() is False
