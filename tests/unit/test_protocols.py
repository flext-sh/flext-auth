"""Tests for FlextAuthProtocols.

Tests the authentication protocols module following FLEXT standards.
"""

from __future__ import annotations

from flext_auth.protocols import FlextAuthProtocols


class TestFlextAuthProtocols:
    """Test FlextAuthProtocols class and its nested protocol classes."""

    def test_inherits_from_flext_protocols(self) -> None:
        """Test that FlextAuthProtocols inherits from FlextProtocols."""
        from flext_core import FlextProtocols

        assert issubclass(FlextAuthProtocols, FlextProtocols)

    def test_foundation_re_exports(self) -> None:
        """Test that foundation protocols are properly re-exported."""
        assert FlextAuthProtocols.Foundation is not None
        assert FlextAuthProtocols.Domain is not None
        assert FlextAuthProtocols.Application is not None
        assert FlextAuthProtocols.Infrastructure is not None
        assert FlextAuthProtocols.Extensions is not None
        assert FlextAuthProtocols.Commands is not None

    def test_user_protocol_definition(self) -> None:
        """Test UserProtocol definition."""
        protocol = FlextAuthProtocols.Auth.UserProtocol

        # Check protocol has required attributes
        assert hasattr(protocol, "__protocol__")
        assert hasattr(protocol, "__annotations__")

        # Check required methods are defined
        assert "verify_password" in protocol.__annotations__
        assert "set_password" in protocol.__annotations__
        assert "can_login" in protocol.__annotations__
        assert "is_locked" in protocol.__annotations__

    def test_session_protocol_definition(self) -> None:
        """Test SessionProtocol definition."""
        protocol = FlextAuthProtocols.Auth.SessionProtocol

        # Check protocol has required attributes
        assert hasattr(protocol, "__protocol__")
        assert hasattr(protocol, "__annotations__")

        # Check required methods are defined
        assert "is_expired" in protocol.__annotations__
        assert "extend_session" in protocol.__annotations__
        assert "is_valid" in protocol.__annotations__
        assert "revoke" in protocol.__annotations__

    def test_token_protocol_definition(self) -> None:
        """Test TokenProtocol definition."""
        protocol = FlextAuthProtocols.Auth.TokenProtocol

        # Check protocol has required attributes
        assert hasattr(protocol, "__protocol__")
        assert hasattr(protocol, "__annotations__")

        # Check required attributes and methods
        assert "token" in protocol.__annotations__
        assert "user_id" in protocol.__annotations__
        assert "expires_at" in protocol.__annotations__
        assert "is_revoked" in protocol.__annotations__
        assert "is_expired" in protocol.__annotations__

    def test_service_protocol_definition(self) -> None:
        """Test ServiceProtocol definition."""
        protocol = FlextAuthProtocols.Auth.ServiceProtocol

        # Check protocol has required attributes
        assert hasattr(protocol, "__protocol__")
        assert hasattr(protocol, "__annotations__")

        # Check required methods are defined
        assert "register_user" in protocol.__annotations__
        assert "authenticate_user" in protocol.__annotations__
        assert "logout_user" in protocol.__annotations__

    def test_backward_compatibility_aliases(self) -> None:
        """Test backward compatibility aliases exist."""
        assert (
            FlextAuthProtocols.FlextAuthUserProtocol
            is FlextAuthProtocols.Auth.UserProtocol
        )
        assert (
            FlextAuthProtocols.FlextAuthSessionProtocol
            is FlextAuthProtocols.Auth.SessionProtocol
        )
        assert (
            FlextAuthProtocols.FlextAuthTokenProtocol
            is FlextAuthProtocols.Auth.TokenProtocol
        )
        assert (
            FlextAuthProtocols.FlextAuthServiceProtocol
            is FlextAuthProtocols.Auth.ServiceProtocol
        )
