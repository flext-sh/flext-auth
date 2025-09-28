"""FlextAuthUtilities - Authentication domain utilities extending FlextUtilities.

This module provides comprehensive authentication utilities with nested classes
for token validation, JWT processing, OAuth helpers, and password utilities.
Uses Pydantic 2.11+ features and Python 3.13+ syntax.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import bcrypt
import jwt
from pydantic import SecretStr

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_core import (
    FlextContainer,
    FlextLogger,
    FlextResult,
    FlextUtilities,
)

__all__ = ["FlextAuthUtilities"]


class FlextAuthUtilities(FlextUtilities):
    """Unified authentication utilities service extending FlextUtilities.

    Provides centralized authentication utilities without duplicating functionality.
    Uses FlextAuthModels and FlextAuthConstants for all domain-specific needs.
    """

    def __init__(self) -> None:
        """Initialize FlextAuthUtilities service."""
        super().__init__()
        self._container = FlextContainer.get_global()
        self._logger = FlextLogger(__name__)

    def execute(self) -> FlextResult[dict[str, Any]]:
        """Execute the main domain service operation.

        Returns:
            FlextResult[dict[str, Any]]: Service status and capabilities.

        """
        return FlextResult[dict[str, Any]].ok({
            "status": "operational",
            "service": "flext-auth-utilities",
            "capabilities": [
                "token_validation",
                "jwt_processing",
                "oauth_helpers",
                "password_utilities",
                "session_management",
                "role_validation",
            ],
        })

    @property
    def logger(self) -> FlextLogger:
        """Get logger instance."""
        return self._logger

    @property
    def container(self) -> FlextContainer:
        """Get container instance."""
        return self._container

    class TokenValidation:
        """Token validation utilities with Pydantic 2.11+ features."""

        @staticmethod
        def validate_jwt_token(
            token: str, secret_key: SecretStr
        ) -> FlextResult[dict[str, Any]]:
            """Validate JWT token using secret key.

            Args:
                token: JWT token to validate
                secret_key: Secret key for validation

            Returns:
                FlextResult containing decoded payload or error

            """
            try:
                decoded_payload: dict[str, Any] = jwt.decode(
                    token,
                    secret_key.get_secret_value(),
                    algorithms=[FlextAuthConstants.Jwt.DEFAULT_ALGORITHM],
                )
                return FlextResult[dict[str, Any]].ok(decoded_payload)
            except jwt.ExpiredSignatureError:
                return FlextResult[dict[str, Any]].fail("Token has expired")
            except jwt.InvalidTokenError as e:
                return FlextResult[dict[str, Any]].fail(f"Invalid token: {e}")
            except Exception as e:
                return FlextResult[dict[str, Any]].fail(f"Token validation failed: {e}")

        @staticmethod
        def validate_bearer_token(authorization_header: str) -> FlextResult[str]:
            """Extract and validate bearer token from authorization header.

            Args:
                authorization_header: Authorization header value

            Returns:
                FlextResult containing token or error

            """
            try:
                if not authorization_header:
                    return FlextResult[str].fail("Authorization header is required")

                if not authorization_header.startswith(
                    FlextAuthConstants.Jwt.BEARER_PREFIX
                ):
                    return FlextResult[str].fail("Invalid authorization header format")

                token = authorization_header[
                    len(FlextAuthConstants.Jwt.BEARER_PREFIX) :
                ]  # Remove Bearer prefix
                if not token:
                    return FlextResult[str].fail("Token is empty")

                return FlextResult[str].ok(token)
            except Exception as e:
                return FlextResult[str].fail(f"Bearer token validation failed: {e}")

        @staticmethod
        def validate_api_key(api_key: str, valid_keys: set[str]) -> FlextResult[bool]:
            """Validate API key against set of valid keys.

            Args:
                api_key: API key to validate
                valid_keys: Set of valid API keys

            Returns:
                FlextResult containing validation result

            """
            try:
                if not api_key:
                    return FlextResult[bool].fail("API key is required")

                is_valid = api_key in valid_keys
                return FlextResult[bool].ok(is_valid)
            except Exception as e:
                return FlextResult[bool].fail(f"API key validation failed: {e}")

        @staticmethod
        def validate_session_token(
            token: str, session_store: dict[str, FlextAuthModels.Session]
        ) -> FlextResult[FlextAuthModels.Session]:
            """Validate session token and return session if valid.

            Args:
                token: Session token to validate
                session_store: Dictionary of active sessions

            Returns:
                FlextResult containing session or error

            """
            try:
                if not token:
                    return FlextResult[FlextAuthModels.Session].fail(
                        "Session token is required"
                    )

                session = session_store.get(token)
                if not session:
                    return FlextResult[FlextAuthModels.Session].fail(
                        "Invalid session token"
                    )

                # Check if session is expired
                if session.expires_at and session.expires_at < datetime.now(UTC):
                    return FlextResult[FlextAuthModels.Session].fail(
                        "Session has expired"
                    )

                return FlextResult[FlextAuthModels.Session].ok(session)
            except Exception as e:
                return FlextResult[FlextAuthModels.Session].fail(
                    f"Session validation failed: {e}"
                )

    class JWTProcessing:
        """JWT processing utilities with advanced features."""

        @staticmethod
        def create_jwt_token(
            payload: dict[str, Any],
            secret_key: SecretStr,
            expires_in_seconds: int = 3600,
        ) -> FlextResult[str]:
            """Create JWT token with expiration.

            Args:
                payload: Token payload
                secret_key: Secret key for signing
                expires_in_seconds: Token expiration time in seconds

            Returns:
                FlextResult containing JWT token or error

            """
            try:
                now = datetime.now(UTC)
                token_payload = {
                    **payload,
                    "iat": int(now.timestamp()),
                    "exp": int(
                        (now + timedelta(seconds=expires_in_seconds)).timestamp()
                    ),
                }

                token = jwt.encode(
                    token_payload,
                    secret_key.get_secret_value(),
                    algorithm=FlextAuthConstants.Jwt.DEFAULT_ALGORITHM,
                )
                return FlextResult[str].ok(token)
            except Exception as e:
                return FlextResult[str].fail(f"JWT creation failed: {e}")

        @staticmethod
        def refresh_jwt_token(
            token: str, secret_key: SecretStr, new_expires_in_seconds: int = 3600
        ) -> FlextResult[str]:
            """Refresh JWT token with new expiration.

            Args:
                token: Original JWT token
                secret_key: Secret key for signing
                new_expires_in_seconds: New expiration time in seconds

            Returns:
                FlextResult containing new JWT token or error

            """
            try:
                # Decode the token without verifying expiration
                decoded_payload = jwt.decode(
                    token,
                    secret_key.get_secret_value(),
                    algorithms=[FlextAuthConstants.Jwt.DEFAULT_ALGORITHM],
                    options={"verify_exp": False},
                )

                # Remove timing claims to regenerate them
                decoded_payload.pop("iat", None)
                decoded_payload.pop("exp", None)

                # Create new token
                return FlextAuthUtilities.JWTProcessing.create_jwt_token(
                    decoded_payload, secret_key, new_expires_in_seconds
                )
            except jwt.InvalidTokenError as e:
                return FlextResult[str].fail(f"Invalid token for refresh: {e}")
            except Exception as e:
                return FlextResult[str].fail(f"Token refresh failed: {e}")

        @staticmethod
        def extract_claims(
            token: str, secret_key: SecretStr
        ) -> FlextResult[dict[str, Any]]:
            """Extract claims from JWT token without full validation.

            Args:
                token: JWT token
                secret_key: Secret key for verification

            Returns:
                FlextResult containing claims or error

            """
            try:
                decoded_payload = jwt.decode(
                    token,
                    secret_key.get_secret_value(),
                    algorithms=[FlextAuthConstants.Jwt.DEFAULT_ALGORITHM],
                    options={
                        "verify_exp": False,
                        "verify_aud": False,
                        "verify_iat": False,
                        "verify_nbf": False,
                    },
                )
                return FlextResult[dict[str, Any]].ok(decoded_payload)
            except jwt.InvalidTokenError as e:
                return FlextResult[dict[str, Any]].fail(f"Invalid token: {e}")
            except Exception as e:
                return FlextResult[dict[str, Any]].fail(
                    f"Claims extraction failed: {e}"
                )

    class OAuthHelpers:
        """OAuth processing utilities."""

        @staticmethod
        def generate_state_parameter() -> FlextResult[str]:
            """Generate secure state parameter for OAuth flow.

            Returns:
                FlextResult containing random state string

            """
            try:
                state = secrets.token_urlsafe(32)
                return FlextResult[str].ok(state)
            except Exception as e:
                return FlextResult[str].fail(f"State generation failed: {e}")

        @staticmethod
        def validate_state_parameter(
            received_state: str, expected_state: str
        ) -> FlextResult[bool]:
            """Validate OAuth state parameter.

            Args:
                received_state: State received from OAuth provider
                expected_state: Expected state value

            Returns:
                FlextResult containing validation result

            """
            try:
                if not received_state or not expected_state:
                    return FlextResult[bool].fail("State parameters cannot be empty")

                # Use constant-time comparison to prevent timing attacks
                is_valid = hmac.compare_digest(received_state, expected_state)
                return FlextResult[bool].ok(is_valid)
            except Exception as e:
                return FlextResult[bool].fail(f"State validation failed: {e}")

        @staticmethod
        def generate_pkce_verifier() -> FlextResult[str]:
            """Generate PKCE code verifier.

            Returns:
                FlextResult containing code verifier

            """
            try:
                verifier = secrets.token_urlsafe(32)
                return FlextResult[str].ok(verifier)
            except Exception as e:
                return FlextResult[str].fail(f"PKCE verifier generation failed: {e}")

        @staticmethod
        def generate_pkce_challenge(verifier: str) -> FlextResult[str]:
            """Generate PKCE code challenge from verifier.

            Args:
                verifier: PKCE code verifier

            Returns:
                FlextResult containing code challenge

            """
            try:
                digest = hashlib.sha256(verifier.encode()).digest()
                challenge = secrets.token_urlsafe(len(digest)).rstrip("=")
                return FlextResult[str].ok(challenge)
            except Exception as e:
                return FlextResult[str].fail(f"PKCE challenge generation failed: {e}")

    class PasswordUtilities:
        """Password processing utilities with secure hashing."""

        SALT_LENGTH: ClassVar[int] = 32
        HASH_ITERATIONS: ClassVar[int] = 100000
        MIN_PASSWORD_LENGTH: ClassVar[int] = 8

        @staticmethod
        def hash_password(
            password: SecretStr, salt: bytes | None = None
        ) -> FlextResult[str]:
            """Hash password using PBKDF2.

            Args:
                password: Password to hash
                salt: Optional salt bytes (generates random if None)

            Returns:
                FlextResult containing hashed password with salt

            """
            try:
                if salt is None:
                    salt = secrets.token_bytes(
                        FlextAuthUtilities.PasswordUtilities.SALT_LENGTH
                    )

                password_hash = hashlib.pbkdf2_hmac(
                    "sha256",
                    password.get_secret_value().encode(),
                    salt,
                    FlextAuthUtilities.PasswordUtilities.HASH_ITERATIONS,
                )

                # Combine salt and hash for storage
                stored_password = salt + password_hash
                return FlextResult[str].ok(stored_password.hex())
            except Exception as e:
                return FlextResult[str].fail(f"Password hashing failed: {e}")

        @staticmethod
        def verify_password(
            password: SecretStr, stored_password_hex: str
        ) -> FlextResult[bool]:
            """Verify password against stored hash.

            Args:
                password: Password to verify
                stored_password_hex: Stored password hash in hex format

            Returns:
                FlextResult containing verification result

            """
            try:
                stored_password = bytes.fromhex(stored_password_hex)
                salt = stored_password[
                    : FlextAuthUtilities.PasswordUtilities.SALT_LENGTH
                ]
                stored_hash = stored_password[
                    FlextAuthUtilities.PasswordUtilities.SALT_LENGTH :
                ]

                password_hash = hashlib.pbkdf2_hmac(
                    "sha256",
                    password.get_secret_value().encode(),
                    salt,
                    FlextAuthUtilities.PasswordUtilities.HASH_ITERATIONS,
                )

                is_valid = hmac.compare_digest(password_hash, stored_hash)
                return FlextResult[bool].ok(is_valid)
            except Exception as e:
                return FlextResult[bool].fail(f"Password verification failed: {e}")

        @staticmethod
        def generate_secure_password(length: int = 16) -> FlextResult[str]:
            """Generate cryptographically secure password.

            Args:
                length: Password length (minimum 8)

            Returns:
                FlextResult containing generated password

            """
            try:
                if length < FlextAuthUtilities.PasswordUtilities.MIN_PASSWORD_LENGTH:
                    return FlextResult[str].fail(
                        f"Password length must be at least {FlextAuthUtilities.PasswordUtilities.MIN_PASSWORD_LENGTH} characters"
                    )

                password = secrets.token_urlsafe(length)[:length]
                return FlextResult[str].ok(password)
            except Exception as e:
                return FlextResult[str].fail(f"Password generation failed: {e}")

        @staticmethod
        def validate_password_strength(
            password: SecretStr,
        ) -> FlextResult[dict[str, bool]]:
            """Validate password strength requirements.

            Args:
                password: Password to validate

            Returns:
                FlextResult containing strength analysis

            """
            try:
                pwd = password.get_secret_value()
                checks = {
                    "min_length": len(pwd)
                    >= FlextAuthUtilities.PasswordUtilities.MIN_PASSWORD_LENGTH,
                    "has_uppercase": any(c.isupper() for c in pwd),
                    "has_lowercase": any(c.islower() for c in pwd),
                    "has_digit": any(c.isdigit() for c in pwd),
                    "has_special": any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd),
                }
                checks["is_strong"] = all(checks.values())
                return FlextResult[dict[str, bool]].ok(checks)
            except Exception as e:
                return FlextResult[dict[str, bool]].fail(
                    f"Password validation failed: {e}"
                )

        @staticmethod
        def hash_password_bcrypt(password: str, rounds: int = 12) -> FlextResult[str]:
            """Hash password using bcrypt.

            Args:
                password: Password to hash
                rounds: Bcrypt rounds (default 12)

            Returns:
                FlextResult containing hashed password

            """
            try:
                salt = bcrypt.gensalt(rounds=rounds)
                hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
                return FlextResult[str].ok(hashed.decode("utf-8"))
            except Exception as e:
                return FlextResult[str].fail(f"Bcrypt password hashing failed: {e}")

        @staticmethod
        def verify_password_bcrypt(
            password: str, hashed_password: str
        ) -> FlextResult[bool]:
            """Verify password against bcrypt hash.

            Args:
                password: Password to verify
                hashed_password: Bcrypt hashed password

            Returns:
                FlextResult containing verification result

            """
            try:
                is_valid = bcrypt.checkpw(
                    password.encode("utf-8"), hashed_password.encode("utf-8")
                )
                return FlextResult[bool].ok(is_valid)
            except Exception as e:
                return FlextResult[bool].fail(
                    f"Bcrypt password verification failed: {e}"
                )

    class SessionManagement:
        """Session management utilities."""

        @staticmethod
        def create_session_token() -> FlextResult[str]:
            """Create secure session token.

            Returns:
                FlextResult containing session token

            """
            try:
                token = secrets.token_urlsafe(32)
                return FlextResult[str].ok(token)
            except Exception as e:
                return FlextResult[str].fail(f"Session token creation failed: {e}")

        @staticmethod
        def create_session(
            user_id: str, expires_in_seconds: int = 86400
        ) -> FlextResult[FlextAuthModels.Session]:
            """Create new session for user.

            Args:
                user_id: User identifier
                expires_in_seconds: Session expiration time in seconds

            Returns:
                FlextResult containing session object

            """
            try:
                token_result = (
                    FlextAuthUtilities.SessionManagement.create_session_token()
                )
                if token_result.is_failure:
                    return FlextResult[FlextAuthModels.Session].fail(
                        token_result.error or "Token creation failed"
                    )

                session_id = f"session_{secrets.token_hex(8)}"
                session = FlextAuthModels.Session(
                    session_id=session_id,
                    session_token=token_result.value,
                    user_id=user_id,
                    expires_at=datetime.now(UTC)
                    + timedelta(seconds=expires_in_seconds),
                    is_active=True,
                    ip_address=None,
                    user_agent=None,
                )
                return FlextResult[FlextAuthModels.Session].ok(session)
            except Exception as e:
                return FlextResult[FlextAuthModels.Session].fail(
                    f"Session creation failed: {e}"
                )

        @staticmethod
        def refresh_session(
            session: FlextAuthModels.Session, extends_by_seconds: int = 86400
        ) -> FlextResult[FlextAuthModels.Session]:
            """Refresh session expiration time.

            Args:
                session: Session to refresh
                extends_by_seconds: Extension time in seconds

            Returns:
                FlextResult containing refreshed session

            """
            try:
                refreshed_session = session.model_copy()
                refreshed_session.expires_at = datetime.now(UTC) + timedelta(
                    seconds=extends_by_seconds
                )
                refreshed_session.last_accessed_at = datetime.now(UTC)
                return FlextResult[FlextAuthModels.Session].ok(refreshed_session)
            except Exception as e:
                return FlextResult[FlextAuthModels.Session].fail(
                    f"Session refresh failed: {e}"
                )

    class RoleValidation:
        """Role and permission validation utilities."""

        @staticmethod
        def validate_user_role(
            user: FlextAuthModels.User, required_role: str
        ) -> FlextResult[bool]:
            """Validate if user has required role.

            Args:
                user: User object
                required_role: Required role name

            Returns:
                FlextResult containing validation result

            """
            try:
                if not user.roles:
                    return FlextResult[bool].ok(False)

                has_role = required_role in user.roles
                return FlextResult[bool].ok(has_role)
            except Exception as e:
                return FlextResult[bool].fail(f"Role validation failed: {e}")

        @staticmethod
        def validate_user_permissions(
            user: FlextAuthModels.User, required_permissions: list[str]
        ) -> FlextResult[bool]:
            """Validate if user has all required permissions.

            Args:
                user: User object
                required_permissions: List of required permissions

            Returns:
                FlextResult containing validation result

            """
            try:
                if not user.roles:
                    return FlextResult[bool].ok(False)

                # For now, we'll implement a simple role-based permission system
                # where REDACTED_LDAP_BIND_PASSWORD role has all permissions and user role has basic permissions
                user_permissions = set()
                for role in user.roles:
                    if role == FlextAuthConstants.Roles.ADMIN:
                        user_permissions.update(
                            required_permissions
                        )  # Admin has all permissions
                    elif role == FlextAuthConstants.Roles.USER:
                        user_permissions.update(
                            FlextAuthConstants.Permissions.BASIC_USER_PERMISSIONS
                        )  # Basic user permissions
                    else:
                        user_permissions.add(role)  # Role name as permission

                has_all_permissions = all(
                    perm in user_permissions for perm in required_permissions
                )
                return FlextResult[bool].ok(has_all_permissions)
            except Exception as e:
                return FlextResult[bool].fail(f"Permission validation failed: {e}")

        @staticmethod
        def get_user_permissions(user: FlextAuthModels.User) -> FlextResult[set[str]]:
            """Get all permissions for user based on roles.

            Args:
                user: User object

            Returns:
                FlextResult containing set of permissions

            """
            try:
                permissions = set()
                if user.roles:
                    for role in user.roles:
                        if role == FlextAuthConstants.Roles.ADMIN:
                            permissions.update(
                                FlextAuthConstants.Permissions.ADMIN_PERMISSIONS
                            )  # Admin permissions
                        elif role == FlextAuthConstants.Roles.USER:
                            permissions.update(
                                FlextAuthConstants.Permissions.BASIC_USER_PERMISSIONS
                            )  # Basic user permissions
                        else:
                            permissions.add(role)  # Role name as permission
                return FlextResult[set[str]].ok(permissions)
            except Exception as e:
                return FlextResult[set[str]].fail(f"Permission extraction failed: {e}")

    async def execute_async(self) -> FlextResult[dict[str, Any]]:
        """Execute utilities service operation asynchronously."""
        return FlextResult[dict[str, Any]].ok({
            "status": "operational",
            "service": "flext-auth-utilities",
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "1.0.0",
        })
