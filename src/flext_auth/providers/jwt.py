"""FLEXT Auth JWT Provider - JWT-based authentication provider.

This module implements JWT (JSON Web Token) authentication following the
base provider protocol. It provides token generation, validation, and refresh
capabilities using PyJWT.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt

from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import BaseAuthProvider, BaseAuthProviderMixin
from flext_auth.utilities import FlextAuthUtilities
from flext_core import FlextBus, FlextContext, FlextLogger, FlextResult, FlextTypes


class JwtAuthProvider(BaseAuthProvider, BaseAuthProviderMixin):
    """JWT-based authentication provider.

    Implements authentication using JSON Web Tokens (JWT) with bcrypt password
    hashing. Supports token generation, validation, and refresh operations.

    Features:
        - Secure JWT token generation with configurable expiration
        - Password hashing using bcrypt (12 rounds production default)
        - Token validation with signature verification
        - Token refresh support
        - Configurable algorithms (HS256, HS512, etc.)

    Configuration:
        - secret_key: Secret key for JWT signing
        - algorithm: JWT algorithm (default: HS256)
        - access_token_expiry_minutes: Access token lifetime (default: 30)
        - refresh_token_expiry_days: Refresh token lifetime (default: 7)
        - bcrypt_rounds: Password hashing rounds (default: 12)
        - issuer: Token issuer identifier (optional)
        - audience: Token audience identifier (optional)

    Example:
        >>> config = {
        ...     "secret_key": "your-secret-key",
        ...     "algorithm": "HS256",
        ...     "access_token_expiry_minutes": 30,
        ... }
        >>> provider = JwtAuthProvider(config)
        >>> result = provider.authenticate({
        ...     "username": "user",
        ...     "password": "password",
        ...     "user_id": "user-123",
        ... })

    """

    def __init__(self, config: FlextAuthConfig) -> None:
        """Initialize JWT authentication provider.

        Args:
            config: Provider configuration with JWT settings

        Required config keys:
            - secret_key: str - Secret key for signing

        Optional config keys:
            - algorithm: str - JWT algorithm (default: HS256)
            - access_token_expiry_minutes: int - Access token lifetime (default: 30)
            - refresh_token_expiry_days: int - Refresh token lifetime (default: 7)
            - bcrypt_rounds: int - Password hashing rounds (default: 12)
            - issuer: str - Token issuer
            - audience: str - Token audience

        """
        self._config = config
        self._logger = FlextLogger(__name__)
        self._context = FlextContext()
        self._bus = FlextBus()

        # Extract configuration with defaults
        self._secret_key = self._config.get("secret_key")
        if not self._secret_key:
            error_msg = "JWT provider requires 'secret_key' in configuration"
            raise ValueError(error_msg)

        self._algorithm = self._config.get(
            "algorithm", FlextAuthConstants.Jwt.DEFAULT_ALGORITHM
        )
        self._access_token_expiry_minutes = self._config.get(
            "access_token_expiry_minutes", 30
        )
        self._refresh_token_expiry_days = self._config.get(
            "refresh_token_expiry_days", 7
        )
        self._bcrypt_rounds = self._config.get(
            "bcrypt_rounds", FlextAuthConstants.Credentials.Password.BCRYPT_ROUNDS
        )
        self._issuer = self._config.get("issuer")
        self._audience = self._config.get("audience")

        self._logger.info(
            "JWT provider initialized",
            extra={
                "algorithm": self._algorithm,
                "access_expiry_minutes": self._access_token_expiry_minutes,
                "refresh_expiry_days": self._refresh_token_expiry_days,
            },
        )

    def authenticate(
        self,
        credentials: FlextTypes.Dict,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate user and generate JWT token.

        Args:
            credentials: Dictionary containing:
                - username: str (required for logging/tracking)
                - password: str (required if password_hash not provided)
                - password_hash: str (optional, for pre-hashed passwords)
                - user_id: str (required)
                - email: str (optional)
                - roles: FlextTypes.StringList (optional)
                - additional claims: object additional JWT claims

        Returns:
            FlextResult[AuthToken]: JWT token or authentication error

        Example:
            >>> result = provider.authenticate({
            ...     "username": "john_doe",
            ...     "password": "secure_password",
            ...     "user_id": "user-123",
            ...     "email": "john@example.com",
            ...     "roles": ["user", "REDACTED_LDAP_BIND_PASSWORD"],
            ... })

        """
        # Validate required fields
        validation_result = self._validate_credentials_dict(
            credentials, ["username", "user_id"]
        )
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation_result.error)

        # Password verification if password provided
        if "password" in credentials and "password_hash" in credentials:
            password_result = FlextAuthUtilities.PasswordProcessing.verify_password(
                credentials["password"], credentials["password_hash"]
            )
            if password_result.is_failure:
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    f"Password verification failed: {password_result.error}"
                )

            if not password_result.unwrap():
                self._logger.warning(
                    "Authentication failed: invalid password",
                    extra={"username": credentials.get("username")},
                )
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    "Invalid credentials"
                )

        # Generate access token
        access_token_result = self._generate_access_token(credentials)
        if access_token_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                f"Token generation failed: {access_token_result.error}"
            )

        # Generate refresh token
        refresh_token_result = self._generate_refresh_token(credentials)
        if refresh_token_result.is_failure:
            self._logger.warning(
                f"Refresh token generation failed: {refresh_token_result.error}"
            )
            # Continue with access token only
            refresh_token = None
            refresh_expires_at = None
        else:
            refresh_token_data = refresh_token_result.unwrap()
            refresh_token = refresh_token_data["token"]
            refresh_expires_at = refresh_token_data["expires_at"]

        access_token_data = access_token_result.unwrap()

        # Create AuthToken model
        # AuthToken uses 'token' field, not 'access_token'
        auth_token = FlextAuthModels.AuthToken(
            token=access_token_data["token"],
            token_type=FlextAuthConstants.Jwt.DEFAULT_TOKEN_TYPE,
            expires_at=access_token_data["expires_at"],
            refresh_token=refresh_token,
            refresh_expires_at=refresh_expires_at,
            user_id=credentials["user_id"],
            username=credentials.get("username"),
            email=credentials.get("email"),
            roles=credentials.get("roles", []),
        )

        self._logger.info(
            "Authentication successful",
            extra={
                "username": credentials.get("username"),
                "user_id": credentials["user_id"],
            },
        )

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[bool]:
        """Validate JWT token.

        Args:
            token: Token string or AuthToken object to validate

        Returns:
            FlextResult[bool]: True if valid, False if invalid, or error

        Example:
            >>> result = provider.validate(token_string)
            >>> if result.is_success and result.unwrap():
            ...     print("Token is valid")

        """
        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[bool].fail(str(e))

        # Decode and verify token
        try:
            payload = jwt.decode(
                token_string,
                self._secret_key,
                algorithms=[self._algorithm],
                options={
                    "verify_exp": True,
                    "verify_aud": False,  # Optional audience verification
                    "verify_iss": False,  # Optional issuer verification
                },
            )

            # Additional validation checks
            if "sub" not in payload:
                return FlextResult[bool].fail("Token missing 'sub' claim")

            if "exp" not in payload:
                return FlextResult[bool].fail("Token missing 'exp' claim")

            # Check expiration manually as well
            exp_timestamp = payload["exp"]
            if datetime.fromtimestamp(exp_timestamp, tz=UTC) < datetime.now(UTC):
                return FlextResult[bool].fail("Token expired")

            self._logger.debug(
                "Token validated successfully", extra={"sub": payload.get("sub")}
            )

            return FlextResult[bool].ok(True)

        except jwt.ExpiredSignatureError:
            return FlextResult[bool].fail("Token expired")
        except jwt.InvalidTokenError as e:
            return FlextResult[bool].fail(f"Invalid token: {e}")
        except Exception as e:
            return FlextResult[bool].fail(f"Token validation failed: {e}")

    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh JWT token.

        Args:
            token: Existing token to refresh (can be access or refresh token)

        Returns:
            FlextResult[AuthToken]: New token or error

        Example:
            >>> result = provider.refresh(old_token)
            >>> if result.is_success:
            ...     new_token = result.unwrap()

        """
        # Check capability
        capability_check = self._check_capability_supported("refresh")
        if capability_check.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(capability_check.error)

        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[FlextAuthModels.AuthToken].fail(str(e))

        # Decode token without expiration verification (refresh tokens may be expired)
        try:
            payload = jwt.decode(
                token_string,
                self._secret_key,
                algorithms=[self._algorithm],
                options={"verify_exp": False},  # Don't verify expiration for refresh
            )

            # Extract user information from payload
            user_id = payload.get("sub")
            if not user_id:
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    "Invalid token: missing user ID"
                )

            # Recreate credentials from payload
            credentials = {
                "user_id": user_id,
                "username": payload.get("username"),
                "email": payload.get("email"),
                "roles": payload.get("roles", []),
            }

            # Generate new tokens
            return self.authenticate(credentials)

        except jwt.InvalidTokenError as e:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                f"Invalid token for refresh: {e}"
            )
        except Exception as e:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                f"Token refresh failed: {e}"
            )

    def revoke(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[None]:
        """Revoke JWT token.

        Note: JWT tokens are stateless, so true revocation requires a token
        blacklist. This implementation logs the revocation but doesn't maintain
        a blacklist. For production use, implement a Redis-based blacklist.

        Args:
            token: Token to revoke

        Returns:
            FlextResult[None]: Success or error

        Example:
            >>> result = provider.revoke(token)
            >>> if result.is_success:
            ...     print("Token revoked (logged)")

        """
        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[None].fail(str(e))

        # Decode token to get metadata
        try:
            payload = jwt.decode(
                token_string,
                self._secret_key,
                algorithms=[self._algorithm],
                options={"verify_exp": False},
            )

            self._logger.info(
                "Token revoked (logged only - implement blacklist for production)",
                extra={
                    "sub": payload.get("sub"),
                    "jti": payload.get("jti"),
                    "exp": payload.get("exp"),
                },
            )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Token revocation failed: {e}")

    def supports(self) -> set[str]:
        """Return JWT provider capabilities.

        Returns:
            set[str]: Set of supported capabilities

        Capabilities:
            - token: Token generation
            - validate: Token validation
            - refresh: Token refresh
            - password_hash: Password hashing (bcrypt)
            - jwt: JWT standard support

        """
        return {"token", "validate", "refresh", "password_hash", "jwt"}

    def get_metadata(self) -> FlextTypes.Dict:
        """Return JWT provider metadata.

        Returns:
            FlextTypes.Dict: Provider metadata

        """
        return {
            "name": "jwt",
            "version": "2.0.0",
            "description": "JWT-based authentication with bcrypt password hashing",
            "capabilities": list(self.supports()),
            "algorithm": self._algorithm,
            "access_token_expiry_minutes": self._access_token_expiry_minutes,
            "refresh_token_expiry_days": self._refresh_token_expiry_days,
            "bcrypt_rounds": self._bcrypt_rounds,
            "issuer": self._issuer,
            "audience": self._audience,
        }

    def get_decoding_params(self) -> FlextResult[FlextTypes.Dict]:
        """Get parameters needed for token decoding.

        Returns:
            FlextResult[dict]: Decoding parameters with secret_key and algorithm

        """
        return FlextResult.ok({
            "secret_key": self._secret_key,
            "algorithm": self._algorithm,
        })

    def _generate_access_token(
        self, credentials: FlextTypes.Dict
    ) -> FlextResult[FlextTypes.Dict]:
        """Generate JWT access token.

        Args:
            credentials: User credentials and claims

        Returns:
            FlextResult[dict]: Token data with "token" and "expires_at" keys

        """
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=self._access_token_expiry_minutes)

        payload: FlextTypes.Dict = {
            "sub": credentials["user_id"],
            "exp": int(expires_at.timestamp()),
            "iat": int(now.timestamp()),
            "jti": str(uuid4()),  # Unique token ID
        }

        # Add optional claims
        if self._issuer:
            payload["iss"] = self._issuer
        if self._audience:
            payload["aud"] = self._audience
        if "username" in credentials:
            payload["username"] = credentials["username"]
        if "email" in credentials:
            payload["email"] = credentials["email"]
        if "roles" in credentials:
            payload["roles"] = credentials["roles"]

        # Encode token
        token_result = FlextAuthUtilities.JWTProcessing.encode_token(
            payload, self._secret_key, self._algorithm
        )

        if token_result.is_failure:
            return FlextResult[FlextTypes.Dict].fail(token_result.error)

        return FlextResult[FlextTypes.Dict].ok({
            "token": token_result.unwrap(),
            "expires_at": expires_at,
        })

    def _generate_refresh_token(
        self, credentials: FlextTypes.Dict
    ) -> FlextResult[FlextTypes.Dict]:
        """Generate JWT refresh token.

        Args:
            credentials: User credentials

        Returns:
            FlextResult[dict]: Token data with "token" and "expires_at" keys

        """
        now = datetime.now(UTC)
        expires_at = now + timedelta(days=self._refresh_token_expiry_days)

        payload: FlextTypes.Dict = {
            "sub": credentials["user_id"],
            "exp": int(expires_at.timestamp()),
            "iat": int(now.timestamp()),
            "jti": str(uuid4()),
            "type": "refresh",  # Mark as refresh token
        }

        # Add minimal claims for refresh token
        if "username" in credentials:
            payload["username"] = credentials["username"]

        # Encode token
        token_result = FlextAuthUtilities.JWTProcessing.encode_token(
            payload, self._secret_key, self._algorithm
        )

        if token_result.is_failure:
            return FlextResult[FlextTypes.Dict].fail(token_result.error)

        return FlextResult[FlextTypes.Dict].ok({
            "token": token_result.unwrap(),
            "expires_at": expires_at,
        })


__all__ = ["JwtAuthProvider"]
