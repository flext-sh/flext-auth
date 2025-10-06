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
from flext_core import FlextBus, FlextContext, FlextLogger, FlextResult, FlextTypes

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.mixin import FlextAuthProviderMixin
from flext_auth.utilities import FlextAuthUtilities


class FlextAuthJwtProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    """JWT-based authentication provider.

    Implements authentication using JSON Web Tokens (JWT) with bcrypt password
    hashing. Supports token generation, validation, and refresh operations.

    Features:
        - JWT token generation and validation
        - Password hashing with bcrypt
        - Token refresh capabilities
        - Configurable expiration times
        - Support for multiple algorithms (HS256, RS256, etc.)

    Example:
        >>> provider = FlextAuthJwtProvider({
        ...     "secret_key": "your-secret-key",
        ...     "algorithm": "HS256",
        ...     "expiry_minutes": 30,
        ... })
        >>> result = provider.authenticate({"username": "user", "password": "password"})

    """

    def __init__(self, config: FlextTypes.Dict) -> None:
        """Initialize JWT provider with configuration.

        Args:
            config: Provider configuration dictionary

        Required config fields:
            - secret_key: str - JWT signing secret
            - algorithm: str - JWT algorithm (default: HS256)

        Optional config fields:
            - expiry_minutes: int - Token expiration in minutes (default: 30)
            - refresh_expiry_days: int - Refresh token expiration in days (default: 7)
            - issuer: str - JWT issuer claim (default: flext-auth)
            - audience: str - JWT audience claim (default: flext-users)

        """
        super().__init__()
        self._config = config
        self._secret_key = config.get("secret_key", FlextAuthConstants.Jwt.SECRET_KEY)
        self._algorithm = config.get(
            "algorithm", FlextAuthConstants.Jwt.DEFAULT_ALGORITHM
        )
        self._expiry_minutes = config.get(
            "expiry_minutes", FlextAuthConstants.Jwt.DEFAULT_EXPIRY_MINUTES
        )
        self._refresh_expiry_days = config.get("refresh_expiry_days", 7)
        self._issuer = config.get("issuer", FlextAuthConstants.Jwt.ISSUER_CLAIM)
        self._audience = config.get("audience", FlextAuthConstants.Jwt.AUDIENCE_CLAIM)

        # Initialize flext-core components
        self._logger = FlextLogger(__name__)
        self._context = FlextContext()
        self._bus = FlextBus()

    def authenticate(
        self,
        credentials: FlextTypes.Dict,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate user with username/password credentials.

        Args:
            credentials: Dictionary containing username and password

        Returns:
            FlextResult[AuthToken]: Authentication token on success

        """
        # Validate required fields
        validation = self._validate_credentials_dict(
            credentials, ["username", "password"]
        )
        if validation.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation.error)

        username = credentials["username"]
        password = credentials["password"]

        # Verify password (in real implementation, this would query user database)
        password_valid = FlextAuthUtilities.PasswordProcessing.verify_password(
            password, credentials.get("password_hash", "hashed_password")
        )

        if not password_valid:
            return FlextResult[FlextAuthModels.AuthToken].fail("Invalid credentials")

        # Generate access token
        access_token_result = self._generate_access_token(credentials)
        if access_token_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                access_token_result.error
            )

        access_token_data = access_token_result.unwrap()

        # Generate refresh token
        refresh_token_result = self._generate_refresh_token(credentials)
        if refresh_token_result.is_failure:
            self._logger.warning(
                f"Refresh token generation failed: {refresh_token_result.error}"
            )
            # Continue with access token only
            refresh_token = None
            # refresh_expires_at = None  # Not used in current implementation
        else:
            refresh_token_data = refresh_token_result.unwrap()
            refresh_token = refresh_token_data["token"]
            # refresh_expires_at = refresh_token_data["expires_at"]  # Not used in current implementation

        # Create AuthToken model
        auth_token = FlextAuthModels.AuthToken(
            token=access_token_data["token"],
            token_type=FlextAuthConstants.Jwt.DEFAULT_TOKEN_TYPE,
            expires_at=access_token_data["expires_at"],
            refresh_token=refresh_token,
            user_id=credentials["user_id"],
            is_revoked=False,
        )

        self._logger.info(
            "Authentication successful",
            extra={
                "username": username,
                "user_id": credentials.get("user_id"),
                "token_type": "JWT",
            },
        )

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[bool]:
        """Validate JWT token.

        Args:
            token: JWT token string or AuthToken object

        Returns:
            FlextResult[bool]: True if valid, False if invalid

        """
        # Extract token string
        token_string = self._extract_token_string(token)

        # Validate token string format
        validation = self._validate_token_string(token_string)
        if validation.is_failure:
            return FlextResult[bool].fail(validation.error)

        try:
            # Decode and validate JWT
            payload = jwt.decode(
                token_string,
                self._secret_key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                audience=self._audience,
            )

            # Check expiration
            if "exp" in payload:
                exp_timestamp = payload["exp"]
                if datetime.now(UTC).timestamp() > exp_timestamp:
                    return FlextResult[bool].ok(False)

            return FlextResult[bool].ok(True)

        except jwt.ExpiredSignatureError:
            return FlextResult[bool].ok(False)
        except jwt.InvalidTokenError as e:
            return FlextResult[bool].fail(f"Invalid token: {e}")

    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh JWT token.

        Args:
            token: Existing token to refresh

        Returns:
            FlextResult[AuthToken]: New token on success

        """
        # Check if refresh is supported
        capability_check = self._check_capability_supported("refresh")
        if capability_check.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(capability_check.error)

        # Extract token string
        token_string = self._extract_token_string(token)

        try:
            # Decode token to get user information
            payload = jwt.decode(
                token_string,
                self._secret_key,
                algorithms=[self._algorithm],
                options={"verify_exp": False},  # Allow expired tokens for refresh
            )

            # Generate new token with same user info
            new_token_result = self._generate_access_token(payload)
            if new_token_result.is_failure:
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    new_token_result.error
                )

            new_token_data = new_token_result.unwrap()

            # Create new AuthToken
            auth_token = FlextAuthModels.AuthToken(
                token=new_token_data["token"],
                token_type=FlextAuthConstants.Jwt.DEFAULT_TOKEN_TYPE,
                expires_at=new_token_data["expires_at"],
                user_id=payload.get("user_id", "unknown"),
                is_revoked=False,
            )

            return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

        except jwt.InvalidTokenError as e:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                f"Invalid token for refresh: {e}"
            )

    def revoke(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[None]:
        """Revoke JWT token.

        Args:
            token: Token to revoke

        Returns:
            FlextResult[None]: Success if revoked

        """
        # JWT tokens are stateless, so revocation requires external tracking
        # This is a placeholder implementation
        _ = token  # Mark as used to avoid linting error
        self._logger.info("Token revocation requested (stateless JWT)")
        return FlextResult[None].ok(None)

    def supports(self) -> set[str]:
        """Return supported capabilities.

        Returns:
            set[str]: Set of supported capabilities

        """
        return {"token", "validate", "refresh"}

    def get_metadata(self) -> FlextTypes.Dict:
        """Return provider metadata.

        Returns:
            FlextTypes.Dict: Provider metadata

        """
        return {
            "name": "jwt",
            "version": "1.0.0",
            "capabilities": list(self.supports()),
            "description": "JWT-based authentication provider",
            "algorithm": self._algorithm,
            "expiry_minutes": self._expiry_minutes,
        }

    def _generate_access_token(
        self, credentials: FlextTypes.Dict
    ) -> FlextResult[FlextTypes.Dict]:
        """Generate access token.

        Args:
            credentials: User credentials

        Returns:
            FlextResult[dict]: Token data on success

        """
        try:
            now = datetime.now(UTC)
            expires_at = now + timedelta(minutes=self._expiry_minutes)

            # Create JWT payload
            payload = {
                "sub": credentials.get(
                    "user_id", credentials.get("username", "unknown")
                ),
                "username": credentials.get("username", "unknown"),
                "iat": now.timestamp(),
                "exp": expires_at.timestamp(),
                "iss": self._issuer,
                "aud": self._audience,
                "jti": str(uuid4()),
            }

            # Generate token
            token = FlextAuthUtilities.JWTProcessing.encode_token(
                payload, self._secret_key, self._algorithm
            )

            return FlextResult[FlextTypes.Dict].ok({
                "token": token,
                "expires_at": expires_at,
            })

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Token generation failed: {e}")

    def _generate_refresh_token(
        self, credentials: FlextTypes.Dict
    ) -> FlextResult[FlextTypes.Dict]:
        """Generate refresh token.

        Args:
            credentials: User credentials

        Returns:
            FlextResult[dict]: Refresh token data on success

        """
        try:
            now = datetime.now(UTC)
            expires_at = now + timedelta(days=self._refresh_expiry_days)

            # Create refresh token payload
            payload = {
                "sub": credentials.get(
                    "user_id", credentials.get("username", "unknown")
                ),
                "type": "refresh",
                "iat": now.timestamp(),
                "exp": expires_at.timestamp(),
                "iss": self._issuer,
                "aud": self._audience,
                "jti": str(uuid4()),
            }

            # Generate refresh token
            token = FlextAuthUtilities.JWTProcessing.encode_token(
                payload, self._secret_key, self._algorithm
            )

            return FlextResult[FlextTypes.Dict].ok({
                "token": token,
                "expires_at": expires_at,
            })

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(
                f"Refresh token generation failed: {e}"
            )

    def generate_access_token(
        self, payload: FlextTypes.Dict, expires_in_minutes: int | None = None
    ) -> FlextResult[FlextTypes.Dict]:
        """Generate access token with custom payload.

        Args:
            payload: Token payload data
            expires_in_minutes: Token expiration in minutes

        Returns:
            FlextResult[dict]: Token data on success

        """
        try:
            now = datetime.now(UTC)
            expiry_minutes = expires_in_minutes or self._expiry_minutes
            expires_at = now + timedelta(minutes=expiry_minutes)

            # Create JWT payload
            full_payload = {
                **payload,
                "iat": now.timestamp(),
                "exp": expires_at.timestamp(),
                "iss": self._issuer,
                "aud": self._audience,
                "jti": str(uuid4()),
            }

            # Generate token
            token = FlextAuthUtilities.JWTProcessing.encode_token(
                full_payload, self._secret_key, self._algorithm
            )

            return FlextResult[FlextTypes.Dict].ok({
                "token": token,
                "expires_at": expires_at,
            })

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Token generation failed: {e}")


__all__ = ["FlextAuthJwtProvider"]
