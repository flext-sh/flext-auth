"""JWT implementation for FLEXT Auth.

No duplication - uses standard libraries only.
"""

from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import Any

import jwt

from flext_auth.infrastructure.config import AuthConfig
from flext_observability.logging import get_logger

logger = get_logger(__name__)


class JWTService:
    """JWT token service."""

    def __init__(self, settings: AuthConfig) -> None:
        self._settings = settings
        self._algorithm = settings.jwt_algorithm

        # Load keys based on algorithm
        if self._algorithm.startswith("RS"):
            # RSA algorithms
            if settings.jwt_private_key_path:
                self._private_key: str | None = Path(settings.jwt_private_key_path).read_text(
                    encoding="utf-8",
                )
            else:
                self._private_key = None

            if settings.jwt_public_key_path:
                self._public_key: str | None = Path(settings.jwt_public_key_path).read_text(
                    encoding="utf-8",
                )
            else:
                self._public_key = None
        else:
            # Symmetric algorithms
            self._private_key = settings.jwt_secret_key
            self._public_key = settings.jwt_secret_key

    def create_token(
        self,
        user_id: str,
        username: str,
        token_type: str = "access",
        expires_delta: timedelta | None = None,
        additional_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create a JWT token for a user.

        Args:
            user_id: Unique identifier for the user.
            username: Username for the user.
            token_type: Type of token (default: "access").
            expires_delta: Optional custom expiration time.
            additional_claims: Optional additional claims to include.

        Returns:
            Encoded JWT token string.

        Raises:
            ValueError: If private key is not configured.

        """
        if not self._private_key:
            msg = "Private key not configured for token creation"
            raise ValueError(msg)

        # Set expiration
        if expires_delta:
            expire = datetime.now(UTC) + expires_delta
        elif token_type == "access":
            expire = datetime.now(UTC) + timedelta(
                minutes=self._settings.jwt_access_token_expire_minutes,
            )
        else:
            # refresh token
            expire = datetime.now(UTC) + timedelta(
                days=self._settings.jwt_refresh_token_expire_days,
            )

        # Build payload
        payload = {
            "sub": user_id,
            "username": username,
            "token_type": token_type,
            "exp": expire,
            "iat": datetime.now(UTC),
            "nbf": datetime.now(UTC),
        }

        # Add additional claims
        if additional_claims:
            payload.update(additional_claims)

        # Create token
        token = jwt.encode(
            payload,
            self._private_key,
            algorithm=self._algorithm,
        )

        logger.debug(
            f"token_created: user_id={user_id}, token_type={token_type}, expires_at={expire.isoformat()}",
        )

        return token

    def decode_token(self, token: str) -> dict[str, Any]:
        """Decode and validate a JWT token.

        Args:
            token: JWT token string to decode.

        Returns:
            Dictionary containing token claims.

        Raises:
            ValueError: If public key is not configured.
            jwt.InvalidTokenError: If token is invalid or expired.

        """
        if not self._public_key:
            msg = "Public key not configured for token validation"
            raise ValueError(msg)

        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=[self._algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "require": ["exp", "iat", "nbf", "sub"],
                },
            )

            logger.debug(
                f"token_decoded: user_id={payload.get('sub')}, token_type={payload.get('token_type')}",
            )

            typed_payload: dict[str, Any] = payload
            return typed_payload

        except jwt.ExpiredSignatureError as e:
            logger.warning("token_expired")
            msg = "Token has expired"
            raise ValueError(msg) from e
        except jwt.InvalidTokenError as e:
            logger.warning(f"token_invalid: {e}")
            msg = f"Invalid token: {e}"
            raise ValueError(msg) from e
