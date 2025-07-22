"""JWT implementation for FLEXT Auth following Dependency Inversion Principle.

This module implements JWT services using abstract interfaces instead of
direct dependencies on external libraries, following the Dependency Inversion Principle.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flext_auth.infrastructure.abstractions import (
        ConfigurationProvider,
        FileSystemInterface,
        JWTLibrary,
        LoggerInterface,
        TimeProvider,
    )


class JWTService:
    """JWT token service following Dependency Inversion Principle.

    Depends on abstractions instead of concrete implementations,
    enabling easier testing and flexibility in dependency choices.
    """

    def __init__(
        self,
        jwt_library: JWTLibrary,
        config: ConfigurationProvider,
        filesystem: FileSystemInterface,
        time_provider: TimeProvider,
        logger: LoggerInterface,
    ) -> None:
        self._jwt_library = jwt_library
        self._config = config
        self._filesystem = filesystem
        self._time_provider = time_provider
        self._logger = logger

        # Load configuration
        self._algorithm = self._config.get_string("auth_algorithm", "HS256")
        self._access_token_expire_minutes = self._config.get_int(
            "auth_token_expire_minutes", 30,
        )
        self._refresh_token_expire_days = self._config.get_int(
            "jwt_refresh_token_expire_days", 7,
        )

        # Load keys based on algorithm
        if self._algorithm.startswith("RS"):
            # RSA algorithms - load from files
            private_key_path = self._config.get_string("jwt_private_key_path", "")
            public_key_path = self._config.get_string("jwt_public_key_path", "")

            if private_key_path:
                try:
                    self._private_key: str | None = self._filesystem.read_text(
                        Path(private_key_path),
                    )
                except ValueError as e:
                    self._logger.exception(
                        f"Failed to load private key from {private_key_path}: {e}",
                    )
                    self._private_key = None
            else:
                self._private_key = None

            if public_key_path:
                try:
                    self._public_key: str | None = self._filesystem.read_text(
                        Path(public_key_path),
                    )
                except ValueError as e:
                    self._logger.exception(
                        f"Failed to load public key from {public_key_path}: {e}",
                    )
                    self._public_key = None
            else:
                self._public_key = None
        else:
            # Symmetric algorithms - use secret key
            secret_key = self._config.get_string("jwt_secret_key")
            self._private_key = secret_key
            self._public_key = secret_key

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
            msg = "Private key is not configured"
            raise ValueError(msg)

        # Set expiration using time provider
        now = self._time_provider.now_utc()
        if expires_delta:
            expire = now + expires_delta
        elif token_type == "access":
            expire = now + timedelta(minutes=self._access_token_expire_minutes)
        else:
            # refresh token
            expire = now + timedelta(days=self._refresh_token_expire_days)

        # Build payload
        payload = {
            "sub": user_id,
            "username": username,
            "token_type": token_type,
            "exp": expire,
            "iat": now,
            "nbf": now,
        }

        # Add additional claims
        if additional_claims:
            payload.update(additional_claims)

        # Create token using injected JWT library
        try:
            token = self._jwt_library.encode(
                payload,
                self._private_key,
                self._algorithm,
            )
        except ValueError as e:
            self._logger.exception(f"Failed to create JWT token: {e}")
            raise

        self._logger.debug(
            f"token_created: user_id={user_id}, token_type={token_type}, "
            f"expires_at={expire.isoformat()}",
        )

        return token

    def decode_token(self, token: str) -> dict[str, Any]:
        """Decode and validate a JWT token.

        Args:
            token: JWT token string to decode.

        Returns:
            Dictionary containing token claims.

        Raises:
            ValueError: If public key is not configured or token is invalid.

        """
        if not self._public_key:
            msg = "Public key is not configured"
            raise ValueError(msg)

        try:
            # Use injected JWT library to decode token
            payload = self._jwt_library.decode(
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

            self._logger.debug(
                f"token_decoded: user_id={payload.get('sub')}, "
                f"token_type={payload.get('token_type')}",
            )

            return payload

        except ValueError as e:
            # All JWT errors are converted to ValueError by the adapter
            self._logger.warning(f"token_validation_failed: {e}")
            raise


def create_jwt_service(
    jwt_library: JWTLibrary,
    config: ConfigurationProvider,
    filesystem: FileSystemInterface,
    time_provider: TimeProvider,
    logger: LoggerInterface,
) -> JWTService:
    """Factory function to create JWTService with proper dependency injection.

    Args:
        jwt_library: JWT library implementation (e.g., PyJWTAdapter)
        config: Configuration provider implementation
        filesystem: File system interface implementation
        time_provider: Time provider implementation
        logger: Logger interface implementation

    Returns:
        JWTService: Configured JWT service instance

    """
    return JWTService(
        jwt_library=jwt_library,
        config=config,
        filesystem=filesystem,
        time_provider=time_provider,
        logger=logger,
    )
