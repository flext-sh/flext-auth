"""API Key authentication provider implementation.

This module implements API key-based authentication, commonly used for:
- REST API authentication
- Service-to-service authentication
- Programmatic access to APIs
- Third-party integrations

API keys can be validated through various mechanisms:
- Database lookup
- Hash comparison
- External validation service
- Rate limiting and quota management

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from flext_core import FlextLogger, FlextResult, FlextTypes

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.mixin import FlextAuthProviderMixin


class FlextAuthApiKeyProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    """API Key authentication provider.

    This provider implements API key-based authentication for REST APIs
    and service-to-service communication.

    Configuration:
        - key_prefix: API key prefix (e.g., 'sk_', 'pk_') (optional)
        - key_length: Length of generated API keys (default: 32)
        - hash_algorithm: Algorithm for key hashing (default: 'sha256')
        - require_key_id: Require both key ID and secret (default: False)
        - key_storage: Storage mechanism ('memory', 'database') (default: 'memory')
        - rate_limit_enabled: Enable rate limiting (default: False)
        - rate_limit_requests: Max requests per window (default: 1000)
        - rate_limit_window_seconds: Rate limit window (default: 3600)

    Example:
        >>> config = {
        ...     "key_prefix": "sk_",
        ...     "key_length": 32,
        ...     "hash_algorithm": "sha256",
        ...     "require_key_id": True,
        ... }
        >>> provider = FlextAuthApiKeyProvider(config)
        >>> # Generate new API key
        >>> key_result = provider.generate_api_key(
        ...     user_id="user-123", name="Production API Key"
        ... )
        >>> # Authenticate with API key
        >>> result = provider.authenticate({"api_key": "sk_..."})

    """

    def __init__(self, config: FlextTypes.Dict) -> None:
        """Initialize API Key authentication provider.

        Args:
            config: Provider configuration dictionary

        """
        self._config = config
        self.logger = FlextLogger(__name__)

        # Configuration with defaults and type checking
        self._key_prefix = str(self._config.get("key_prefix", ""))
        self._key_length = int(str(self._config.get("key_length", 32)))
        self._hash_algorithm = str(self._config.get("hash_algorithm", "sha256"))
        self._require_key_id = bool(self._config.get("require_key_id", False))
        self._key_storage = str(self._config.get("key_storage", "memory"))
        self._rate_limit_enabled = bool(self._config.get("rate_limit_enabled", False))
        self._rate_limit_requests = int(
            str(self._config.get("rate_limit_requests", 1000))
        )
        self._rate_limit_window_seconds = int(
            str(self._config.get("rate_limit_window_seconds", 3600))
        )

        # In-memory storage (for development/testing)
        # In production, use database or external key management service
        self._api_keys: FlextTypes.NestedDict = {}  # key_hash -> metadata
        self._rate_limits: dict[
            str, list[datetime]
        ] = {}  # key_hash -> request timestamps

        self.logger.info(
            "API Key provider initialized",
            extra={
                "key_prefix": self._key_prefix or "none",
                "key_length": self._key_length,
                "hash_algorithm": self._hash_algorithm,
                "require_key_id": self._require_key_id,
            },
        )

    def authenticate(
        self,
        credentials: FlextTypes.Dict,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate using API key.

        Args:
            credentials: Must contain 'api_key' (and optionally 'key_id' if required)

        Returns:
            FlextResult[AuthToken]: Authentication token or error

        Example:
            >>> result = provider.authenticate({
            ...     "api_key": "sk_abc123...",
            ... })

        """
        # Validate required fields
        required_fields = ["api_key"]
        if self._require_key_id:
            required_fields.append("key_id")

        validation_result = self._validate_credentials_dict(
            credentials, required_fields
        )
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation_result.error)

        api_key = credentials["api_key"]
        if not isinstance(api_key, str):
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "API key must be a string"
            )

        # Validate API key format
        if self._key_prefix and not api_key.startswith(self._key_prefix):
            return FlextResult[FlextAuthModels.AuthToken].fail(
                f"Invalid API key format: expected prefix '{self._key_prefix}'"
            )

        # Hash the API key for lookup
        key_hash = self._hash_api_key(api_key)

        # Check if key exists
        if key_hash not in self._api_keys:
            self.logger.warning("Authentication failed: API key not found")
            return FlextResult[FlextAuthModels.AuthToken].fail("Invalid API key")

        key_metadata = self._api_keys[key_hash]

        # Check if key is active
        if not key_metadata.get("active", True):
            return FlextResult[FlextAuthModels.AuthToken].fail("API key is disabled")

        # Check expiration
        expires_at = key_metadata.get("expires_at")
        if (
            expires_at
            and isinstance(expires_at, datetime)
            and datetime.now(UTC) > expires_at
        ):
            return FlextResult[FlextAuthModels.AuthToken].fail("API key expired")

        # Check rate limits
        if self._rate_limit_enabled:
            rate_limit_check = self._check_rate_limit(key_hash)
            if rate_limit_check.is_failure:
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    rate_limit_check.error
                )

        # Create authentication token
        # Calculate expires_at: use key expiration or far future
        token_expires_at = expires_at or datetime.now(UTC) + timedelta(days=365 * 10)

        auth_token = FlextAuthModels.AuthToken(
            token=api_key,  # API key serves as the token
            token_type=FlextAuthConstants.Jwt.API_TOKEN_TYPE,
            expires_at=token_expires_at,
            user_id=key_metadata["user_id"],
            is_revoked=False,
        )

        self.logger.info(
            "API key authentication successful",
            extra={
                "user_id": key_metadata["user_id"],
                "key_name": key_metadata.get("name"),
            },
        )

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[bool]:
        """Validate API key.

        Args:
            token: API key string or AuthToken object

        Returns:
            FlextResult[bool]: True if API key is valid

        """
        try:
            api_key = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[bool].fail(str(e))

        # Hash and lookup
        key_hash = self._hash_api_key(api_key)

        if key_hash not in self._api_keys:
            return FlextResult[bool].fail("API key not found")

        key_metadata = self._api_keys[key_hash]

        # Check active status
        if not key_metadata.get("active", True):
            return FlextResult[bool].fail("API key is disabled")

        # Check expiration
        expires_at = key_metadata.get("expires_at")
        if (
            expires_at
            and isinstance(expires_at, datetime)
            and datetime.now(UTC) > expires_at
        ):
            return FlextResult[bool].fail("API key expired")

        return FlextResult[bool].ok(True)

    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh API key.

        API keys typically don't support refresh. To extend an API key,
        generate a new one or update the expiration.

        Args:
            token: Current API key

        Returns:
            FlextResult[AuthToken]: Error indicating refresh not supported

        """
        _ = token  # Token parameter required by interface but not used for API key refresh
        return FlextResult[FlextAuthModels.AuthToken].fail(
            "API keys do not support refresh. Generate a new key or update expiration."
        )

    def revoke(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[None]:
        """Revoke API key.

        Args:
            token: API key to revoke

        Returns:
            FlextResult[None]: Success or error

        """
        try:
            api_key = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[None].fail(str(e))

        key_hash = self._hash_api_key(api_key)

        if key_hash not in self._api_keys:
            return FlextResult[None].fail("API key not found")

        # Mark as inactive instead of deleting for audit trail
        self._api_keys[key_hash]["active"] = False
        self._api_keys[key_hash]["revoked_at"] = datetime.now(UTC)

        self.logger.info(
            "API key revoked",
            extra={"key_id": self._api_keys[key_hash].get("key_id")},
        )

        return FlextResult[None].ok(None)

    def supports(self) -> set[str]:
        """Return API Key provider capabilities.

        Returns:
            set[str]: Set of supported capability strings

        Capabilities:
            - token: API key generation
            - validate: API key validation
            - apikey: API key authentication
            - revoke: API key revocation
            - rate_limit: Rate limiting (if enabled)

        """
        capabilities = {"token", "validate", "apikey", "revoke"}

        if self._rate_limit_enabled:
            capabilities.add("rate_limit")

        return capabilities

    def get_metadata(self) -> FlextTypes.Dict:
        """Return API Key provider metadata.

        Returns:
            FlextTypes.Dict: Provider metadata

        """
        return {
            "name": "apikey",
            "version": "2.0.0",
            "description": "API Key authentication provider",
            "capabilities": list(self.supports()),
            "key_prefix": self._key_prefix,
            "key_length": self._key_length,
            "hash_algorithm": self._hash_algorithm,
            "require_key_id": self._require_key_id,
            "rate_limit_enabled": self._rate_limit_enabled,
        }

    # Helper methods

    def _hash_api_key(self, api_key: str) -> str:
        """Hash API key for storage.

        Args:
            api_key: Raw API key string

        Returns:
            str: Hashed API key

        """
        hash_obj = hashlib.new(self._hash_algorithm)
        hash_obj.update(api_key.encode("utf-8"))
        return hash_obj.hexdigest()

    def _check_rate_limit(self, key_hash: str) -> FlextResult[None]:
        """Check rate limit for API key.

        Args:
            key_hash: Hashed API key

        Returns:
            FlextResult[None]: Success if within limit, error if exceeded

        """
        now = datetime.now(UTC)
        window_start = now - timedelta(seconds=self._rate_limit_window_seconds)

        # Get request timestamps for this key
        if key_hash not in self._rate_limits:
            self._rate_limits[key_hash] = []

        # Remove old timestamps outside the window
        self._rate_limits[key_hash] = [
            ts for ts in self._rate_limits[key_hash] if ts > window_start
        ]

        # Check if limit exceeded
        if len(self._rate_limits[key_hash]) >= self._rate_limit_requests:
            return FlextResult[None].fail(
                f"Rate limit exceeded: {self._rate_limit_requests} "
                f"requests per {self._rate_limit_window_seconds} seconds"
            )

        # Record this request
        self._rate_limits[key_hash].append(now)

        return FlextResult[None].ok(None)

    def generate_api_key(
        self,
        user_id: str,
        name: str | None = None,
        scopes: FlextTypes.StringList | None = None,
        expires_in_days: int | None = None,
    ) -> FlextResult[FlextTypes.StringDict]:
        """Generate new API key.

        Args:
            user_id: User ID associated with this key
            name: Human-readable name for the key
            scopes: List of scopes/permissions for this key
            expires_in_days: Number of days until expiration (None = never expires)

        Returns:
            FlextResult[FlextTypes.Dict]: Dictionary with 'key_id', 'api_key', and 'key_hash'

        """
        # Generate key ID
        key_id = f"{self._key_prefix}id_{secrets.token_hex(8)}"

        # Generate API key
        raw_key = secrets.token_hex(self._key_length)
        api_key = f"{self._key_prefix}{raw_key}"

        # Hash for storage
        key_hash = self._hash_api_key(api_key)

        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)

        # Store metadata
        self._api_keys[key_hash] = {
            "key_id": key_id,
            "user_id": user_id,
            "name": name,
            "scopes": scopes or [],
            "active": True,
            "created_at": datetime.now(UTC),
            "expires_at": expires_at,
        }

        self.logger.info(
            "API key generated",
            extra={
                "key_id": key_id,
                "user_id": user_id,
                "key_name": name,
                "expires_at": expires_at.isoformat() if expires_at else "never",
            },
        )

        return FlextResult[FlextTypes.StringDict].ok({
            "key_id": key_id,
            "api_key": api_key,  # Return only once - never log or store raw key
            "key_hash": key_hash,
        })


__all__ = ["FlextAuthApiKeyProvider"]
