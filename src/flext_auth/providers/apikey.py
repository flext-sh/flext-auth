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

from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.mixin import FlextAuthProviderMixin


class FlextAuthApiKeyProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    r"""SOLID-compliant API Key authentication provider.

    Uses composition for key validation, generation, and rate limiting.
    Railway-oriented programming with flext-core patterns for maximum maintainability.
        >>> config = {
        ...     "key_prefix": "sk_",
        ...     "key_length": 32,
        ...     "hash_algorithm": "sha256",
        ...     "require_key_id": True,
        ... }
        >>> provider = FlextAuthApiKeyProvider(config)
        >>> # Generate new API key
        >>> key_result = provider.generate_api_key(
        ...     identity_id="user-123", name="Production API Key"
        ... )
        >>> # Authenticate with API key
        >>> result = provider.authenticate({"api_key": "sk_..."})

    """

 def __init__(self, config: FlextAuthModels.ProviderConfiguration) -> None:
 """Initialize API Key provider with SOLID delegation.

        Uses composition for key validation, generation, and rate limiting.
        Railway-oriented initialization with proper error handling.
        """
        self.logger = FlextLogger(__name__)
        self._config = config

        # Use railway-oriented validation
        validation_result = self._validate_configuration()
        if validation_result.is_failure:
            msg = f"API Key configuration validation failed: {validation_result.error}"
            raise ValueError(msg)

        # Initialize components using composition
        self._key_validator = self._KeyValidator(self)
        self._key_generator = self._KeyGenerator(self)
        self._rate_limiter = self._RateLimiter(self)

        # In-memory storage
        self._api_keys: FlextTypes.NestedDict = {}
        self._rate_limits: dict[str, list[datetime]] = {}

        self.logger.info("API Key provider initialized")

    def get_api_key_data(self, key_hash: str) -> dict[str, object] | None:
        """Get API key data by hash."""
        return self._api_keys.get(key_hash)

    def get_hash_algorithm(self) -> str:
        """Get hash algorithm for API keys."""
        return "sha256"

    def get_key_length(self) -> int:
        """Get API key length."""
        return 32

    def get_key_prefix(self) -> str:
        """Get API key prefix."""
        return "fk_"

    def is_rate_limit_enabled(self) -> bool:
        """Check if rate limiting is enabled."""
        return True

    def get_rate_limit_requests(self) -> int:
        """Get rate limit requests per window."""
        return 100

    def get_rate_limit_window(self) -> int:
        """Get rate limit window in seconds."""
        return 3600

    def get_rate_limit_history(self, key_hash: str) -> list[datetime]:
        """Get rate limit history for key."""
        return self._rate_limits.get(key_hash, [])

    def _validate_configuration(self) -> FlextResult[None]:
        """Railway-oriented configuration validation."""
        # Validate field types
        validations = [
            (
                "key_prefix",
                (str, type(None)),
                "API Key key_prefix must be a string or None",
            ),
            (
                "key_length",
                (int, type(None)),
                "API Key key_length must be an integer or None",
            ),
            (
                "hash_algorithm",
                (str, type(None)),
                "API Key hash_algorithm must be a string or None",
            ),
            (
                "require_key_id",
                (bool, type(None)),
                "API Key require_key_id must be a boolean or None",
            ),
            (
                "key_storage",
                (str, type(None)),
                "API Key key_storage must be a string or None",
            ),
            (
                "rate_limit_enabled",
                (bool, type(None)),
                "API Key rate_limit_enabled must be a boolean or None",
            ),
            (
                "rate_limit_requests",
                (int, type(None)),
                "API Key rate_limit_requests must be an integer or None",
            ),
            (
                "rate_limit_window_seconds",
                (int, type(None)),
                "API Key rate_limit_window_seconds must be an integer or None",
            ),
        ]

        for field_name, expected_types, error_msg in validations:
            field_value = self._config.get(field_name)
            if field_value is not None and not isinstance(field_value, expected_types):
                return FlextResult[None].fail(
                    f"{error_msg}. Got {type(field_value).__name__}"
                )

        return FlextResult[None].ok(None)

    class _KeyValidator:
        """SOLID-compliant API key validator.

 Single responsibility: validate API keys.
 """

        def __init__(self, provider: FlextAuthApiKeyProvider) -> None:
            """Initialize key validator."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def validate_key(self, api_key: str) -> FlextResult[dict[str, object]]:
            """Validate API key format and authenticity."""
            # Check key format
            if not api_key or not isinstance(api_key, str):
                return FlextResult[dict[str, object]].fail(
                    "API key must be a non-empty string"
                )

            # Hash the key for lookup
            key_hash = self._hash_api_key(api_key)

            # Check if key exists in storage
            key_data = self.provider.get_api_key_data(key_hash)
            if not key_data:
                return FlextResult[dict[str, object]].fail("Invalid API key")

            return FlextResult[dict[str, object]].ok(key_data)

        def _hash_api_key(self, api_key: str) -> str:
            """Hash API key for secure storage."""
            algorithm = self.provider.get_hash_algorithm()
            if algorithm == "sha256":
                return hashlib.sha256(api_key.encode()).hexdigest()
            if algorithm == "sha512":
                return hashlib.sha512(api_key.encode()).hexdigest()
            return hashlib.sha256(api_key.encode()).hexdigest()

    class _KeyGenerator:
        """SOLID-compliant API key generator.

 Single responsibility: generate secure API keys.
 """

        def __init__(self, provider: FlextAuthApiKeyProvider) -> None:
            """Initialize key generator."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def generate_key(self) -> str:
            """Generate a new API key."""
            key_length = self.provider.get_key_length()
            key_prefix = self.provider.get_key_prefix()

            # Generate random key
            random_part = secrets.token_hex(key_length // 2)

            return f"{key_prefix}{random_part}"

    class _RateLimiter:
        """SOLID-compliant rate limiter.

 Single responsibility: enforce API rate limits.
 """

        def __init__(self, provider: FlextAuthApiKeyProvider) -> None:
            """Initialize rate limiter."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def check_rate_limit(self, key_hash: str) -> FlextResult[bool]:
            """Check if request is within rate limits."""
            if not self.provider.is_rate_limit_enabled():
                return FlextResult[bool].ok(True)  # Rate limiting disabled

            max_requests = self.provider.get_rate_limit_requests()
            window_seconds = self.provider.get_rate_limit_window()

            # Get current timestamp
            now = datetime.now(UTC)

            # Get request history for this key
            request_times = self.provider.get_rate_limit_history(key_hash)

            # Remove old requests outside the window
            cutoff_time = now - timedelta(seconds=window_seconds)
            request_times[:] = [t for t in request_times if t > cutoff_time]

            # Check if under limit
            if len(request_times) >= max_requests:
                return FlextResult[bool].ok(False)  # Rate limit exceeded

            # Add current request
            request_times.append(now)
            return FlextResult[bool].ok(True)  # Within limits

    def authenticate(
        self,
        credentials: FlextAuthModels.ApiKeyValidation,
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
        # Use the ApiKeyValidation model directly
        if not credentials.is_valid:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                credentials.error_message or "Invalid API key"
            )

        if not credentials.key_data:
            return FlextResult[FlextAuthModels.AuthToken].fail("No key data available")

        # Extract API key from validation result
        api_key = str(credentials.key_data.get("api_key", ""))

        # Use composition for key processing
        return self._process_api_key_authentication(api_key, credentials.key_data)

    def _process_api_key_authentication(
        self, api_key: str, key_data: FlextAuthModels.ApiKeyData
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Process API key authentication result."""
        # Get key hash for rate limiting
        key_hash = self._key_validator.hash_api_key(api_key)

        # Check rate limits using composition
        return self._rate_limiter.check_rate_limit(key_hash).bind(
            lambda within_limits: self._create_api_key_token(
                api_key, key_data, within_limits=within_limits
            )
        )

    def _create_api_key_token(
        self,
        api_key: str,
        key_data: dict[str, object],
        *,
        within_limits: bool,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Create authentication token for API key."""
        if not within_limits:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "API key rate limit exceeded"
            )

        # Create authentication token
        auth_token = FlextAuthModels.AuthToken(
            identity_id=str(key_data.get("user_id", "api_user")),
            token=api_key,  # API key serves as token
            token_type="apikey",
            expires_at=datetime.now(UTC) + timedelta(days=365),
            is_revoked=False,
        )

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)


__all__ = ["FlextAuthApiKeyProvider"]
