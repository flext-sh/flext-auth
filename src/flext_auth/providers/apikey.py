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

from flext_core import r

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.providers.rfc import FlextAuthRfcProvider


class FlextAuthApiKeyProvider(FlextAuthRfcProvider):
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
        self._api_keys: dict[str, dict[str, object]] = {}
        self._rate_limits: dict[str, list[datetime]] = {}

        self.logger.info("API Key provider initialized")

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (e.g., "RFC 7617", "RFC 6749")

        """
        return "RFC API Key"

    def get_api_key_data(self, key_hash: str) -> dict[str, object] | None:
        """Get API key data by hash."""
        return self._api_keys.get(key_hash)

    def get_hash_algorithm(self) -> str:
        """Get hash algorithm for API keys."""
        algorithm_value = self._config.get("hash_algorithm")
        if (
            isinstance(algorithm_value, str)
            and algorithm_value
            and algorithm_value in FlextAuthConstants.ApiKey.HASH_ALGORITHMS
        ):
            return algorithm_value
        return FlextAuthConstants.ApiKey.HASH_ALGORITHM_DEFAULT

    def get_key_length(self) -> int:
        """Get API key length."""
        length_value = self._config.get("key_length")
        if isinstance(length_value, int) and length_value > 0:
            return length_value
        return FlextAuthConstants.ApiKey.LENGTH_DEFAULT

    def get_key_prefix(self) -> str:
        """Get API key prefix."""
        prefix_value = self._config.get("key_prefix")
        if isinstance(prefix_value, str) and prefix_value:
            return prefix_value
        return FlextAuthConstants.ApiKey.PREFIX_DEFAULT

    def is_rate_limit_enabled(self) -> bool:
        """Check if rate limiting is enabled."""
        enabled_value = self._config.get("rate_limit_enabled")
        if isinstance(enabled_value, bool):
            return enabled_value
        return FlextAuthConstants.ApiKey.RATE_LIMIT_ENABLED_DEFAULT

    def get_rate_limit_requests(self) -> int:
        """Get rate limit requests per window."""
        requests_value = self._config.get("rate_limit_requests")
        if isinstance(requests_value, int) and requests_value > 0:
            return requests_value
        return FlextAuthConstants.ApiKey.RATE_LIMIT_REQUESTS_DEFAULT

    def get_rate_limit_window(self) -> int:
        """Get rate limit window in seconds."""
        window_value = self._config.get("rate_limit_window_seconds")
        if isinstance(window_value, int) and window_value > 0:
            return window_value
        return FlextAuthConstants.ApiKey.RATE_LIMIT_WINDOW_SECONDS_DEFAULT

    def get_rate_limit_history(self, key_hash: str) -> list[datetime]:
        """Get rate limit history for key."""
        history_value = self._rate_limits.get(key_hash)
        if not isinstance(history_value, list):
            return []
        return history_value

    def _validate_configuration(self) -> r[bool]:
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
                return r[bool].fail(
                    f"{error_msg}. Got {type(field_value).__name__}"
                )

        return r[bool].ok(True)

    class _KeyValidator:
        """SOLID-compliant API key validator.

        Single responsibility: validate API keys.
        """

        def __init__(self, provider: FlextAuthApiKeyProvider) -> None:
            """Initialize key validator."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def validate_key(self, api_key: str) -> r[dict[str, object]]:
            """Validate API key format and authenticity."""
            # Check key format
            if not api_key or not isinstance(api_key, str):
                return r[dict[str, object]].fail(
                    "API key must be a non-empty string"
                )

            # Hash the key for lookup
            key_hash = self._hash_api_key(api_key)

            # Check if key exists in storage
            key_data = self.provider.get_api_key_data(key_hash)
            if not key_data:
                return r[dict[str, object]].fail("Invalid API key")

            return r[dict[str, object]].ok(key_data)

        def _hash_api_key(self, api_key: str) -> str:
            """Hash API key for secure storage."""
            algorithm = self.provider.get_hash_algorithm()
            # Use constants for algorithm comparison
            if algorithm == FlextAuthConstants.ApiKey.HASH_ALGORITHMS[0]:  # sha256
                return hashlib.sha256(api_key.encode()).hexdigest()
            if algorithm == FlextAuthConstants.ApiKey.HASH_ALGORITHMS[1]:  # sha512
                return hashlib.sha512(api_key.encode()).hexdigest()
            # Default to sha256 if unknown algorithm
            return hashlib.sha256(api_key.encode()).hexdigest()

        def hash_api_key(self, api_key: str) -> str:
            """Public method to hash API key."""
            return self._hash_api_key(api_key)

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

        def check_rate_limit(self, key_hash: str) -> r[bool]:
            """Check if request is within rate limits."""
            if not self.provider.is_rate_limit_enabled():
                return r[bool].ok(True)  # Rate limiting disabled

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
                return r[bool].ok(False)  # Rate limit exceeded

            # Add current request
            request_times.append(now)
            return r[bool].ok(True)  # Within limits

    def authenticate(
        self,
        credentials: dict[str, object],
    ) -> r[FlextAuthModels.AuthToken]:
        """Authenticate using API key.

        Args:
            credentials: Must contain 'api_key' (and optionally 'key_id' if required)

        Returns:
            r[AuthToken]: Authentication token or error

        Example:
            >>> result = provider.authenticate({
            ...     "api_key": "sk_abc123...",
            ... })

        """
        # Validate credentials dict structure
        validation_result = self._validate_credentials_dict(credentials, ["api_key"])
        if validation_result.is_failure:
            return r[FlextAuthModels.AuthToken].fail(
                validation_result.error or "Unknown error"
            )

        api_key_value = credentials.get("api_key")
        if not isinstance(api_key_value, str) or not api_key_value:
            return r[FlextAuthModels.AuthToken].fail(
                "API key must be a non-empty string"
            )
        api_key = api_key_value

        # Validate key using composition
        key_validation_result = self._key_validator.validate_key(api_key)
        if key_validation_result.is_failure:
            return r[FlextAuthModels.AuthToken].fail(
                key_validation_result.error or "Unknown error"
            )

        key_data = key_validation_result.unwrap()

        # Use composition for key processing
        return self._process_api_key_authentication(api_key, key_data)

    def _process_api_key_authentication(
        self, api_key: str, key_data: dict[str, object]
    ) -> r[FlextAuthModels.AuthToken]:
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
    ) -> r[FlextAuthModels.AuthToken]:
        """Create authentication token for API key."""
        if not within_limits:
            return r[FlextAuthModels.AuthToken].fail(
                "API key rate limit exceeded"
            )

        # Create authentication token - fast fail if missing user_id
        user_id_value = key_data.get("user_id")
        if not isinstance(user_id_value, str) or not user_id_value:
            return r[FlextAuthModels.AuthToken].fail(
                "Key data missing required 'user_id' field"
            )
        auth_token = FlextAuthModels.AuthToken(
            identity_id=user_id_value,
            token=api_key,  # API key serves as token
            token_type=FlextAuthConstants.TOKEN_TYPE_API,
            expires_at=datetime.now(UTC)
            + timedelta(days=FlextAuthConstants.ApiKey.EXPIRY_DAYS_DEFAULT),
            is_revoked=False,
        )

        return r[FlextAuthModels.AuthToken].ok(auth_token)

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> r[bool]:
        """Validate API key token.

        Args:
            token: API key token string or AuthToken object

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return r[bool].fail(str(e))

        # Validate key using composition
        validation_result = self._key_validator.validate_key(token_string)
        if validation_result.is_failure:
            return r[bool].fail(validation_result.error or "Unknown error")

        return r[bool].ok(True)

    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> r[FlextAuthModels.AuthToken]:
        """Refresh API key token.

        API keys don't support refresh - they remain valid until revoked.

        Args:
            token: Current API key token

        Returns:
            r[AuthToken]: Error indicating refresh not needed

        """
        _ = token
        return r[FlextAuthModels.AuthToken].fail(
            "API key authentication does not require token refresh. "
            "Use the same API key for subsequent requests."
        )

    def revoke(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> r[bool]:
        """Revoke API key token.

        Args:
            token: API key token to revoke

        Returns:
            r[bool]: True if revoked successfully, error on failure

        """
        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return r[bool].fail(str(e))

        # Hash the key for lookup
        key_hash = self._key_validator.hash_api_key(token_string)

        if key_hash not in self._api_keys:
            return r[bool].fail("API key not found")

        # Mark key as revoked
        self._api_keys[key_hash]["active"] = False
        self._api_keys[key_hash]["revoked_at"] = datetime.now(UTC)

        self.logger.info("API key revoked", key_hash=key_hash[:8])

        return r[bool].ok(True)

    def supports(self) -> set[str]:
        """Return API key provider capabilities.

        Returns:
            set[str]: Set of supported capability strings

        """
        capabilities = {"token", "validate", "apikey", "revoke"}

        if self.is_rate_limit_enabled():
            capabilities.add("rate_limit")

        return capabilities

    def get_metadata(self) -> dict[str, object]:
        """Return API key provider metadata.

        Returns:
            dict[str, object]: Provider metadata

        """
        config = FlextAuthModels.ProviderConfiguration(
            name="apikey",
            type="api_key",
            enabled=True,
            version="2.0.0",
            description="API key authentication provider",
            capabilities=list(self.supports()),
            key_prefix=self.get_key_prefix(),
            key_length=self.get_key_length(),
            hash_algorithm=self.get_hash_algorithm(),
            rate_limit_enabled=self.is_rate_limit_enabled(),
        )
        return dict(config)

    def validate_token(self, token: str) -> r[FlextAuthModels.Identity]:
        """Validate API key token and return identity."""
        # Validate key
        validation_result = self._key_validator.validate_key(token)
        if validation_result.is_failure:
            return r[FlextAuthModels.Identity].fail(
                validation_result.error or "Unknown error"
            )

        key_data = validation_result.unwrap()

        # Extract identity information
        user_id_value = key_data.get("user_id")
        if not isinstance(user_id_value, str) or not user_id_value:
            return r[FlextAuthModels.Identity].fail(
                "Key data missing required 'user_id' field"
            )

        username_value = key_data.get("username")
        username = username_value if isinstance(username_value, str) else user_id_value

        email_value = key_data.get("email")
        email = email_value if isinstance(email_value, str) else f"{username}@internal.invalid"

        roles_value = key_data.get("roles")
        roles = roles_value if isinstance(roles_value, list) else []

        permissions_value = key_data.get("permissions")
        permissions = permissions_value if isinstance(permissions_value, list) else []

        identity = FlextAuthModels.Identity(
            unique_id=user_id_value,
            name=username,
            contact=email,
            roles=roles,
            permissions=permissions,
        )

        return r[FlextAuthModels.Identity].ok(identity)

    def generate_token_for_user(
        self,
        user: FlextAuthModels.Identity,
        token_type: str = FlextAuthConstants.TOKEN_TYPE_ACCESS,
        expiry_minutes: int | None = None,
    ) -> r[str]:
        """Generate API key token for user.

        Args:
            user: User to generate token for
            token_type: Type of token (ignored for API keys)
            expiry_minutes: Token expiry (ignored for API keys, uses default expiry)

        Returns:
            FlextResult containing API key string or error

        """
        _ = token_type  # API keys don't have different types
        _ = expiry_minutes  # API keys use fixed expiry

        # Generate new API key
        api_key = self._key_generator.generate_key()

        # Store key data
        key_hash = self._key_validator.hash_api_key(api_key)
        self._api_keys[key_hash] = {
            "user_id": user.unique_id,
            "username": user.name,
            "email": user.contact,
            "roles": user.roles,
            "permissions": user.permissions,
            "active": True,
            "created_at": datetime.now(UTC),
        }

        return r[str].ok(api_key)


__all__ = ["FlextAuthApiKeyProvider"]
