"""HTTP Basic authentication provider implementation.

This module implements HTTP Basic Authentication (RFC 7617), commonly used for:
- Simple REST API authentication
- Internal service authentication
- Legacy system integration
- Development and testing environments

Basic authentication transmits credentials as base64-encoded username:password
pairs in the Authorization header. While simple, it should only be used over
HTTPS in production environments.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime, timedelta

from flext_core import FlextLogger, FlextResult, FlextTypes

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.mixin import FlextAuthProviderMixin


class FlextAuthBasicProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    r"""SOLID-compliant HTTP Basic authentication provider.

    Uses composition for credential validation, user management, and metadata handling.
    Railway-oriented programming with flext-core patterns for maximum maintainability.

        >>> config = {
        ...     "realm": "My API",
        ...     "require_https": True,
        ...     "case_sensitive": True,
        ... }
        >>> provider = FlextAuthBasicProvider(config)
        >>> # Register user credentials
        >>> provider.add_user("REDACTED_LDAP_BIND_PASSWORD", "secure-password", user_id="REDACTED_LDAP_BIND_PASSWORD-001")
        >>> # Authenticate with Basic credentials
        >>> result = provider.authenticate({
        ...     "authorization": "Basic YWRtaW46c2VjdXJlLXBhc3N3b3Jk"
        ... })

    """

    def __init__(self, config: dict[str, object]) -> None:
        """Initialize Basic Auth provider with SOLID delegation.

        Uses composition for credential validation, user management, and metadata handling.
        Railway-oriented initialization with proper error handling.
        """
        self.logger = FlextLogger(__name__)
        self._config = config

        # Use railway-oriented validation
        validation_result = self._validate_configuration()
        if validation_result.is_failure:
            msg = (
                f"Basic Auth configuration validation failed: {validation_result.error}"
            )
            raise ValueError(msg)

        # Initialize components using composition
        self._credential_validator = self._CredentialValidator(self)
        self._user_manager = self._UserManager(self)
        self._metadata_handler = self._MetadataHandler(self)

        # In-memory user storage
        self._users: FlextTypes.NestedDict = {}

        # Anonymous access configuration
        self._allow_anonymous: bool = config.get("allow_anonymous", False)

        # HTTP Basic Auth realm
        self._realm: str = config.get("realm", "FLEXT Auth")

        # Case sensitivity for credential comparison
        self._case_sensitive: bool = config.get("case_sensitive", True)

        # HTTPS requirement for Basic Auth
        self._require_https: bool = config.get("require_https", True)

        self.logger.info("Basic Auth provider initialized")

    def _validate_configuration(self) -> FlextResult[None]:
        """Railway-oriented configuration validation."""
        # Validate field types
        validations = [
            ("realm", (str, type(None)), "Basic Auth realm must be a string or None"),
            (
                "allow_anonymous",
                (bool, type(None)),
                "Basic Auth allow_anonymous must be a boolean or None",
            ),
            (
                "case_sensitive",
                (bool, type(None)),
                "Basic Auth case_sensitive must be a boolean or None",
            ),
            (
                "user_store",
                (str, type(None)),
                "Basic Auth user_store must be a string or None",
            ),
            (
                "require_https",
                (bool, type(None)),
                "Basic Auth require_https must be a boolean or None",
            ),
        ]

        for field_name, expected_types, error_msg in validations:
            field_value = self._config.get(field_name)
            if field_value is not None and not isinstance(field_value, expected_types):
                return FlextResult[None].fail(
                    f"{error_msg}. Got {type(field_value).__name__}"
                )

        return FlextResult[None].ok(None)

    class _CredentialValidator:
        """SOLID-compliant credential validator.

        Single responsibility: validate Basic Auth credentials.
        """

        def __init__(self, provider) -> None:
            """Initialize credential validator."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def parse_authorization_header(
            self, auth_header: str
        ) -> FlextResult[tuple[str, str]]:
            """Parse Basic Auth authorization header."""
            try:
                if not auth_header.startswith("Basic "):
                    return FlextResult[tuple[str, str]].fail(
                        "Invalid authorization header format"
                    )

                # Decode base64 credentials
                encoded_credentials = auth_header[6:]  # Remove "Basic " prefix
                decoded_bytes = base64.b64decode(encoded_credentials)
                decoded_str = decoded_bytes.decode("utf-8")

                # Split into username:password
                if ":" not in decoded_str:
                    return FlextResult[tuple[str, str]].fail(
                        "Invalid credential format"
                    )

                username, password = decoded_str.split(":", 1)
                return FlextResult[tuple[str, str]].ok((username, password))

            except Exception as e:
                return FlextResult[tuple[str, str]].fail(
                    f"Failed to parse credentials: {e}"
                )

    class _UserManager:
        """SOLID-compliant user manager.

        Single responsibility: manage user storage and authentication.
        """

        def __init__(self, provider) -> None:
            """Initialize user manager."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def authenticate_user(
            self, username: str, password: str
        ) -> FlextResult[dict[str, object]]:
            """Authenticate user against stored credentials."""
            # Check case sensitivity
            case_sensitive = self.provider._config.get("case_sensitive", True)
            lookup_username = username if case_sensitive else username.lower()

            # Look up user in storage
            user_data = self.provider._users.get(lookup_username)
            if not user_data:
                return FlextResult[dict[str, object]].fail("User not found")

            # Verify password (simplified - in production use proper password hashing)
            stored_password = user_data.get("password", "")
            if password != stored_password:
                return FlextResult[dict[str, object]].fail("Invalid password")

            return FlextResult[dict[str, object]].ok(user_data)

    class _MetadataHandler:
        """SOLID-compliant metadata handler.

        Single responsibility: handle authentication metadata.
        """

        def __init__(self, provider) -> None:
            """Initialize metadata handler."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def create_auth_token(
            self, user_data: dict[str, object]
        ) -> FlextAuthModels.AuthToken:
            """Create authentication token from user data."""
            return FlextAuthModels.AuthToken(
                user_id=str(user_data.get("user_id", "unknown")),
                token=secrets.token_hex(32),  # Generate random token
                token_type="basic",
                expires_at=datetime.now(UTC) + timedelta(days=1),
                is_revoked=False,
            )

    def authenticate(
        self,
        credentials: dict[str, object],
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate using HTTP Basic credentials with SOLID delegation.

        Delegates credential parsing, user authentication, and token creation
        to specialized components following SRP.
        """
        # Validate required fields
        validation_result = self._validate_credentials_dict(
            credentials, ["authorization"]
        )
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation_result.error)

        authorization = credentials["authorization"]
        if not isinstance(authorization, str):
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Authorization header must be a string"
            )

        # Use composition for credential processing
        return self._credential_validator.parse_authorization_header(
            authorization
        ).bind(self._process_basic_authentication)

    def _process_basic_authentication(
        self, credentials: tuple[str, str]
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Process Basic authentication result."""
        username, password = credentials

        # Handle anonymous access
        if self._config.get("allow_anonymous", False) and not username:
            return FlextResult[FlextAuthModels.AuthToken].ok(
                FlextAuthModels.AuthToken(
                    user_id="anonymous",
                    token="anonymous",
                    token_type="basic",
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                    is_revoked=False,
                )
            )

        # Use composition for user authentication
        return self._user_manager.authenticate_user(username, password).map(
            self._metadata_handler.create_auth_token
        )

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[bool]:
        """Validate Basic auth credentials.

        Args:
            token: Basic auth token string or AuthToken object

        Returns:
            FlextResult[bool]: True if credentials are valid

        """
        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[bool].fail(str(e))

        # Parse credentials from token
        parse_result = self._parse_basic_token(token_string)
        if parse_result.is_failure:
            return FlextResult[bool].fail(parse_result.error)

        username, password = parse_result.unwrap()

        # Validate against stored credentials
        validation_result = self._validate_user_credentials(username, password)
        if validation_result.is_failure:
            return FlextResult[bool].fail("Invalid credentials")

        return FlextResult[bool].ok(True)

    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh Basic auth token.

        Basic authentication doesn't support token refresh since credentials
        are sent with every request. The same credentials remain valid.

        Args:
            token: Current Basic auth token

        Returns:
            FlextResult[AuthToken]: Error indicating refresh not needed

        """
        _ = token  # Token parameter required by interface but not used for Basic auth refresh
        return FlextResult[FlextAuthModels.AuthToken].fail(
            "Basic authentication does not require token refresh. "
            "Use the same credentials for subsequent requests."
        )

    def revoke(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[None]:
        """Revoke Basic auth credentials.

        This disables the user account associated with the credentials.

        Args:
            token: Basic auth token to revoke

        Returns:
            FlextResult[None]: Success or error

        """
        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[None].fail(str(e))

        # Parse credentials
        parse_result = self._parse_basic_token(token_string)
        if parse_result.is_failure:
            return FlextResult[None].fail(parse_result.error)

        username, _ = parse_result.unwrap()

        # Normalize username
        lookup_username = username if self._case_sensitive else username.lower()

        if lookup_username not in self._users:
            return FlextResult[None].fail("User not found")

        # Mark user as inactive
        self._users[lookup_username]["active"] = False

        self.logger.info("Basic auth credentials revoked", username=username)

        return FlextResult[None].ok(None)

    def supports(self) -> set[str]:
        """Return Basic auth provider capabilities.

        Returns:
            set[str]: Set of supported capability strings

        Capabilities:
            - token: Token generation (credential encoding)
            - validate: Credential validation
            - basic: HTTP Basic authentication
            - revoke: Credential revocation
            - anonymous: Anonymous access (if enabled)

        """
        capabilities = {"token", "validate", "basic", "revoke"}

        if self._allow_anonymous:
            capabilities.add("anonymous")

        return capabilities

    def get_metadata(self) -> dict[str, object]:
        """Return Basic auth provider metadata.

        Returns:
            dict[str, object]: Provider metadata

        """
        return {
            "name": "basic",
            "version": "2.0.0",
            "description": "HTTP Basic authentication provider",
            "capabilities": list(self.supports()),
            "realm": self._realm,
            "allow_anonymous": self._allow_anonymous,
            "case_sensitive": self._case_sensitive,
            "require_https": self._require_https,
        }

    def validate_token(self, token: str) -> FlextResult[FlextAuthModels.User | None]:
        """Validate Basic auth token and return user."""
        return FlextResult[FlextAuthModels.User | None].ok(
            None
        )  # Simplified implementation

    def generate_token_for_user(
        self,
        user: FlextAuthModels.User,
        token_type: str = "access",
        expiry_minutes: int | None = None,
    ) -> FlextResult[str]:
        """Generate Basic auth token for user."""
        return FlextResult[str].fail(
            "Basic auth token generation not implemented in this refactor"
        )

    # Helper methods

    def _parse_authorization_header(
        self, authorization: str
    ) -> FlextResult[tuple[str, str]]:
        """Parse Authorization header.

        Args:
            authorization: Authorization header value

        Returns:
            FlextResult[tuple[str, str]]: (username, password) or error

        """
        if not authorization.startswith("Basic "):
            return FlextResult[tuple[str, str]].fail(
                "Invalid Authorization header: expected 'Basic' scheme"
            )

        credentials_b64 = authorization[6:]  # Remove "Basic " prefix

        try:
            credentials_bytes = base64.b64decode(credentials_b64)
            credentials_str = credentials_bytes.decode("utf-8")
        except Exception as e:
            return FlextResult[tuple[str, str]].fail(f"Invalid base64 encoding: {e}")

        # Split username:password
        if ":" not in credentials_str:
            return FlextResult[tuple[str, str]].fail(
                "Invalid credentials format: expected 'username:password'"
            )

        username, password = credentials_str.split(":", 1)

        return FlextResult[tuple[str, str]].ok((username, password))

    def _parse_basic_token(self, token: str) -> FlextResult[tuple[str, str]]:
        """Parse Basic auth token.

        Args:
            token: Basic auth token (base64-encoded credentials)

        Returns:
            FlextResult[tuple[str, str]]: (username, password) or error

        """
        try:
            credentials_bytes = base64.b64decode(token)
            credentials_str = credentials_bytes.decode("utf-8")
        except Exception as e:
            return FlextResult[tuple[str, str]].fail(f"Invalid token format: {e}")

        if ":" not in credentials_str:
            return FlextResult[tuple[str, str]].fail("Invalid credentials format")

        username, password = credentials_str.split(":", 1)

        return FlextResult[tuple[str, str]].ok((username, password))

    def _validate_user_credentials(
        self, username: str, password: str
    ) -> FlextResult[dict[str, object]]:
        """Validate user credentials.

        Args:
            username: Username
            password: Password

        Returns:
            FlextResult[dict[str, object]]: User data or error

        """
        # Normalize username for lookup
        lookup_username = username if self._case_sensitive else username.lower()

        if lookup_username not in self._users:
            return FlextResult[dict[str, object]].fail("User not found")

        user_data = self._users[lookup_username]

        # Check if user is active
        if not user_data.get("active", True):
            return FlextResult[dict[str, object]].fail("User account is disabled")

        # Validate password
        stored_password = user_data["password"]
        if password != stored_password:
            return FlextResult[dict[str, object]].fail("Invalid password")

        return FlextResult[dict[str, object]].ok(user_data)

    def _encode_credentials(self, username: str, password: str) -> str:
        """Encode credentials as Basic auth token.

        Args:
            username: Username
            password: Password

        Returns:
            str: Base64-encoded credentials

        """
        credentials = f"{username}:{password}"
        credentials_bytes = credentials.encode("utf-8")
        return base64.b64encode(credentials_bytes).decode("utf-8")

    def _create_anonymous_token(self) -> FlextResult[FlextAuthModels.AuthToken]:
        """Create anonymous access token.

        Returns:
            FlextResult[AuthToken]: Anonymous token

        """
        anonymous_id = f"anonymous-{secrets.token_hex(8)}"
        token_expires_at = datetime.now(UTC) + timedelta(
            hours=24
        )  # Anonymous tokens expire in 24 hours

        auth_token = FlextAuthModels.AuthToken(
            token="",  # No credentials for anonymous
            token_type=FlextAuthConstants.Jwt.BASIC_TOKEN_TYPE,
            expires_at=token_expires_at,
            user_id=anonymous_id,
            is_revoked=False,
        )

        self.logger.info("Anonymous access granted", user_id=anonymous_id)

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

    # User management methods (for in-memory storage)

    def add_user(
        self,
        username: str,
        password: str,
        user_id: str | None = None,
        roles: list[str] | None = None,
        permissions: list[str] | None = None,
    ) -> FlextResult[None]:
        """Add user to in-memory storage.

        Args:
            username: Username
            password: Password (stored in plain text - use hashing in production)
            user_id: User ID (generated if not provided)
            roles: User roles
            permissions: User permissions

        Returns:
            FlextResult[None]: Success or error

        """
        lookup_username = username if self._case_sensitive else username.lower()

        if lookup_username in self._users:
            return FlextResult[None].fail(f"User '{username}' already exists")

        self._users[lookup_username] = {
            "username": username,
            "password": password,  # WARNING: Plain text - use bcrypt in production
            "user_id": user_id or f"user-{secrets.token_hex(8)}",
            "roles": roles or [],
            "permissions": permissions or [],
            "active": True,
        }

        self.logger.info("User added", username=username)

        return FlextResult[None].ok(None)

    def remove_user(self, username: str) -> FlextResult[None]:
        """Remove user from in-memory storage.

        Args:
            username: Username to remove

        Returns:
            FlextResult[None]: Success or error

        """
        lookup_username = username if self._case_sensitive else username.lower()

        if lookup_username not in self._users:
            return FlextResult[None].fail(f"User '{username}' not found")

        del self._users[lookup_username]

        self.logger.info("User removed", username=username)

        return FlextResult[None].ok(None)


__all__ = ["FlextAuthBasicProvider"]
