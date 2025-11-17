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

from flext_core import FlextLogger, FlextResult

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.providers.rfc import FlextAuthRfcProvider


class FlextAuthBasicProvider(FlextAuthRfcProvider):
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
        >>> provider.add_user("REDACTED_LDAP_BIND_PASSWORD", "secure-password", identity_id="REDACTED_LDAP_BIND_PASSWORD-001")
        >>> # Authenticate with Basic credentials
        >>> result = provider.authenticate({
        ...     "authorization": "Basic YWRtaW46c2VjdXJlLXBhc3N3b3Jk"
        ... })

    """

    def __init__(self, config: FlextAuthModels.ProviderConfiguration) -> None:
        """Initialize Basic Auth provider with SOLID delegation.

        Uses composition for credential validation, user management, and metadata handling.
        Railway-oriented initialization with proper error handling.
        """
        super().__init__()
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
        self._users: dict[str, dict[str, object]] = {}

        # Anonymous access configuration - fast fail if invalid type
        allow_anonymous_value = config.get("allow_anonymous")
        if allow_anonymous_value is not None and not isinstance(
            allow_anonymous_value, bool
        ):
            error_msg = (
                f"Basic Auth 'allow_anonymous' must be bool or None, "
                f"got {type(allow_anonymous_value).__name__}"
            )
            raise ValueError(error_msg)
        self._allow_anonymous = (
            allow_anonymous_value
            if isinstance(allow_anonymous_value, bool)
            else FlextAuthConstants.BasicAuth.ALLOW_ANONYMOUS_DEFAULT
        )

        # HTTP Basic Auth realm - fast fail if invalid type
        realm_value = config.get("realm")
        if realm_value is not None and not isinstance(realm_value, str):
            error_msg = (
                f"Basic Auth 'realm' must be str or None, "
                f"got {type(realm_value).__name__}"
            )
            raise ValueError(error_msg)
        if isinstance(realm_value, str) and realm_value:
            self._realm = realm_value
        else:
            self._realm = FlextAuthConstants.BasicAuth.REALM_DEFAULT

        # Case sensitivity for credential comparison - fast fail if invalid type
        case_sensitive_value = config.get("case_sensitive")
        if case_sensitive_value is not None and not isinstance(
            case_sensitive_value, bool
        ):
            error_msg = (
                f"Basic Auth 'case_sensitive' must be bool or None, "
                f"got {type(case_sensitive_value).__name__}"
            )
            raise ValueError(error_msg)
        self._case_sensitive = (
            case_sensitive_value
            if isinstance(case_sensitive_value, bool)
            else FlextAuthConstants.BasicAuth.CASE_SENSITIVE_DEFAULT
        )

        # HTTPS requirement for Basic Auth - fast fail if invalid type
        require_https_value = config.get("require_https")
        if require_https_value is not None and not isinstance(
            require_https_value, bool
        ):
            error_msg = (
                f"Basic Auth 'require_https' must be bool or None, "
                f"got {type(require_https_value).__name__}"
            )
            raise ValueError(error_msg)
        self._require_https = (
            require_https_value
            if isinstance(require_https_value, bool)
            else FlextAuthConstants.BasicAuth.REQUIRE_HTTPS_DEFAULT
        )

        self.logger.info("Basic Auth provider initialized")

    def is_case_sensitive(self) -> bool:
        """Get case sensitivity setting."""
        return self._case_sensitive

    def get_user_data(self, username: str) -> dict[str, object] | None:
        """Get user data by username."""
        return self._users.get(username)

    def _validate_configuration(self) -> FlextResult[bool]:
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
                return FlextResult[bool].fail(
                    f"{error_msg}. Got {type(field_value).__name__}"
                )

        return FlextResult[bool].ok(True)

    class _CredentialValidator:
        """SOLID-compliant credential validator.

        Single responsibility: validate Basic Auth credentials.
        """

        def __init__(self, provider: FlextAuthBasicProvider) -> None:
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

        def __init__(self, provider: FlextAuthBasicProvider) -> None:
            """Initialize user manager."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def authenticate_user(
            self, username: str, password: str
        ) -> FlextResult[dict[str, object]]:
            """Authenticate user against stored credentials."""
            # Check case sensitivity
            case_sensitive = self.provider.is_case_sensitive()
            lookup_username = username if case_sensitive else username.lower()

            # Look up user in storage
            user_data = self.provider.get_user_data(lookup_username)
            if not user_data:
                return FlextResult[dict[str, object]].fail("User not found")

            # Verify password (simplified - in production use proper password hashing)
            stored_password_value = user_data.get("password")
            if not isinstance(stored_password_value, str):
                return FlextResult[dict[str, object]].fail(
                    "User password not configured"
                )
            stored_password = stored_password_value
            if password != stored_password:
                return FlextResult[dict[str, object]].fail("Invalid password")

            return FlextResult[dict[str, object]].ok(user_data)

    class _MetadataHandler:
        """SOLID-compliant metadata handler.

        Single responsibility: handle authentication metadata.
        """

        def __init__(self, provider: FlextAuthBasicProvider) -> None:
            """Initialize metadata handler."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def create_auth_token(
            self, user_data: dict[str, object]
        ) -> FlextAuthModels.AuthToken:
            """Create authentication token from user data."""
            user_id_value = user_data.get("user_id")
            if not isinstance(user_id_value, str) or not user_id_value:
                msg = "User data missing required 'user_id' field"
                raise ValueError(msg)
            return FlextAuthModels.AuthToken(
                identity_id=user_id_value,
                token=secrets.token_hex(32),  # Generate random token
                token_type=FlextAuthConstants.TOKEN_TYPE_ACCESS,
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
        # Validate credentials dict structure
        validation_result = self._validate_credentials_dict(
            credentials, ["username", "password"]
        )
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation_result.error)

        username_value = credentials.get("username")
        if not isinstance(username_value, str) or not username_value:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Username must be a non-empty string"
            )
        username = username_value

        password_value = credentials.get("password")
        if not isinstance(password_value, str) or not password_value:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Password must be a non-empty string"
            )
        password = password_value

        # Use composition for user authentication
        return self._user_manager.authenticate_user(username, password).map(
            self._metadata_handler.create_auth_token
        )

    def _process_basic_authentication(
        self, credentials: tuple[str, str]
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Process Basic authentication result."""
        username, password = credentials

        # Handle anonymous access
        allow_anonymous_value = self._config.get("allow_anonymous")
        allow_anonymous = (
            isinstance(allow_anonymous_value, bool) and allow_anonymous_value
        )
        if allow_anonymous and not username:
            return FlextResult[FlextAuthModels.AuthToken].ok(
                FlextAuthModels.AuthToken(
                    identity_id="anonymous",
                    token="anonymous",
                    token_type=FlextAuthConstants.TOKEN_TYPE_ACCESS,
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
    ) -> FlextResult[bool]:
        """Revoke Basic auth credentials.

        This disables the user account associated with the credentials.

        Args:
        token: Basic auth token to revoke

        Returns:
        FlextResult[bool]: Success or error

        """
        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[bool].fail(str(e))

        # Parse credentials
        parse_result = self._parse_basic_token(token_string)
        if parse_result.is_failure:
            return FlextResult[bool].fail(parse_result.error)

        username, _ = parse_result.unwrap()

        # Normalize username
        lookup_username = username if self._case_sensitive else username.lower()

        if lookup_username not in self._users:
            return FlextResult[bool].fail("User not found")

        # Mark user as inactive
        self._users[lookup_username]["active"] = False

        self.logger.info("Basic auth credentials revoked", username=username)

        return FlextResult[bool].ok(True)

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
        config = FlextAuthModels.ProviderConfiguration(
            name="basic",
            type="http_basic",
            enabled=True,
            version="2.0.0",
            description="HTTP Basic authentication provider",
            capabilities=list(self.supports()),
            realm=self._realm,
            allow_anonymous=self._allow_anonymous,
            case_sensitive=self._case_sensitive,
            require_https=self._require_https,
        )
        return dict(config)

    def validate_token(self, token: str) -> FlextResult[FlextAuthModels.Identity]:
        """Validate Basic auth token and return user."""
        # Basic auth token validation requires implementation
        # Fast fail: implementation not available
        _ = token  # Mark as intentionally unused
        return FlextResult[FlextAuthModels.Identity].fail(
            "Basic auth token validation not implemented"
        )

    def generate_token_for_user(
        self,
        _user: FlextAuthModels.Identity,
        _token_type: str = FlextAuthConstants.TOKEN_TYPE_ACCESS,
        _expiry_minutes: int | None = None,
    ) -> FlextResult[str]:
        """Generate Basic auth token for user."""
        # User, token type, and expiry are currently unused because Basic authentication
        # does not issue bearer tokens. Return explicit error with context.
        return FlextResult[str].fail(
            "Basic auth token generation is not supported (type "
            f"{_token_type}, expiry={_expiry_minutes})"
        )

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (e.g., "RFC 7617", "RFC 6749")

        """
        return "RFC 7617"

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
        active_value = user_data.get("active")
        if isinstance(active_value, bool) and not active_value:
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
            hours=FlextAuthConstants.BasicAuth.ANONYMOUS_TOKEN_EXPIRY_HOURS
        )

        auth_token = FlextAuthModels.AuthToken(
            token="",  # No credentials for anonymous
            token_type=FlextAuthConstants.TOKEN_TYPE_ACCESS,
            expires_at=token_expires_at,
            identity_id=anonymous_id,
            is_revoked=False,
        )

        self.logger.info("Anonymous access granted", identity_id=anonymous_id)

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

    # User management methods (for in-memory storage)

    def add_user(
        self,
        username: str,
        password: str,
        user_id: str | None = None,
        roles: list[str] | None = None,
        permissions: list[str] | None = None,
    ) -> FlextResult[bool]:
        """Add user to in-memory storage.

        Args:
        username: Username
        password: Password (stored in plain text - use hashing in production)
        user_id: User ID (generated if not provided)
        roles: User roles
        permissions: User permissions

        Returns:
        FlextResult[bool]: Success or error

        """
        lookup_username = username if self._case_sensitive else username.lower()

        if lookup_username in self._users:
            return FlextResult[bool].fail(f"User '{username}' already exists")

        if roles is None:
            user_roles: list[str] = []
        else:
            if not isinstance(roles, list):
                return FlextResult[bool].fail("Roles must be a list")
            user_roles = roles

        if permissions is None:
            user_permissions: list[str] = []
        else:
            if not isinstance(permissions, list):
                return FlextResult[bool].fail("Permissions must be a list")
            user_permissions = permissions

        if user_id is None:
            return FlextResult[bool].fail("user_id is required")
        if not isinstance(user_id, str) or not user_id:
            return FlextResult[bool].fail("user_id must be a non-empty string")
        final_user_id = user_id
        self._users[lookup_username] = {
            "username": username,
            "password": password,  # Warning: Plain text - use bcrypt in production
            "user_id": final_user_id,
            "roles": user_roles,
            "permissions": user_permissions,
            "active": True,
        }

        self.logger.info("User added", username=username)

        return FlextResult[bool].ok(True)

    def remove_user(self, username: str) -> FlextResult[bool]:
        """Remove user from in-memory storage.

        Args:
        username: Username to remove

        Returns:
        FlextResult[bool]: Success or error

        """
        lookup_username = username if self._case_sensitive else username.lower()

        if lookup_username not in self._users:
            return FlextResult[bool].fail(f"User '{username}' not found")

        del self._users[lookup_username]

        self.logger.info("User removed", username=username)

        return FlextResult[bool].ok(True)


__all__ = ["FlextAuthBasicProvider"]
