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
from flext_auth.providers.base import BaseAuthProvider, BaseAuthProviderMixin


class BasicAuthProvider(BaseAuthProvider, BaseAuthProviderMixin):
    """HTTP Basic authentication provider.

    This provider implements HTTP Basic Authentication (RFC 7617) for simple
    username/password authentication over HTTP.

    Configuration:
        - realm: Authentication realm name (default: "Restricted")
        - allow_anonymous: Allow anonymous access (default: False)
        - case_sensitive: Case-sensitive username matching (default: True)
        - user_store: User storage mechanism ('memory', 'database') (default: 'memory')
        - require_https: Require HTTPS for authentication (default: True)

    Security Notes:
        - Credentials are transmitted as base64-encoded strings (NOT encrypted)
        - MUST use HTTPS in production to protect credentials
        - Basic auth credentials are sent with EVERY request
        - No built-in logout mechanism (credentials cached by browser)
        - Consider using for internal APIs or development only

    Example:
        >>> config = {
        ...     "realm": "My API",
        ...     "require_https": True,
        ...     "case_sensitive": True,
        ... }
        >>> provider = BasicAuthProvider(config)
        >>> # Register user credentials
        >>> provider.add_user("REDACTED_LDAP_BIND_PASSWORD", "secure-password", user_id="REDACTED_LDAP_BIND_PASSWORD-001")
        >>> # Authenticate with Basic credentials
        >>> result = provider.authenticate({
        ...     "authorization": "Basic YWRtaW46c2VjdXJlLXBhc3N3b3Jk"
        ... })

    """

    def __init__(self, config: FlextTypes.Dict) -> None:
        """Initialize HTTP Basic authentication provider.

        Args:
            config: Provider configuration dictionary

        """
        self._config = config
        self._logger = FlextLogger(__name__)

        # Configuration with defaults
        self._realm = self._config.get("realm", "Restricted")
        self._allow_anonymous = self._config.get("allow_anonymous", False)
        self._case_sensitive = self._config.get("case_sensitive", True)
        self._user_store = self._config.get("user_store", "memory")
        self._require_https = self._config.get("require_https", True)

        # In-memory user storage (for development/testing)
        # In production, integrate with user database or directory service
        self._users: FlextTypes.NestedDict = {}  # username -> user data

        self._logger.info(
            "Basic Auth provider initialized",
            extra={
                "realm": self._realm,
                "allow_anonymous": self._allow_anonymous,
                "case_sensitive": self._case_sensitive,
                "require_https": self._require_https,
            },
        )

    def authenticate(
        self,
        credentials: FlextTypes.Dict,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate using HTTP Basic credentials.

        Args:
            credentials: Must contain 'authorization' header with Basic auth credentials
                        Optional: 'request_url' to validate HTTPS requirement

        Returns:
            FlextResult[AuthToken]: Authentication token or error

        Example:
            >>> result = provider.authenticate({
            ...     "authorization": "Basic dXNlcjpwYXNz",
            ...     "request_url": "https://api.example.com/endpoint",
            ... })

        """
        # Validate required fields
        validation_result = self._validate_credentials_dict(
            credentials, ["authorization"]
        )
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation_result.error)

        authorization = credentials["authorization"]
        request_url = credentials.get("request_url", "")

        # Check HTTPS requirement
        if (
            self._require_https
            and request_url
            and not request_url.startswith("https://")
        ):
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Basic authentication requires HTTPS"
            )

        # Parse Authorization header
        parse_result = self._parse_authorization_header(authorization)
        if parse_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(parse_result.error)

        username, password = parse_result.unwrap()

        # Handle anonymous access
        if self._allow_anonymous and not username and not password:
            return self._create_anonymous_token()

        # Validate credentials
        validation_result = self._validate_user_credentials(username, password)
        if validation_result.is_failure:
            self._logger.warning(
                "Authentication failed",
                extra={"username": username, "reason": validation_result.error},
            )
            return FlextResult[FlextAuthModels.AuthToken].fail("Invalid credentials")

        user_data = validation_result.unwrap()

        # Create authentication token
        # Basic auth doesn't naturally expire, but we need a far-future date for the model
        token_expires_at = datetime.now(UTC) + timedelta(days=365 * 10)

        auth_token = FlextAuthModels.AuthToken(
            token=self._encode_credentials(
                username, password
            ),  # Basic token is the credentials
            token_type=FlextAuthConstants.Jwt.BASIC_TOKEN_TYPE,
            expires_at=token_expires_at,
            user_id=user_data["user_id"],
            # Additional metadata stored as extra fields
            username=username,
            realm=self._realm,
            roles=user_data.get("roles", []),
            permissions=user_data.get("permissions", []),
            auth_method="basic",
        )

        self._logger.info(
            "Basic authentication successful",
            extra={"username": username, "user_id": user_data["user_id"]},
        )

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

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
        _token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh Basic auth token.

        Basic authentication doesn't support token refresh since credentials
        are sent with every request. The same credentials remain valid.

        Args:
            token: Current Basic auth token

        Returns:
            FlextResult[AuthToken]: Error indicating refresh not needed

        """
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

        self._logger.info(
            "Basic auth credentials revoked", extra={"username": username}
        )

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

    def get_metadata(self) -> FlextTypes.Dict:
        """Return Basic auth provider metadata.

        Returns:
            FlextTypes.Dict: Provider metadata

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
    ) -> FlextResult[FlextTypes.Dict]:
        """Validate user credentials.

        Args:
            username: Username
            password: Password

        Returns:
            FlextResult[FlextTypes.Dict]: User data or error

        """
        # Normalize username for lookup
        lookup_username = username if self._case_sensitive else username.lower()

        if lookup_username not in self._users:
            return FlextResult[FlextTypes.Dict].fail("User not found")

        user_data = self._users[lookup_username]

        # Check if user is active
        if not user_data.get("active", True):
            return FlextResult[FlextTypes.Dict].fail("User account is disabled")

        # Validate password
        stored_password = user_data["password"]
        if password != stored_password:
            return FlextResult[FlextTypes.Dict].fail("Invalid password")

        return FlextResult[FlextTypes.Dict].ok(user_data)

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
            # Additional metadata
            username="anonymous",
            realm=self._realm,
            anonymous=True,
            roles=["anonymous"],
            permissions=[],
            auth_method="basic",
        )

        self._logger.info("Anonymous access granted", extra={"user_id": anonymous_id})

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

    # User management methods (for in-memory storage)

    def add_user(
        self,
        username: str,
        password: str,
        user_id: str | None = None,
        roles: FlextTypes.StringList | None = None,
        permissions: FlextTypes.StringList | None = None,
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

        self._logger.info("User added", extra={"username": username})

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

        self._logger.info("User removed", extra={"username": username})

        return FlextResult[None].ok(None)


__all__ = ["BasicAuthProvider"]
