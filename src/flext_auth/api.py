"""FLEXT Auth API - Thin facade exposing all authentication functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime

from flext_core import (
    FlextLogger,
    FlextResult,
    FlextService,
)

from flext_auth.config import FlextAuthConfig
from flext_auth.managers import (
    FlextAuthAuditLogger,
    FlextAuthRateLimiter,
    FlextAuthSessionManager,
    FlextAuthUserManager,
)
from flext_auth.middleware import (
    FlextAuthHttpMiddleware,
    FlextAuthMiddleware,
    FlextAuthWebMiddleware,
)
from flext_auth.models import FlextAuthModels
from flext_auth.providers import (
    ApiKeyAuthProvider,
    BasicAuthProvider,
    CertificateAuthProvider,
    JwtAuthProvider,
    KerberosAuthProvider,
    LdapAuthProvider,
    OAuth2AuthProvider,
    OidcAuthProvider,
    SamlAuthProvider,
)
from flext_auth.providers.base import BaseAuthProvider
from flext_auth.registry import FlextAuthProviderRegistry
from flext_auth.utilities import FlextAuthUtilities


class FlextAuth(FlextService):
    """Main authentication service providing comprehensive auth functionality.

    This service integrates all authentication providers, manages user sessions,
    handles token operations, and provides middleware for web frameworks.

    Features:
    - Multi-provider authentication (Basic, JWT, LDAP, OAuth2, SAML, etc.)
    - User management and session handling
    - Token creation, validation, and refresh
    - Password hashing and verification
    - Audit logging and security monitoring
    - Rate limiting and brute force protection
    """

    def __init__(self, config: FlextAuthConfig | None = None) -> None:
        """Initialize the authentication service.

        Args:
            config: Authentication configuration. If None, uses global config.

        """
        super().__init__()

        # Initialize configuration
        self.config = config or FlextAuthConfig.get_global_instance()

        # Initialize logger
        self._logger = FlextLogger(__name__)

        # Initialize providers registry
        self._providers = FlextAuthProviderRegistry()

        # Initialize user manager
        self._user_manager = FlextAuthUserManager(self.config)

        # Initialize session manager
        self._session_manager = FlextAuthSessionManager(self.config)

        # Initialize audit logger
        self._audit_logger = FlextAuthAuditLogger(self.config)

        # Register built-in providers
        self._register_builtin_providers()

        # Initialize rate limiter
        self._rate_limiter = FlextAuthRateLimiter(self.config)

        # Initialize middleware
        self._middleware = FlextAuthMiddleware(self)

        # Initialize utilities
        self._utils = FlextAuthUtilities(self.config)

    def _get_params_from_context(self) -> dict[str, object]:
        """Get params from context or return empty dict."""
        # For now, return empty params
        # In a real implementation, this would get the params from the request context
        return {}

    def _register_builtin_providers(self) -> None:
        """Register all built-in authentication providers."""
        # Basic authentication
        basic_provider = BasicAuthProvider(self.config)
        self._providers.register("basic", basic_provider)

        # JWT authentication
        jwt_provider = JwtAuthProvider(self.config)
        self._providers.register("jwt", jwt_provider)

        # LDAP authentication (if configured)
        if hasattr(self.config, "ldap_enabled") and self.config.ldap_enabled:
            ldap_provider = LdapAuthProvider(self.config)
            self._providers.register("ldap", ldap_provider)

        # OAuth2 authentication
        oauth2_provider = OAuth2AuthProvider(self.config)
        self._providers.register("oauth2", oauth2_provider)

        # OIDC authentication
        oidc_provider = OidcAuthProvider(self.config)
        self._providers.register("oidc", oidc_provider)

        # SAML authentication
        saml_provider = SamlAuthProvider(self.config)
        self._providers.register("saml", saml_provider)

        # Kerberos authentication
        kerberos_provider = KerberosAuthProvider(self.config)
        self._providers.register("kerberos", kerberos_provider)

        # Certificate authentication
        cert_provider = CertificateAuthProvider(self.config)
        self._providers.register("certificate", cert_provider)

        # API Key authentication
        apikey_provider = ApiKeyAuthProvider(self.config)
        self._providers.register("apikey", apikey_provider)

    # User Management Methods
    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        **extra_fields: object,
    ) -> FlextResult[FlextAuthModels.User]:
        """Create a new user account.

        Args:
            username: Unique username for the user
            email: User's email address
            password: Plain text password (will be hashed)
            **extra_fields: Additional user fields

        Returns:
            FlextResult containing the created User or error

        """
        return self._user_manager.create_user(
            username=username,
            email=email,
            password=password,
            **extra_fields,
        )

    def get_user(self, user_id: str) -> FlextResult[FlextAuthModels.User]:
        """Get user by ID.

        Args:
            user_id: User identifier

        Returns:
            FlextResult containing the User or error

        """
        return self._user_manager.get_user(user_id)

    def get_user_by_username(self, username: str) -> FlextResult[FlextAuthModels.User]:
        """Get user by username.

        Args:
            username: Username to search for

        Returns:
            FlextResult containing the User or error

        """
        return self._user_manager.get_user_by_username(username)

    def update_user(
        self,
        user_id: str,
        **updates: object,
    ) -> FlextResult[FlextAuthModels.User]:
        """Update user information.

        Args:
            user_id: User identifier
            **updates: Fields to update

        Returns:
            FlextResult containing the updated User or error

        """
        return self._user_manager.update_user(user_id, **updates)

    def delete_user(self, user_id: str) -> FlextResult[None]:
        """Delete a user account.

        Args:
            user_id: User identifier to delete

        Returns:
            FlextResult indicating success or error

        """
        return self._user_manager.delete_user(user_id)

    def authenticate_user(
        self,
        username: str,
        password: str,
        provider: str = "basic",
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate a user with username/password.

        Args:
            username: User's username
            password: User's password
            provider: Authentication provider to use

        Returns:
            FlextResult containing AuthToken or error

        """
        # Check rate limiting
        rate_limit_result = self._rate_limiter.check_rate_limit(username)
        if rate_limit_result.is_failure:
            self._audit_logger.log_auth_failure(
                username=username,
                reason="rate_limited",
                provider=provider,
            )
            return rate_limit_result

        # Get the authentication provider
        provider_result = self._providers.get_provider(provider)
        if provider_result.is_failure:
            return provider_result

        auth_provider = provider_result.value

        # Attempt authentication
        auth_result = auth_provider.authenticate(username, password)

        # Log the attempt
        if auth_result.is_success:
            self._audit_logger.log_auth_success(
                username=username,
                provider=provider,
            )
            # Create session
            session_result = self._session_manager.create_session(
                user_id=auth_result.value.user_id,
                username=username,
            )
            if session_result.is_success:
                # Update token with session info
                auth_result.value.session_id = session_result.value.session_id
        else:
            self._audit_logger.log_auth_failure(
                username=username,
                reason=str(auth_result.error),
                provider=provider,
            )
            # Record failed attempt for rate limiting
            self._rate_limiter.record_failed_attempt(username)

        return auth_result

    def validate_token(self, token: str) -> FlextResult[FlextAuthModels.User]:
        """Validate an authentication token.

        Args:
            token: JWT token to validate

        Returns:
            FlextResult containing the authenticated User or error

        """
        # Use JWT provider for validation
        jwt_provider_result = self._providers.get_provider("jwt")
        if jwt_provider_result.is_failure:
            return jwt_provider_result

        jwt_provider = jwt_provider_result.value
        validation_result = jwt_provider.validate_token(token)

        if validation_result.is_success:
            self._audit_logger.log_token_validation(
                token_id=token[:10] + "...",  # Log partial token for tracking
                success=True,
            )
        else:
            self._audit_logger.log_token_validation(
                token_id=token[:10] + "..." if token else "unknown",
                success=False,
                reason=str(validation_result.error),
            )

        return validation_result

    def refresh_token(self, token: str) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh an authentication token.

        Args:
            token: Current valid token to refresh

        Returns:
            FlextResult containing new AuthToken or error

        """
        # Use JWT provider for refresh
        jwt_provider_result = self._providers.get_provider("jwt")
        if jwt_provider_result.is_failure:
            return jwt_provider_result

        jwt_provider = jwt_provider_result.value
        refresh_result = jwt_provider.refresh_token(token)

        if refresh_result.is_success:
            self._audit_logger.log_token_refresh(
                old_token_id=token[:10] + "...",
                new_token_id=refresh_result.value.token[:10] + "...",
                success=True,
            )
        else:
            self._audit_logger.log_token_refresh(
                old_token_id=token[:10] + "..." if token else "unknown",
                new_token_id=None,
                success=False,
                reason=str(refresh_result.error),
            )

        return refresh_result

    def logout_user(self, token: str) -> FlextResult[None]:
        """Logout a user by invalidating their session.

        Args:
            token: User's authentication token

        Returns:
            FlextResult indicating success or error

        """
        # Validate token first
        validation_result = self.validate_token(token)
        if validation_result.is_failure:
            return FlextResult.fail(f"Invalid token: {validation_result.error}")

        user = validation_result.value

        # End session
        session_result = self._session_manager.end_session(user.user_id)
        if session_result.is_failure:
            return session_result

        # Log logout
        self._audit_logger.log_user_logout(user.username)

        return FlextResult.ok(None)

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> FlextResult[None]:
        """Change a user's password.

        Args:
            user_id: User identifier
            current_password: Current password for verification
            new_password: New password to set

        Returns:
            FlextResult indicating success or error

        """
        # Get user
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return user_result

        user = user_result.value

        # Verify current password
        verify_result = user.verify_password(current_password)
        if verify_result.is_failure or not verify_result.value:
            self._audit_logger.log_password_change_failure(
                username=user.username,
                reason="invalid_current_password",
            )
            return FlextResult.fail("Current password is incorrect")

        # Validate new password
        validation_result = self._utils.validate_password(new_password)
        if validation_result.is_failure:
            return validation_result

        # Set new password
        set_result = user.set_password(new_password)
        if set_result.is_failure:
            return set_result

        # Log success
        self._audit_logger.log_password_change_success(user.username)

        return FlextResult.ok(None)

    def reset_password(self, user_id: str, new_password: str) -> FlextResult[None]:
        """Reset a user's password (REDACTED_LDAP_BIND_PASSWORD operation).

        Args:
            user_id: User identifier
            new_password: New password to set

        Returns:
            FlextResult indicating success or error

        """
        # Get user
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return user_result

        user = user_result.value

        # Validate new password
        validation_result = self._utils.validate_password(new_password)
        if validation_result.is_failure:
            return validation_result

        # Set new password
        set_result = user.set_password(new_password)
        if set_result.is_failure:
            return set_result

        # Log reset
        self._audit_logger.log_password_reset(user.username)

        return FlextResult.ok(None)

    def authorize_user(
        self,
        user_id: str,
        permission: str,
        resource: str | None = None,
    ) -> FlextResult[bool]:
        """Check if a user has a specific permission.

        Args:
            user_id: User identifier
            permission: Permission to check
            resource: Optional resource context

        Returns:
            FlextResult containing boolean authorization result

        """
        # Get user
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return user_result

        user = user_result.value

        # Check permission
        auth_result = self._utils.check_permission(user, permission, resource)

        # Log authorization check
        self._audit_logger.log_authorization_check(
            username=user.username,
            permission=permission,
            resource=resource,
            granted=auth_result.value if auth_result.is_success else False,
        )

        return auth_result

    def get_user_permissions(self, user_id: str) -> FlextResult[list[str]]:
        """Get all permissions for a user.

        Args:
            user_id: User identifier

        Returns:
            FlextResult containing list of permission strings

        """
        # Get user
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return user_result

        user = user_result.value

        return FlextResult.ok(user.permissions)

    def get_user_roles(self, user_id: str) -> FlextResult[list[str]]:
        """Get all roles for a user.

        Args:
            user_id: User identifier

        Returns:
            FlextResult containing list of role strings

        """
        # Get user
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return user_result

        user = user_result.value

        return FlextResult.ok(user.roles)

    def add_user_role(self, user_id: str, role: str) -> FlextResult[None]:
        """Add a role to a user.

        Args:
            user_id: User identifier
            role: Role to add

        Returns:
            FlextResult indicating success or error

        """
        return self._user_manager.add_user_role(user_id, role)

    def remove_user_role(self, user_id: str, role: str) -> FlextResult[None]:
        """Remove a role from a user.

        Args:
            user_id: User identifier
            role: Role to remove

        Returns:
            FlextResult indicating success or error

        """
        return self._user_manager.remove_user_role(user_id, role)

    def add_user_permission(self, user_id: str, permission: str) -> FlextResult[None]:
        """Add a permission to a user.

        Args:
            user_id: User identifier
            permission: Permission to add

        Returns:
            FlextResult indicating success or error

        """
        return self._user_manager.add_user_permission(user_id, permission)

    def remove_user_permission(
        self, user_id: str, permission: str
    ) -> FlextResult[None]:
        """Remove a permission from a user.

        Args:
            user_id: User identifier
            permission: Permission to remove

        Returns:
            FlextResult indicating success or error

        """
        return self._user_manager.remove_user_permission(user_id, permission)

    # Session Management Methods
    def get_active_sessions(
        self, user_id: str
    ) -> FlextResult[list[FlextAuthModels.Session]]:
        """Get all active sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            FlextResult containing list of active sessions

        """
        return self._session_manager.get_active_sessions(user_id)

    def end_session(self, session_id: str) -> FlextResult[None]:
        """End a specific session.

        Args:
            session_id: Session identifier

        Returns:
            FlextResult indicating success or error

        """
        return self._session_manager.end_session_by_id(session_id)

    def end_all_sessions(self, user_id: str) -> FlextResult[None]:
        """End all sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            FlextResult indicating success or error

        """
        return self._session_manager.end_all_sessions(user_id)

    # Middleware and Integration Methods
    @property
    def middleware(self) -> FlextAuthMiddleware:
        """Get the authentication middleware."""
        return self._middleware

    def get_http_middleware(self) -> FlextAuthHttpMiddleware:
        """Get HTTP middleware for web frameworks."""
        return FlextAuthHttpMiddleware(self)

    def get_web_middleware(self) -> FlextAuthWebMiddleware:
        """Get web middleware for web frameworks."""
        return FlextAuthWebMiddleware(self)

    # Provider Management Methods
    def register_provider(
        self, name: str, provider: BaseAuthProvider
    ) -> FlextResult[None]:
        """Register a custom authentication provider.

        Args:
            name: Provider name
            provider: Provider instance

        Returns:
            FlextResult indicating success or error

        """
        return self._providers.register(name, provider)

    def get_provider(self, name: str) -> FlextResult[BaseAuthProvider]:
        """Get a registered authentication provider.

        Args:
            name: Provider name

        Returns:
            FlextResult containing the provider or error

        """
        return self._providers.get_provider(name)

    def list_providers(self) -> list[str]:
        """List all registered provider names."""
        return self._providers.list_providers()

    # Utility Methods
    def hash_password(self, password: str) -> FlextResult[str]:
        """Hash a password.

        Args:
            password: Plain text password

        Returns:
            FlextResult containing hashed password

        """
        return self._utils.hash_password(password)

    def verify_password_hash(self, password: str, hashed: str) -> FlextResult[bool]:
        """Verify a password against its hash.

        Args:
            password: Plain text password
            hashed: Hashed password

        Returns:
            FlextResult containing boolean verification result

        """
        return self._utils.verify_password_hash(password, hashed)

    def generate_secure_token(self, length: int = 32) -> str:
        """Generate a secure random token.

        Args:
            length: Token length in bytes

        Returns:
            Secure random token string

        """
        return self._utils.generate_secure_token(length)

    def validate_password_strength(
        self, password: str
    ) -> FlextResult[dict[str, object]]:
        """Validate password strength.

        Args:
            password: Password to validate

        Returns:
            FlextResult containing validation results

        """
        return self._utils.validate_password_strength(password)

    # Audit and Monitoring Methods
    def get_audit_logs(
        self,
        user_id: str | None = None,
        event_type: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
    ) -> FlextResult[list[FlextAuthModels.AuditLog]]:
        """Get audit logs with optional filtering.

        Args:
            user_id: Filter by user ID
            event_type: Filter by event type
            start_date: Filter from this date
            end_date: Filter to this date
            limit: Maximum number of logs to return

        Returns:
            FlextResult containing list of audit logs

        """
        return self._audit_logger.get_logs(
            user_id=user_id,
            event_type=event_type,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )

    def get_security_stats(self) -> FlextResult[dict[str, object]]:
        """Get security statistics.

        Returns:
            FlextResult containing security statistics

        """
        return FlextResult.ok({
            "active_sessions": self._session_manager.get_total_active_sessions(),
            "failed_login_attempts": self._rate_limiter.get_total_failed_attempts(),
            "audit_log_entries": self._audit_logger.get_total_log_entries(),
        })

    # Async Methods for Future Use
    async def authenticate_user_async(
        self,
        username: str,
        password: str,
        provider: str = "basic",
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Async version of authenticate_user."""
        # For now, delegate to sync version
        # In the future, this could use async providers
        return self.authenticate_user(username, password, provider)

    async def validate_token_async(
        self, token: str
    ) -> FlextResult[FlextAuthModels.User]:
        """Async version of validate_token."""
        return self.validate_token(token)

    async def refresh_token_async(
        self, token: str
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Async version of refresh_token."""
        return self.refresh_token(token)

    # Message-based API for advanced integrations
    def handle_message(self, message: dict[str, object]) -> FlextResult[object]:
        """Handle a message-based authentication request.

        Args:
            message: Message dictionary with operation and params

        Returns:
            FlextResult containing operation result

        """
        operation = message.get("operation", "")

        match operation:
            case "authenticate":
                username = message.get("username", "")
                password = message.get("password", "")
                provider = message.get("provider", "basic")
                return self.authenticate_user(
                    str(username), str(password), str(provider)
                )

            case "validate_token":
                token = message.get("token", "")
                return self.validate_token(str(token))

            case "refresh_token":
                token = message.get("token", "")
                return self.refresh_token(str(token))

            case "create_user":
                username = message.get("username", "")
                email = message.get("email", "")
                password = message.get("password", "")
                return self.create_user(str(username), str(email), str(password))

            case "get_user":
                user_id = message.get("user_id", "")
                return self.get_user(str(user_id))

            case "logout":
                token = message.get("token", "")
                return self.logout_user(str(token))

            case "change_password":
                user_id = message.get("user_id", "")
                current_password = message.get("current_password", "")
                new_password = message.get("new_password", "")
                return self.change_password(
                    str(user_id), str(current_password), str(new_password)
                )

            case _:
                return FlextResult.fail(f"Unknown operation: {operation}")

    async def handle_message_async(
        self, message: dict[str, object]
    ) -> FlextResult[object]:
        """Async version of handle_message."""
        operation = message.get("operation", "")

        match operation:
            case "authenticate":
                username = message.get("username", "")
                password = message.get("password", "")
                provider = message.get("provider", "basic")
                return await self.authenticate_user_async(
                    str(username), str(password), str(provider)
                )

            case "validate_token":
                token = message.get("token", "")
                return await self.validate_token_async(str(token))

            case "refresh_token":
                token = message.get("token", "")
                return await self.refresh_token_async(str(token))

            case "create_user":
                username = message.get("username", "")
                email = message.get("email", "")
                password = message.get("password", "")
                return self.create_user(str(username), str(email), str(password))

            case "get_user":
                user_id = message.get("user_id", "")
                return self.get_user(str(user_id))

            case "logout":
                token = message.get("token", "")
                return self.logout_user(str(token))

            case "change_password":
                user_id = message.get("user_id", "")
                current_password = message.get("current_password", "")
                new_password = message.get("new_password", "")
                return self.change_password(
                    str(user_id), str(current_password), str(new_password)
                )

            case _:
                return FlextResult.fail(f"Unknown operation: {operation}")

    # Logging initialization
    self._logger.info(
        f"FlextAuth initialized: token_expire_minutes={self.config.jwt_expiry_minutes}, "
        f"bcrypt_rounds={self.config.bcrypt_rounds}, jwt_secret_length={len(str(self.config.jwt_auth_secret.get_secret_value()))}"
    )


# Module exports
__all__ = [
    "FlextAuth",
]
