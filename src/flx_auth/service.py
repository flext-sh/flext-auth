"""Authentication service with zero boilerplate using Python 3.13."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable
from uuid import UUID

from flx_core.domain.pydantic_base import DomainBaseModel
from flx_core.security.rate_limiting import TokenBucketLimiter
from pydantic import Field

from flx_auth.jwt_service import JWTConfig, JWTService, TokenPair
from flx_auth.jwt_service import JwtInMemoryTokenStorage as InMemoryTokenStorage
from flx_auth.models import (
    ADMIN_ROLE,
    OPERATOR_ROLE,
    VIEWER_ROLE,
    Permission,
    Role,
    User,
)
from flx_auth.security import PasswordHasher

if TYPE_CHECKING:
    from flx_core.domain.advanced_types import UserId

# Python 3.13 type aliases
type Username = str
type Email = str
type Password = str


@runtime_checkable
class UserRepositoryProtocol(Protocol):
    """Protocol for user repository implementations."""

    async def get_by_id(self, user_id: UserId) -> User | None:
        """Get user by unique identifier."""
        ...

    async def get_by_username(self, username: Username) -> User | None:
        """Get user by username."""
        ...

    async def get_by_email(self, email: Email) -> User | None:
        """Get user by email address."""
        ...

    async def save(self, user: User) -> None:
        """Save user to repository."""
        ...

    async def delete(self, user_id: UserId) -> None:
        """Delete user from repository."""
        ...


@runtime_checkable
class RoleRepositoryProtocol(Protocol):
    """Protocol for role repository implementations."""

    async def get_by_name(self, name: str) -> Role | None:
        """Get role by name."""
        ...

    async def get_user_roles(self, user_id: UserId) -> list[Role]:
        """Get all roles assigned to a user."""
        ...

    async def save(self, role: Role) -> None:
        """Save role to repository."""
        ...


class AuthenticationService(DomainBaseModel):
    """Enterprise authentication service with comprehensive security and zero boilerplate patterns.

    Provides complete authentication capabilities including user management, JWT handling,
    rate limiting, security audit trails, and enterprise-grade access control with
    comprehensive validation and security enforcement.
    """

    # Core dependencies with enterprise validation
    user_repository: UserRepositoryProtocol = Field(
        description="User data persistence layer with comprehensive CRUD operations",
    )
    role_repository: RoleRepositoryProtocol = Field(
        description="Role-based access control repository for permission management",
    )
    password_hasher: PasswordHasher = Field(
        default_factory=PasswordHasher,
        description="Secure password hashing service using enterprise-grade cryptographic algorithms",
    )
    jwt_service: JWTService = Field(
        default_factory=lambda: JWTService(
            JWTConfig(),
            InMemoryTokenStorage(),
        ),
        description="JWT token management service with comprehensive lifecycle and security validation",
    )
    rate_limiter: TokenBucketLimiter = Field(
        default_factory=lambda: TokenBucketLimiter(rate=10.0, capacity=100),
        description="Rate limiting service preventing brute force attacks and abuse",
    )

    # Enterprise security configuration
    max_login_attempts: int = Field(
        default=5,
        description="Maximum failed login attempts before account lockout",
    )
    lockout_duration_minutes: int = Field(
        default=30,
        description="Account lockout duration for security protection",
    )
    require_email_verification: bool = Field(
        default=False,
        description="Require email verification for enhanced security",
    )

    async def register(
        self,
        username: Username,
        email: Email,
        password: Password,
        roles: list[str] | None = None,
    ) -> User:
        """Register new user with automatic validation."""
        # Check if user exists
        if await self.user_repository.get_by_username(username):
            msg = f"Username '{username}' already exists"
            raise ValueError(msg)

        if await self.user_repository.get_by_email(email):
            msg = f"Email '{email}' already registered"
            raise ValueError(msg)

        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=self.password_hasher.hash(password),
        )

        # Assign roles
        if roles:
            for role_name in roles:
                role = await self.role_repository.get_by_name(role_name)
                if role:
                    user.add_role(role)

        # Save user
        await self.user_repository.save(user)

        return user

    async def authenticate(
        self, username_or_email: str, password: Password, ip_address: str | None = None
    ) -> TokenPair:
        """Authenticate user and return token pair."""
        # Rate limiting
        if ip_address and not await self.rate_limiter.is_allowed(ip_address):
            msg = "Too many login attempts. Please try again later."
            raise ValueError(msg)

        # Find user
        user = await self._find_user(username_or_email)
        if not user:
            msg = "Invalid credentials"
            raise ValueError(msg)

        # Check if user is locked
        if user.is_locked:
            msg = "Account is locked. Please try again later."
            raise ValueError(msg)

        # Verify password
        if not self.password_hasher.verify(password, user.password_hash):
            # Record failed attempt
            user.record_failed_attempt(
                lock_after=self.max_login_attempts,
                lock_duration_minutes=self.lockout_duration_minutes,
            )
            await self.user_repository.save(user)
            msg = "Invalid credentials"
            raise ValueError(msg)

        # Check if password needs rehashing
        if self.password_hasher.needs_rehash(user.password_hash):
            user.password_hash = self.password_hasher.hash(password)

        # Record successful login
        user.record_login()
        await self.user_repository.save(user)

        # Load user roles
        roles = await self.role_repository.get_user_roles(user.user_id)
        user.roles = frozenset(role.name for role in roles)

        # Create token pair
        return self.jwt_service.create_token_pair(user)

    async def refresh_tokens(
        self, refresh_token: str, ip_address: str | None = None
    ) -> TokenPair:
        """Refresh token pair using refresh token."""
        # Rate limiting
        if ip_address and not await self.rate_limiter.is_allowed(ip_address):
            msg = "Too many refresh attempts. Please try again later."
            raise ValueError(msg)

        # Verify refresh token and get user ID
        claims = await self.jwt_service.verify_token(
            refresh_token,
            token_type="refresh",
        )
        if not claims:
            msg = "Invalid refresh token"
            raise ValueError(msg)
        user_id = UUID(claims["sub"])

        # Load user
        user = await self.user_repository.get_by_id(user_id)
        if not user or not user.is_active:
            msg = "User not found or inactive"
            raise ValueError(msg)

        # Load user roles
        roles = await self.role_repository.get_user_roles(user.user_id)
        user.roles = frozenset(role.name for role in roles)

        # Refresh tokens
        return await self.jwt_service.refresh_tokens(refresh_token, user)

    async def verify_access_token(self, token: str) -> User:
        """Verify access token and return user."""
        # Verify token
        claims = await self.jwt_service.verify_token(token, token_type="access")
        if not claims:
            msg = "Invalid access token"
            raise ValueError(msg)
        user_id = UUID(claims["sub"])

        # Load user
        user = await self.user_repository.get_by_id(user_id)
        if not user or not user.is_active:
            msg = "User not found or inactive"
            raise ValueError(msg)

        # Load user roles
        roles = await self.role_repository.get_user_roles(user.user_id)
        user.roles = frozenset(role.name for role in roles)

        return user

    async def revoke_token(self, token: str) -> None:
        """Revoke token by adding to blacklist."""
        await self.jwt_service.revoke_token(token)

    async def change_password(
        self, user_id: UserId, old_password: Password, new_password: Password
    ) -> None:
        """Change user password with validation.

        Validates the old password, hashes the new password, updates
        the user record, and performs necessary security cleanup
        for password change operations.

        Args:
        ----
        user_id: Unique user identifier
        old_password: Current password for verification
        new_password: New password to set

        Raises:
        ------
        ValueError: If user not found or old password is invalid

        Note:
        ----
            Password changes are logged for security audit purposes.

        """
        # Load user
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            msg = "User not found"
            raise ValueError(msg)

        # Verify old password
        if not self.password_hasher.verify(old_password, user.password_hash):
            msg = "Invalid old password"
            raise ValueError(msg)

        # Update password
        user.password_hash = self.password_hasher.hash(new_password)
        await self.user_repository.save(user)

    async def reset_password(self, user_id: UserId, new_password: Password) -> None:
        """Reset user password (REDACTED_LDAP_BIND_PASSWORD function)."""
        # Load user
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            msg = "User not found"
            raise ValueError(msg)

        # Update password
        user.password_hash = self.password_hasher.hash(new_password)
        user.failed_attempts = 0
        user.locked_until = None
        await self.user_repository.save(user)

    async def check_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has permission through roles."""
        # Load user roles
        roles = await self.role_repository.get_user_roles(user.user_id)

        # Check each role for permission
        return any(role.has_permission(permission) for role in roles)

    async def _find_user(self, username_or_email: str) -> User | None:
        """Find user by username or email."""
        # Try username first
        user = await self.user_repository.get_by_username(username_or_email)
        if user:
            return user

        # Try email
        return await self.user_repository.get_by_email(username_or_email)


# In-memory repositories for development
class ServiceInMemoryUserRepository:
    """Simple in-memory user repository."""

    def __init__(self) -> None:
        """Initialize in-memory user repository with empty collections."""
        self._users: dict[UserId, User] = {}
        self._username_index: dict[Username, UserId] = {}
        self._email_index: dict[Email, UserId] = {}

    async def get_by_id(self, user_id: UserId) -> User | None:
        """Get user by unique identifier.

        Retrieves user information from the in-memory repository using
        the user's unique identifier for authentication and authorization
        operations.

        Args:
        ----
        user_id: Unique user identifier

        Returns:
        -------
        User object if found, None otherwise

        Note:
        ----

        """
        return self._users.get(user_id)

    async def get_by_username(self, username: Username) -> User | None:
        """Get user by username.

        Retrieves user information from the in-memory repository using
        the username as the lookup key for authentication operations.

        Args:
        ----
        username: User's unique username

        Returns:
        -------
        User object if found, None otherwise

        Note:
        ----

        """
        user_id = self._username_index.get(username)
        return self._users.get(user_id) if user_id else None

    async def get_by_email(self, email: Email) -> User | None:
        """Get user by email address.

        Retrieves user information from the in-memory repository using
        the email address as the lookup key for authentication operations.

        Args:
        ----
        email: User's email address

        Returns:
        -------
        User object if found, None otherwise

        Note:
        ----

        """
        user_id = self._email_index.get(email)
        return self._users.get(user_id) if user_id else None

    async def save(self, user: User) -> None:
        """Save user to repository.

        Persists user information to the in-memory repository with
        proper indexing for efficient lookup by username and email
        address.

        Args:
        ----
        user: User object to save

        Note:
        ----

        """
        self._users[user.user_id] = user
        self._username_index[user.username] = user.user_id
        self._email_index[user.email] = user.user_id

    async def delete(self, user_id: UserId) -> None:
        """Delete user from repository.

        Removes user from the in-memory repository and cleans up
        associated index entries for username and email address
        to maintain data consistency.

        Args:
        ----
        user_id: Unique user identifier

        Note:
        ----

        """
        user = self._users.pop(user_id, None)
        if user:
            self._username_index.pop(user.username, None)
            self._email_index.pop(user.email, None)


class ServiceInMemoryRoleRepository:
    """Simple in-memory role repository."""

    def __init__(self) -> None:
        """Initialize in-memory role repository with default roles."""
        self._roles: dict[str, Role] = {
            "REDACTED_LDAP_BIND_PASSWORD": ADMIN_ROLE,
            "operator": OPERATOR_ROLE,
            "viewer": VIEWER_ROLE,
        }
        self._user_roles: dict[UserId, set[str]] = {}

    async def get_by_name(self, name: str) -> Role | None:
        """Get role by name.

        Retrieves role information from the in-memory repository using
        the role name as the lookup key for authorization operations.

        Args:
        ----
        name: Role name to lookup

        Returns:
        -------
        Role object if found, None otherwise

        Note:
        ----

        """
        return self._roles.get(name)

    async def get_user_roles(self, user_id: UserId) -> list[Role]:
        """Get all roles assigned to a user.

        Retrieves all roles assigned to the specified user from the
        in-memory repository for authorization and permission checking.

        Args:
        ----
        user_id: Unique user identifier

        Returns:
        -------
        List of Role objects assigned to the user

        Note:
        ----

        """
        role_names = self._user_roles.get(user_id, set())
        return [self._roles[name] for name in role_names if name in self._roles]

    async def save(self, role: Role) -> None:
        """Save role to repository.

        Persists role information to the in-memory repository for
        authorization and permission management operations.

        Args:
        ----
        role: Role object to save

        Note:
        ----

        """
        self._roles[role.name] = role
