"""FLEXT Auth API - Main facade class for authentication operations.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
import secrets
import string
from datetime import UTC, datetime

from flext_core import FlextEntityId, FlextResult

from flext_auth.config import FlextAuthConfig
from flext_auth.container_services import (
    SessionRepositoryType,
    UserRepositoryType,
    configure_flext_auth_container,
    get_auth_service,
    get_flext_auth_services,
    get_jwt_service,
    get_password_service,
)
from flext_auth.entities import FlextUser, FlextUserRole, FlextUserStatus
from flext_auth.jwt import FlextJWTService
from flext_auth.password_service import FlextPasswordService
from flext_auth.repositories_simple import (
    SimplePostgreSQLSessionRepository,
    SimplePostgreSQLUserRepository,
    create_postgresql_pool,
    initialize_database_schema,
)
from flext_auth.session import InMemorySessionRepository
from flext_auth.user import InMemoryUserRepository


class FlextAuth:
    """Main FlextAuth API facade class using FlextContainer DI.

    Refactored to eliminate duplications by using centralized FlextContainer
    for dependency injection instead of manual service instantiation.
    """

    def __init__(
        self,
        config: FlextAuthConfig | None = None,
        user_repository: UserRepositoryType | None = None,
        session_repository: SessionRepositoryType | None = None,
    ) -> None:
        """Initialize FlextAuth using FlextContainer DI to eliminate duplications."""
        # Configure container with provided or default services
        container_result = configure_flext_auth_container(
            container=None,
            config=config,
            user_repository=user_repository,
            session_repository=session_repository,
        )

        if not container_result.success:
            msg = f"Failed to configure FlextAuth container: {container_result.error}"
            raise RuntimeError(msg)

        # Get auth service from container - eliminates manual instantiation
        auth_service_result = get_auth_service()
        if not auth_service_result.success:
            msg = f"Failed to get auth service: {auth_service_result.error}"
            raise RuntimeError(msg)

        self._auth_service = auth_service_result.value

    @classmethod
    async def create_with_postgresql(
        cls,
        database_url: str,
        config: FlextAuthConfig | None = None,
    ) -> FlextAuth:
        """Create FlextAuth with REAL PostgreSQL repositories."""
        pool = await create_postgresql_pool(database_url)

        # Initialize database schema
        init_result = await initialize_database_schema(pool)
        if not init_result.success:
            msg = f"Failed to initialize database: {init_result.error}"
            raise RuntimeError(msg)

        user_repo = SimplePostgreSQLUserRepository(pool)
        session_repo = SimplePostgreSQLSessionRepository(pool)

        return cls(
            config=config,
            user_repository=user_repo,
            session_repository=session_repo,
        )

    async def authenticate(
        self, username: str, password: str
    ) -> FlextResult[dict[str, object]]:
        """Authenticate user with username and password."""
        # Validate input
        validation_result = self._validate_auth_input(username, password)
        if validation_result:
            return validation_result

        try:
            # Get services and validate user
            user_result = await self._get_and_validate_user(username, password)
            if not user_result.success:
                return user_result

            user_data = user_result.value
            # Generate and return token
            return self._generate_auth_token(user_data)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Authentication error: {e}")

    def _validate_auth_input(self, username: str, password: str) -> FlextResult[dict[str, object]] | None:
        """Validate authentication input parameters."""
        if not username or not password:
            return FlextResult[dict[str, object]].fail(
                "Username and password are required"
            )
        return None

    async def _get_and_validate_user(self, username: str, password: str) -> FlextResult[dict[str, object]]:
        """Get user from repository and validate password."""
        # Get user repository
        repo_result = self._get_user_repository()
        if not repo_result.success:
            return repo_result

        user_repository = repo_result.value

        # Get user and validate password
        return await self._validate_user_password(username, password, user_repository)

    def _get_user_repository(self) -> FlextResult[dict[str, object]]:
        """Get user repository from container with type validation."""
        services_result = get_flext_auth_services()
        if not services_result.success:
            return FlextResult[dict[str, object]].fail("Failed to get services")

        services = services_result.value
        user_repository = services.get("user_repository")
        if not user_repository:
            return FlextResult[dict[str, object]].fail("User repository not available")

        # Type narrowing for mypy
        if not isinstance(
            user_repository,
            (InMemoryUserRepository, SimplePostgreSQLUserRepository),
        ):
            return FlextResult[dict[str, object]].fail("Invalid user repository type")

        return FlextResult[dict[str, object]].ok(user_repository)

    async def _validate_user_password(
        self, username: str, password: str, user_repository: object
    ) -> FlextResult[dict[str, object]]:
        """Validate user exists and password is correct."""
        # Check if user exists
        user_result = await user_repository.get_by_username(username)
        if not user_result.success or not user_result.value:
            return FlextResult[dict[str, object]].fail("Invalid credentials")

        user = user_result.value

        # Verify password
        password_service_result = get_password_service()
        if not password_service_result.success:
            return FlextResult[dict[str, object]].fail("Password service not available")

        password_service = password_service_result.value
        password_result = password_service.verify_password(password, user.password_hash)
        if not password_result.unwrap_or(False):  # noqa: FBT003
            return FlextResult[dict[str, object]].fail("Invalid credentials")

        return FlextResult[dict[str, object]].ok(user)

    def _generate_auth_token(self, user: object) -> FlextResult[dict[str, object]]:
        """Generate authentication token for successful login."""
        jwt_service_result = get_jwt_service()
        if not jwt_service_result.success:
            return FlextResult[dict[str, object]].fail("JWT service not available")

        jwt_service = jwt_service_result.value
        token_result = jwt_service.generate_access_token(
            user_id=str(user.id),
            username=user.username,
            role=str(user.role),
            session_id="sync_session",
        )

        if not token_result.success:
            return FlextResult[dict[str, object]].fail("Failed to generate token")

        return FlextResult[dict[str, object]].ok({
            "authenticated": True,
            "user": {"username": user.username, "email": user.email},
            "access_token": token_result.value,
        })

    async def create_user(
        self, username: str, email: str, password: str
    ) -> FlextResult[dict[str, object]]:
        """Create a new user."""
        # Validate input
        validation_result = self._validate_create_user_input(username, email, password)
        if validation_result:
            return validation_result

        # Get repository and validate uniqueness
        repository_result = await self._get_repository_and_validate_uniqueness(
            username, email
        )
        if not repository_result.success:
            return repository_result

        user_repository = repository_result.value

        # Create and save user
        return await self._create_and_save_user(
            username, email, password, user_repository
        )

    def _validate_create_user_input(
        self, username: str, email: str, password: str
    ) -> FlextResult[dict[str, object]] | None:
        """Validate create user input parameters."""
        if not username or not email or not password:
            return FlextResult[dict[str, object]].fail(
                "Username, email, and password are required"
            )
        return None

    async def _get_repository_and_validate_uniqueness(
        self, username: str, email: str
    ) -> FlextResult[object]:
        """Get user repository and validate uniqueness constraints."""
        # Get services from container
        services_result = get_flext_auth_services()
        if not services_result.success:
            return FlextResult[object].fail("Failed to get services")

        services = services_result.value
        user_repository = services.get("user_repository")
        if not user_repository:
            return FlextResult[object].fail("User repository not available")

        # Type narrowing for mypy
        if not isinstance(
            user_repository, (InMemoryUserRepository, SimplePostgreSQLUserRepository)
        ):
            return FlextResult[object].fail("Invalid user repository type")

        # Check uniqueness
        error_msg = await self._validate_user_uniqueness(
            username, email, user_repository
        )
        if error_msg:
            return FlextResult[object].fail(error_msg)

        return FlextResult[object].ok(user_repository)

    async def _create_and_save_user(
        self, username: str, email: str, password: str, user_repository: object
    ) -> FlextResult[dict[str, object]]:
        """Create user entity and save to repository."""
        # Get password service and hash password
        password_service_result = get_password_service()
        if not password_service_result.success:
            return FlextResult[dict[str, object]].fail("Password service not available")

        password_service = password_service_result.value
        hash_result = password_service.hash_password(password)
        if not hash_result.success or not hash_result.value:
            return FlextResult[dict[str, object]].fail("Failed to hash password")

        # Create user entity
        user = FlextUser(
            id=FlextEntityId(f"user_{username}"),
            username=username,
            email=email,
            password_hash=hash_result.value.value,  # FlextHashedPassword.value
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        # Save user
        save_error = await self._save_user_safely(user, user_repository)
        if save_error:
            return FlextResult[dict[str, object]].fail(save_error)

        return FlextResult[dict[str, object]].ok({
            "user_created": True,
            "username": user.username,
            "email": user.email,
            "id": str(user.id),
        })

    async def _validate_user_uniqueness(
        self, username: str, email: str, user_repository: UserRepositoryType
    ) -> str | None:
        """Validate that username and email are unique."""
        try:
            # Check for existing username - pure async
            existing_user_result = await user_repository.get_by_username(username)
            if existing_user_result.success:
                # Use .value pattern
                if (
                    hasattr(existing_user_result, "value")
                    and existing_user_result.value is not None
                ):
                    return "Username already exists"
            else:
                error_msg = existing_user_result.error or "Unknown error"
                return f"Username check failed: {error_msg}"

            # Check for existing email - pure async
            existing_email_result = await user_repository.get_by_email(email)
            if existing_email_result.success:
                # Use .value pattern
                if (
                    hasattr(existing_email_result, "value")
                    and existing_email_result.value is not None
                ):
                    return "Email already exists"
            else:
                return f"Email check failed: {existing_email_result.error or 'Unknown error'}"

            return None
        except Exception as e:
            return f"User validation error: {e}"

    async def _save_user_safely(
        self, user: FlextUser, user_repository: UserRepositoryType
    ) -> str | None:
        """Save user safely and return error message if any."""
        try:
            save_result = await user_repository.save(user)
            if not save_result.success:
                return "Failed to save user"
            return None
        except Exception as e:
            return f"Failed to save user: {e}"

    # No sync wrappers - pure async architecture only

    @property
    def config(self) -> FlextAuthConfig:
        """Get the authentication configuration from container."""
        services_result = get_flext_auth_services()
        if services_result.success:
            config = services_result.value.get("config")
            if config and isinstance(config, FlextAuthConfig):
                return config
        # Create default configuration
        return FlextAuthConfig(
            app_name="FlextAuth",
            version="1.0.0",
            environment="development",
            password_min_length=8,
            password_max_length=128,
            bcrypt_rounds=12,
            max_login_attempts=5,
            lockout_duration_minutes=30,
            session_timeout_hours=24,
            max_concurrent_sessions=5,
            rate_limit_per_minute=60,
            auth_rate_limit_per_minute=5,
            access_token_expire_minutes=30,
            refresh_token_expire_days=7,
            jwt_secret_key=DEFAULT_JWT_SECRET,
        )

    @property
    def service(self) -> object:
        """Get the underlying authentication service from container."""
        return self._auth_service

    @property
    def auth_service(self) -> object:
        """Get the underlying authentication service (alias for service)."""
        return self._auth_service

    @property
    def jwt_service(self) -> FlextJWTService:
        """Get JWT service for token operations from container."""
        jwt_service_result = get_jwt_service()
        if jwt_service_result.success:
            return jwt_service_result.value
        msg = f"JWT service not available: {jwt_service_result.error}"
        raise RuntimeError(msg)

    @property
    def password_service(self) -> FlextPasswordService:
        """Get password service for password operations from container."""
        password_service_result = get_password_service()
        if password_service_result.success:
            return password_service_result.value
        msg = f"Password service not available: {password_service_result.error}"
        raise RuntimeError(msg)

    @property
    def user_repository(self) -> UserRepositoryType:
        """Get user repository for user management from container."""
        services_result = get_flext_auth_services()
        if services_result.success:
            user_repo = services_result.value.get("user_repository")
            if isinstance(
                user_repo, (InMemoryUserRepository, SimplePostgreSQLUserRepository)
            ):
                return user_repo
        msg = "User repository not available from container"
        raise RuntimeError(msg)

    @property
    def session_repository(self) -> SessionRepositoryType:
        """Get session repository for session management from container."""
        services_result = get_flext_auth_services()
        if services_result.success:
            session_repo = services_result.value.get("session_repository")
            if isinstance(
                session_repo,
                (InMemorySessionRepository, SimplePostgreSQLSessionRepository),
            ):
                return session_repo
        msg = "Session repository not available from container"
        raise RuntimeError(msg)


# =============================================================================
# CONSTANTS AND TYPE ALIASES
# =============================================================================

# Role constants using current entities
ADMIN_ROLE = FlextUserRole.ADMIN.value
USER_ROLE = FlextUserRole.USER.value

# Modern type aliases using current patterns
type FlextAuthRole = str
type FlextAuthPermissions = list[str]
type FlextAuthUserData = dict[str, object]
type FlextAuthSessionData = dict[str, object]
type FlextAuthTokenData = dict[str, object]
type FlextAuthHeaders = dict[str, str]
type FlextAuthClaims = dict[str, object]

# =============================================================================
# HELPER FUNCTIONS - Single API source
# =============================================================================


# Constants for JWT security - noqa: S105 (dev secret is intentional)
DEFAULT_JWT_SECRET = "dev-secret-key-change-in-production"  # noqa: S105
MIN_PASSWORD_LENGTH_CONSTANT = 8


def flext_auth_quick_start(
    *,
    jwt_secret: str = DEFAULT_JWT_SECRET,
) -> FlextAuth:
    """Quick start helper using FlextAuth API.

    Args:
        jwt_secret: JWT secret key for token signing

    Returns:
        Configured FlextAuth instance

    """
    config = FlextAuthConfig(
        app_name="FlextAuth",
        version="1.0.0",
        environment="development",
        password_min_length=8,
        password_max_length=128,
        bcrypt_rounds=12,
        max_login_attempts=5,
        lockout_duration_minutes=30,
        session_timeout_hours=24,
        max_concurrent_sessions=5,
        rate_limit_per_minute=60,
        auth_rate_limit_per_minute=5,
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
        jwt_secret_key=jwt_secret,
    )

    return FlextAuth(config=config)


def flext_auth_hash_password(password: str) -> FlextResult[str]:
    """Hash password using current password service.

    Args:
        password: Plain text password to hash

    Returns:
        FlextResult containing hashed password or error

    """
    service = FlextPasswordService()
    hash_result = service.hash_password(password)

    if not hash_result.success:
        return FlextResult[str].fail(hash_result.error or "Password hashing failed")

    return FlextResult[str].ok(hash_result.value.value)


def flext_auth_verify_password(password: str, hashed: str) -> FlextResult[bool]:
    """Verify password using current password service.

    Args:
        password: Plain text password
        hashed: Hashed password to verify against

    Returns:
        FlextResult containing verification result or error

    """
    service = FlextPasswordService()
    verify_result = service.verify_password(password, hashed)

    if not verify_result.success:
        return FlextResult[bool].fail(
            verify_result.error or "Password verification failed"
        )

    return FlextResult[bool].ok(verify_result.value)


def flext_auth_generate_jwt(
    user_id: str,
    username: str,
    role: str = "user",
    session_id: str = "default",
    jwt_secret: str = DEFAULT_JWT_SECRET,
) -> FlextResult[str]:
    """Generate JWT token using current JWT service.

    Args:
        user_id: User ID for the token
        username: Username for the token
        role: User role for the token
        session_id: Session ID for the token
        jwt_secret: JWT secret key

    Returns:
        FlextResult containing JWT token or error

    """
    service = FlextJWTService(secret_key=jwt_secret)
    token_result = service.generate_access_token(
        user_id=user_id,
        username=username,
        role=role,
        session_id=session_id,
    )

    if not token_result.success:
        return FlextResult[str].fail(token_result.error or "JWT generation failed")

    return FlextResult[str].ok(token_result.value)


def flext_auth_validate_jwt(
    token: str,
    jwt_secret: str = DEFAULT_JWT_SECRET,
) -> FlextResult[dict[str, object]]:
    """Validate JWT token using current JWT service.

    Args:
        token: JWT token to validate
        jwt_secret: JWT secret key

    Returns:
        FlextResult containing decoded claims or error

    """
    service = FlextJWTService(secret_key=jwt_secret)
    validate_result = service.verify_token(token)

    if not validate_result.success:
        return FlextResult[dict[str, object]].fail(
            validate_result.error or "JWT validation failed"
        )

    # Convert JWTClaims object to dict
    claims_obj = validate_result.value
    claims_dict: dict[str, object] = {
        "user_id": claims_obj.sub,
        "username": claims_obj.username,
        "role": claims_obj.role,
        "session_id": claims_obj.session_id,
        "permissions": claims_obj.permissions,
        "iat": claims_obj.iat,
        "exp": claims_obj.exp,
    }

    return FlextResult[dict[str, object]].ok(claims_dict)


def flext_auth_validate_email(email: str) -> bool:
    """Validate email format using simple regex.

    Args:
        email: Email address to validate

    Returns:
        Boolean indicating if email is valid

    """
    if not email or not isinstance(email, str):
        return False

    # Simple email regex validation
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(email_pattern, email.strip()))


def flext_auth_validate_password_strength(password: str) -> FlextResult[bool]:
    """Validate password strength using current standards.

    Args:
        password: Password to validate

    Returns:
        FlextResult containing validation result

    """
    # Constants for password validation
    min_password_length = MIN_PASSWORD_LENGTH_CONSTANT
    required_char_types = 3

    if not password or not isinstance(password, str):
        return FlextResult[bool].fail("Password must be a non-empty string")

    # Check minimum length
    if len(password) < min_password_length:
        return FlextResult[bool].ok(False)  # noqa: FBT003

    # Check for required character types
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    # Password is strong if it has at least 3 of 4 character types
    strength_score = sum([has_upper, has_lower, has_digit, has_special])
    is_strong = strength_score >= required_char_types

    return FlextResult[bool].ok(is_strong)


# Utility functions
def generate_secure_token(length: int = 32) -> str:
    """Generate a secure random token.

    Args:
        length: Length of the token to generate

    Returns:
        Secure random token string

    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure random password.

    Args:
        length: Length of the password to generate

    Returns:
        Secure random password string

    """
    # Ensure password has all character types
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = "".join(secrets.choice(alphabet) for _ in range(length))

    # Ensure at least one of each type
    if length >= MIN_PASSWORD_LENGTH_CONSTANT:
        # Replace some random positions with required character types
        password = list(password)
        password[0] = secrets.choice(string.ascii_uppercase)
        password[1] = secrets.choice(string.ascii_lowercase)
        password[2] = secrets.choice(string.digits)
        password[3] = secrets.choice("!@#$%^&*")
        # Shuffle to avoid predictable positions
        secrets.SystemRandom().shuffle(password)
        password = "".join(password)

    return password


def get_utc_now() -> datetime:
    """Get current UTC datetime.

    Returns:
        Current UTC datetime

    """
    return datetime.now(UTC)


def is_strong_password(password: str) -> bool:
    """Check if password meets strength requirements.

    Args:
        password: Password to check

    Returns:
        True if password is strong, False otherwise

    """
    return flext_auth_validate_password_strength(password).unwrap_or(False)  # noqa: FBT003


def mask_sensitive_data(data: str, visible_chars: int = 4, mask_char: str = "*") -> str:
    """Mask sensitive data showing only last few characters.

    Args:
        data: Sensitive data to mask
        visible_chars: Number of characters to show at the end
        mask_char: Character to use for masking

    Returns:
        Masked data string

    """
    if not data or len(data) <= visible_chars:
        return mask_char * len(data) if data else ""

    mask_length = len(data) - visible_chars
    return mask_char * mask_length + data[-visible_chars:]


__all__ = [
    # Constants
    "ADMIN_ROLE",
    "USER_ROLE",
    # Main API class
    "FlextAuth",
    "FlextAuthClaims",
    "FlextAuthHeaders",
    "FlextAuthPermissions",
    "FlextAuthRole",
    "FlextAuthSessionData",
    "FlextAuthTokenData",
    "FlextAuthUserData",
    "flext_auth_generate_jwt",
    "flext_auth_hash_password",
    # Helper functions
    "flext_auth_quick_start",
    "flext_auth_validate_email",
    "flext_auth_validate_jwt",
    "flext_auth_validate_password_strength",
    "flext_auth_verify_password",
    "generate_secure_password",
    "generate_secure_token",
    "get_utc_now",
    "is_strong_password",
    "mask_sensitive_data",
]
