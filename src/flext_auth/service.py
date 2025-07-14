"""Authentication service implementation."""

from typing import Any


class AuthService:
    """Abstract authentication service interface."""

    def __init__(self) -> None:
        """Initialize authentication service."""

    async def authenticate(self, username: str | None, password: str | None) -> Any:
        """Authenticate user with username and password.

        Args:
            username: Username or email for authentication.
            password: Password for authentication.

        Returns:
            User object if authentication successful.

        Raises:
            NotImplementedError: This is an abstract method.
        """
        raise NotImplementedError("AuthService.authenticate must be implemented")

    async def register(self, user_data: dict[str, Any]) -> Any:
        """Register a new user.

        Args:
            user_data: User registration data.

        Returns:
            Created user object.

        Raises:
            NotImplementedError: This is an abstract method.
        """
        raise NotImplementedError("AuthService.register must be implemented")

    async def create_user(self, username: str | None, password: str | None, user_data: dict[str, Any] | None) -> Any:
        """Create a new user.

        Args:
            username: Username for the new user.
            password: Password for the new user.
            user_data: Additional user data.

        Returns:
            Created user object.

        Raises:
            NotImplementedError: This is an abstract method.
        """
        raise NotImplementedError("AuthService.create_user must be implemented")

    async def get_user(self, user_id: str | None) -> Any:
        """Get user by ID.

        Args:
            user_id: User identifier.

        Returns:
            User object if found, None otherwise.

        Raises:
            NotImplementedError: This is an abstract method.
        """
        raise NotImplementedError("AuthService.get_user must be implemented")


class ServiceInMemoryUserRepository:
    """In-memory user repository for testing."""

    def __init__(self) -> None:
        """Initialize empty user repository."""
        self.users: dict[str, Any] = {}

    def find_by_email(self, email: str) -> Any | None:
        """Find user by email address."""
        return self.users.get(email)

    def save(self, user: Any) -> Any:
        """Save user to repository."""
        self.users[user.email] = user
        return user


class ServiceInMemoryRoleRepository:
    """In-memory role repository for testing."""

    def __init__(self) -> None:
        """Initialize empty role repository."""
        self.roles: dict[str, Any] = {}

    def find_by_name(self, name: str) -> Any | None:
        """Find role by name."""
        return self.roles.get(name)


class AuthenticationService:
    """Authentication service."""

    def __init__(
        self,
        user_repository: ServiceInMemoryUserRepository,
        role_repository: ServiceInMemoryRoleRepository,
    ) -> None:
        """Initialize authentication service with repositories."""
        self.user_repository = user_repository
        self.role_repository = role_repository

    def register(self, user_data: dict[str, Any]) -> Any:
        """Register a new user with provided data."""
        # Simulate user registration
        user = type("User", (), user_data)()
        return self.user_repository.save(user)

    def authenticate(self, email: str, password: str) -> Any | None:
        """Authenticate user with email and password."""
        user = self.user_repository.find_by_email(email)
        if user and hasattr(user, "password") and user.password == password:
            return user
        return None
