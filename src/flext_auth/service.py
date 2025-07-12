"""Authentication service implementation."""

from typing import Any


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

    def __init__(self, user_repository: ServiceInMemoryUserRepository, role_repository: ServiceInMemoryRoleRepository) -> None:
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
