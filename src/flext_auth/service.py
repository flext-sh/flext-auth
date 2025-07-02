"""Authentication service implementation."""

from typing import Any, Optional


class ServiceInMemoryUserRepository:
    """In-memory user repository for testing."""

    def __init__(self) -> None:
        self.users: dict[str, Any] = {}

    def find_by_email(self, email: str) -> Optional[Any]:
        """Find user by email."""
        return self.users.get(email)

    def save(self, user: Any) -> Any:
        """Save user."""
        self.users[user.email] = user
        return user


class ServiceInMemoryRoleRepository:
    """In-memory role repository for testing."""

    def __init__(self) -> None:
        self.roles: dict[str, Any] = {}

    def find_by_name(self, name: str) -> Optional[Any]:
        """Find role by name."""
        return self.roles.get(name)


class AuthenticationService:
    """Authentication service."""

    def __init__(
        self,
        user_repository: ServiceInMemoryUserRepository,
        role_repository: ServiceInMemoryRoleRepository,
    ) -> None:
        self.user_repository = user_repository
        self.role_repository = role_repository

    def register(self, user_data: dict[str, Any]) -> Any:
        """Register new user."""
        # Simulate user registration
        user = type("User", (), user_data)()
        return self.user_repository.save(user)

    def authenticate(self, email: str, password: str) -> Optional[Any]:
        """Authenticate user."""
        user = self.user_repository.find_by_email(email)
        if user and hasattr(user, "password") and user.password == password:
            return user
        return None
