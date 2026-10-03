"""Basic FLEXT Auth usage flow examples."""

from __future__ import annotations

import os

from flext_auth import FlextAuth, FlextAuthSettings, p, r, u


class FlextAuthBasicUsageFlows:
    """Reusable basic usage flow examples."""

    logger = u.fetch_logger(__name__)

    @classmethod
    def example_basic_authentication(cls) -> p.Result[bool]:
        """Show the typed authentication settings the service runs with."""
        settings = FlextAuthSettings()
        cls.logger.info(
            "Authentication configuration loaded",
            expiry_minutes=settings.Auth.expiry_minutes,
            hash_rounds=settings.Auth.hash_rounds,
            max_sessions_per_user=settings.Auth.max_sessions_per_user,
        )
        return r[bool].ok(True)

    @classmethod
    def example_user_lifecycle(cls) -> p.Result[bool]:
        """Register, authenticate and validate the issued token."""
        auth = FlextAuth()
        password = os.getenv("FLEXT_DEMO_USER_PASSWORD", "StrongPass123!")
        register_result = auth.register_user(
            username="lifecycleuser",
            email="lifecycle@example.com",
            password=password,
            roles=["user"],
        )
        if register_result.failure:
            return r[bool].from_failure(register_result)
        cls.logger.info("User registered", name=register_result.value.name)
        auth_result = auth.authenticate_user("lifecycleuser", password)
        if auth_result.failure:
            return r[bool].from_failure(auth_result)
        cls.logger.info("User authenticated", session_id=auth_result.value.session_id)
        return auth.token_service.validate_token(auth_result.value.token)

    @classmethod
    def example_direct_auth(cls) -> p.Result[bool]:
        """Register and authenticate directly, returning the token validity."""
        auth = FlextAuth()
        password = os.getenv("FLEXT_DEMO_PASSWORD", "MySecurePassword123!")
        reg_result = auth.register_user("directuser", "direct@example.com", password)
        if reg_result.failure:
            return r[bool].from_failure(reg_result)
        auth_result = auth.authenticate_user("directuser", password)
        if auth_result.failure:
            return r[bool].from_failure(auth_result)
        cls.logger.info("User authenticated", username="directuser")
        return auth.token_service.validate_token(auth_result.value.token)


__all__: list[str] = ["FlextAuthBasicUsageFlows"]
