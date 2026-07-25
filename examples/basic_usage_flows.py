"""Basic FLEXT Auth usage flow examples."""

from __future__ import annotations

import os

from flext_auth import FlextAuth, FlextAuthSettings, t, u


class FlextAuthBasicUsageFlows:
    """Reusable basic usage flow examples."""

    logger = u.fetch_logger(__name__)

    @classmethod
    def example_basic_authentication(cls) -> None:
        """Demonstrate basic authentication with FlextAuth."""
        cls.logger.info("Starting basic authentication example")
        FlextAuth()
        cls.logger.info("FlextAuth instance created with in-memory storage")
        settings = FlextAuthSettings()
        cls.logger.info(
            "Authentication configuration loaded",
            expiry_minutes=settings.expiry_minutes,
            hash_rounds=settings.hash_rounds,
            max_sessions_per_user=settings.max_sessions_per_user,
        )

    @classmethod
    def example_password_operations(cls) -> None:
        """Demonstrate password operations."""
        cls.logger.info("Starting password operations example")
        FlextAuth()
        cls.logger.info("Password operations are handled by the auth service")

    @classmethod
    def example_email_validation(cls) -> None:
        """Demonstrate email validation patterns."""
        cls.logger.info("Starting email validation example")
        test_emails = [
            "valid@example.com",
            "user.name@domain.co.uk",
            "invalid.email",
            "missing@domain",
            "double@@domain.com",
            "",
        ]

        def validate_email_manual(email: str) -> bool:
            """Manual email validation for demonstration."""
            if not email:
                return False
            if "@" not in email or email.count("@") != 1:
                return False
            local, domain = email.split("@")
            if not local or not domain:
                return False
            if "." not in domain:
                return False
            return ".." not in email

        valid_count = 0
        for email in test_emails:
            valid = validate_email_manual(email)
            if valid:
                valid_count += 1
            cls.logger.info("Email validation result", email=email, valid=valid)
        cls.logger.info(
            "Email validation completed",
            valid_emails=valid_count,
            total_emails=len(test_emails),
        )

    @classmethod
    def example_user_lifecycle(cls) -> None:
        """Demonstrate complete user lifecycle."""
        cls.logger.info("Starting user lifecycle example")
        auth: FlextAuth = FlextAuth()
        password = os.getenv("FLEXT_DEMO_USER_PASSWORD", "StrongPass123!")
        cls.logger.info("Registering user lifecycle example")
        register_result = auth.register_user(
            username="lifecycleuser",
            email="lifecycle@example.com",
            password=password,
            roles=["user"],
        )
        if register_result.success:
            user_data = register_result.value
            roles_payload: list[t.JsonValue] = list(user_data.roles)
            cls.logger.info(
                "User registered successfully",
                name=user_data.name,
                contact=user_data.contact,
                roles=roles_payload,
                active=user_data.is_active,
            )
            cls.logger.info("Authenticating registered user")
            auth_result = auth.authenticate_user("lifecycleuser", password)
            if auth_result.success:
                cls.logger.info("User authentication successful")
                auth_token = auth_result.value
                jwt_token_str = auth_token.token
                session_id = auth_token.session_id
                cls.logger.info(
                    "Authentication token generated",
                    jwt_token_preview=(jwt_token_str[:50] + "...")
                    if jwt_token_str
                    else "",
                    session_id=session_id,
                )
                cls.logger.info("Validating JWT token")
                token_result = auth.token_service.validate_token(jwt_token_str)
                if token_result.success:
                    cls.logger.info(
                        "Token validation successful",
                        valid=token_result.value,
                    )
                else:
                    cls.logger.error(
                        "Token validation failed",
                        error=token_result.error,
                    )
            else:
                cls.logger.error("Authentication failed", error=auth_result.error)
        else:
            cls.logger.error(
                "User registration failed",
                error=register_result.error,
            )

    @classmethod
    def example_direct_auth(cls) -> None:
        """Demonstrate direct authentication workflow."""
        cls.logger.info("Starting direct authentication example")
        auth: FlextAuth = FlextAuth()
        username = "directuser"
        email = "direct@example.com"
        password = os.getenv("FLEXT_DEMO_PASSWORD", "MySecurePassword123!")
        reg_result = auth.register_user(username, email, password)
        if reg_result.success:
            cls.logger.info("User registered successfully", username=username)
            auth_result = auth.authenticate_user(username, password)
            if auth_result.success:
                cls.logger.info("User authenticated successfully", username=username)
                auth_token = auth_result.value
                access_token = auth_token.token
                cls.logger.info(
                    "Access token generated",
                    token_preview=(access_token[:50] + "...") if access_token else "",
                )
            else:
                cls.logger.error("Authentication failed", error=auth_result.error)
        else:
            cls.logger.error("User registration failed", error=reg_result.error)


__all__: list[str] = ["FlextAuthBasicUsageFlows"]
