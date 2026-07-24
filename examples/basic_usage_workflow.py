"""Basic FLEXT Auth workflow examples."""

from __future__ import annotations

import os
import secrets
import string

from flext_auth import FlextAuth, c, t, u


class FlextAuthBasicUsageWorkflow:
    """Reusable full workflow usage examples."""

    logger = u.fetch_logger(__name__)

    @classmethod
    def example_advanced_registration(cls) -> None:
        """Demonstrate advanced user registration with roles."""
        cls.logger.info("Starting advanced registration example")
        auth: FlextAuth = FlextAuth()
        password = os.getenv("FLEXT_DEMO_ADVANCED_PASSWORD", "AdvancedPass123!")
        register_result = auth.register_user(
            username="REDACTED_LDAP_BIND_PASSWORD",
            email="REDACTED_LDAP_BIND_PASSWORD@company.com",
            password=password,
            roles=["REDACTED_LDAP_BIND_PASSWORD", "user"],
        )
        if register_result.success:
            user_data = register_result.value
            admin_roles_payload: list[t.JsonValue] = list(user_data.roles)
            cls.logger.info(
                "Admin user registered successfully",
                name=user_data.name,
                roles=admin_roles_payload,
                has_REDACTED_LDAP_BIND_PASSWORD_role=(
                    "REDACTED_LDAP_BIND_PASSWORD" in user_data.roles
                ),
                is_active=user_data.is_active,
            )
        else:
            cls.logger.error("Admin registration failed", error=register_result.error)
        user_result = auth.register_user(
            username="regularuser",
            email="user@company.com",
            password=password,
            roles=["user"],
        )
        if user_result.success:
            user_data = user_result.value
            user_roles_payload: list[t.JsonValue] = list(user_data.roles)
            cls.logger.info(
                "Regular user registered successfully",
                name=user_data.name,
                roles=user_roles_payload,
                has_REDACTED_LDAP_BIND_PASSWORD_role=(
                    "REDACTED_LDAP_BIND_PASSWORD" in user_data.roles
                ),
            )
        else:
            cls.logger.error("User registration failed", error=user_result.error)

    @classmethod
    def example_complete_workflow(cls) -> None:
        """Demonstrate complete authentication workflow."""
        cls.logger.info("Starting complete workflow example")
        auth: FlextAuth = FlextAuth()
        password = os.getenv("FLEXT_DEMO_WORKFLOW_PASSWORD", "WorkflowPass123!")
        cls.logger.info("Step 1: User registration")
        reg_result = auth.register_user(
            username="workflowuser", email="workflow@example.com", password=password
        )
        if reg_result.failure:
            cls.logger.error("Registration failed", error=reg_result.error)
            return
        user = reg_result.value
        cls.logger.info("User registered successfully", name=user.name)
        cls.logger.info("Step 2: User authentication")
        auth_result = auth.authenticate_user("workflowuser", password)
        if auth_result.failure:
            cls.logger.error("Authentication failed", error=auth_result.error)
            return
        auth_token = auth_result.value
        cls.logger.info("Authentication successful")
        cls.logger.info("Step 3: Token operations")
        jwt_token_str = auth_token.token
        token_validation = auth.token_service.validate_token(jwt_token_str)
        if token_validation.success:
            cls.logger.info("Token validation successful", valid=token_validation.value)
        else:
            cls.logger.error("Token validation failed", error=token_validation.error)
        cls.logger.info("Step 4: Get user information")
        identity_id: str = user.name
        user_info = auth.identity_service.identity_manager.get_user(identity_id)
        if user_info.success:
            retrieved_user = user_info.value
            cls.logger.info("User information retrieved", name=retrieved_user.name)
        else:
            cls.logger.error("Failed to get user information", error=user_info.error)

    @staticmethod
    def generate_secure_password(length: int = c.Auth.CREDENTIAL_MAX_LENGTH) -> str:
        """Generate a secure password."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        return "".join(secrets.choice(chars) for _ in range(length))


__all__: list[str] = ["FlextAuthBasicUsageWorkflow"]
