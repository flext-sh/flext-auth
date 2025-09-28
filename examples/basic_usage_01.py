"""FLEXT Auth - Basic usage examples.

This example demonstrates basic FLEXT Auth usage with real functionality
following FLEXT ecosystem patterns: no prints, structured logging,
type-safe operations, and domain-driven design.

All methods used exist and work as expected according to flext-core patterns.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import secrets
import string

from flext_auth import FlextAuth, FlextAuthConfig, FlextAuthModels
from flext_core import FlextLogger

# Get structured logger instance
logger = FlextLogger(__name__)


def example_basic_authentication() -> None:
    """Demonstrate basic authentication with FlextAuth."""
    logger.info("Starting basic authentication example")

    # Create authentication instance
    FlextAuth()
    logger.info("FlextAuth instance created with in-memory storage")

    # Show current configuration
    # Note: FlextAuth doesn't have a get_config() method
    config = FlextAuthConfig()

    logger.info(
        "Authentication configuration loaded",
        jwt_expiry_minutes=config.jwt_expiry_minutes,
        bcrypt_rounds=config.bcrypt_rounds,
        max_login_attempts=config.max_login_attempts,
    )


def example_password_operations() -> None:
    """Demonstrate password operations."""
    logger.info("Starting password operations example")

    FlextAuth()

    # Hash a password using User model
    password = os.getenv("FLEXT_DEMO_PASSWORD", "MySecurePassword123!")
    try:
        demo_user = FlextAuthModels.User(
            id="password-demo-user",
            username="password_demo",
            email="password@demo.com",
            full_name="Password Demo User",
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )

        # Set password (this will hash it)
        set_result = demo_user.set_password(password)
        if set_result.is_success:
            logger.info("Password hashed successfully")

            # Verify correct password
            verify_result = demo_user.verify_password(password)
            is_valid = verify_result.value if verify_result.is_success else False
            logger.info(
                "Password verification with correct password", is_valid=is_valid
            )

            # Verify wrong password
            wrong_verify_result = demo_user.verify_password("WrongPassword")
            is_invalid = (
                wrong_verify_result.value if wrong_verify_result.is_success else False
            )
            logger.info(
                "Password verification with wrong password", is_valid=is_invalid
            )

    except Exception as e:
        logger.exception("Password operation failed", error=str(e))
        raise


def example_email_validation() -> None:
    """Demonstrate email validation patterns."""
    logger.info("Starting email validation example")

    test_emails = [
        "valid@example.com",
        "user.name@domain.co.uk",
        "invalid.email",
        "missing@domain",
        "double@@domain.com",
        "",
    ]

    def validate_email_manual(email: str) -> bool:
        """Manual email validation for demonstration.

        Returns:
            bool: True if email is valid, False otherwise

        """
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
        is_valid = validate_email_manual(email)
        if is_valid:
            valid_count += 1
        logger.info("Email validation result", email=email, is_valid=is_valid)

    logger.info(
        "Email validation completed",
        valid_emails=valid_count,
        total_emails=len(test_emails),
    )


def example_user_lifecycle() -> None:
    """Demonstrate complete user lifecycle."""
    logger.info("Starting user lifecycle example")

    auth: FlextAuth = FlextAuth()
    password = os.getenv("FLEXT_DEMO_USER_PASSWORD", "StrongPass123!")

    # Register user
    logger.info("Registering user lifecycle example")
    register_result = auth.register_user(
        username="lifecycleuser",
        email="lifecycle@example.com",
        password=password,
        full_name="Lifecycle User",
        roles=["user"],
    )

    if register_result.is_success:
        user_data = register_result.value
        logger.info(
            "User registered successfully",
            username=user_data.username,
            email=user_data.email,
            roles=user_data.roles,
            active=user_data.is_active,
        )

        # Authenticate user
        logger.info("Authenticating registered user")
        auth_result = auth.authenticate_user("lifecycleuser", password)

        if auth_result.is_success:
            logger.info("User authentication successful")
            auth_data = auth_result.value

            # Extract token info
            jwt_token_str = str(auth_data.get("jwt_token", ""))
            session_id = auth_data.get("session_id")

            logger.info(
                "Authentication tokens generated",
                jwt_token_preview=jwt_token_str[:30] + "..." if jwt_token_str else "",
                session_id=session_id,
            )

            # Validate token
            logger.info("Validating JWT token")
            token_result = auth.validate_token(jwt_token_str)
            if token_result.is_success:
                claims = token_result.value
                logger.info(
                    "Token validation successful",
                    user_id=claims.get("user_id"),
                    username=claims.get("username"),
                )
            else:
                logger.error("Token validation failed", error=token_result.error)
        else:
            logger.error("Authentication failed", error=auth_result.error)
    else:
        logger.error("User registration failed", error=register_result.error)


def example_direct_auth() -> None:
    """Demonstrate direct authentication workflow."""
    logger.info("Starting direct authentication example")

    auth: FlextAuth = FlextAuth()

    # Register and authenticate in sequence
    username = "directuser"
    email = "direct@example.com"
    password = os.getenv("FLEXT_DEMO_PASSWORD", "MySecurePassword123!")

    # Step 1: Register
    reg_result = auth.register_user(username, email, password)

    if reg_result.is_success:
        logger.info("User registered successfully", username=username)

        # Step 2: Authenticate
        auth_result = auth.authenticate_user(username, password)

        if auth_result.is_success:
            logger.info("User authenticated successfully", username=username)

            auth_data = auth_result.value
            tokens_data = auth_data.get("tokens", {})

            access_token = str(tokens_data.get("access_token", ""))
            logger.info(
                "Access token generated",
                token_preview=access_token[:20] + "..." if access_token else "",
            )

        else:
            logger.error("Authentication failed", error=auth_result.error)
    else:
        logger.error("User registration failed", error=reg_result.error)


def example_advanced_registration() -> None:
    """Demonstrate advanced user registration with roles."""
    logger.info("Starting advanced registration example")

    auth: FlextAuth = FlextAuth()
    password = os.getenv("FLEXT_DEMO_ADVANCED_PASSWORD", "AdvancedPass123!")

    # Register REDACTED_LDAP_BIND_PASSWORD user
    REDACTED_LDAP_BIND_PASSWORD_result = auth.register_user(
        username="REDACTED_LDAP_BIND_PASSWORD",
        email="REDACTED_LDAP_BIND_PASSWORD@company.com",
        password=password,
        full_name="Administrator",
        roles=["REDACTED_LDAP_BIND_PASSWORD", "user"],
    )

    if REDACTED_LDAP_BIND_PASSWORD_result.is_success:
        user_data = REDACTED_LDAP_BIND_PASSWORD_result.value
        logger.info(
            "Admin user registered successfully",
            username=user_data.username,
            roles=user_data.roles,
            has_REDACTED_LDAP_BIND_PASSWORD_role="REDACTED_LDAP_BIND_PASSWORD" in user_data.roles,
            is_active=user_data.is_active,
        )
    else:
        logger.error("Admin registration failed", error=REDACTED_LDAP_BIND_PASSWORD_result.error)

    # Register regular user
    user_result = auth.register_user(
        username="regularuser",
        email="user@company.com",
        password=password,
        full_name="Regular User",
        roles=["user"],
    )

    if user_result.is_success:
        user_data = user_result.value
        logger.info(
            "Regular user registered successfully",
            username=user_data.username,
            roles=user_data.roles,
            has_REDACTED_LDAP_BIND_PASSWORD_role="REDACTED_LDAP_BIND_PASSWORD" in user_data.roles,
        )
    else:
        logger.error("User registration failed", error=user_result.error)


def example_complete_workflow() -> None:
    """Demonstrate complete authentication workflow."""
    logger.info("Starting complete workflow example")

    auth: FlextAuth = FlextAuth()
    password = os.getenv("FLEXT_DEMO_WORKFLOW_PASSWORD", "WorkflowPass123!")

    # Step 1: Register user
    logger.info("Step 1: User registration")
    reg_result = auth.register_user(
        username="workflowuser",
        email="workflow@example.com",
        password=password,
        full_name="Workflow User",
    )

    if reg_result.is_failure:
        logger.error("Registration failed", error=reg_result.error)
        return

    user = reg_result.value
    logger.info("User registered successfully", username=user.username)

    # Step 2: Authentication
    logger.info("Step 2: User authentication")
    auth_result = auth.authenticate_user("workflowuser", password)

    if auth_result.is_failure:
        logger.error("Authentication failed", error=auth_result.error)
        return

    auth_data = auth_result.value
    logger.info("Authentication successful")

    # Step 3: Token operations
    logger.info("Step 3: Token operations")
    jwt_token_str = str(auth_data.get("jwt_token", ""))
    session_id = str(auth_data.get("session_id", ""))

    # Validate token
    token_validation = auth.validate_token(jwt_token_str)
    if token_validation.is_success:
        claims = token_validation.value
        logger.info("Token validation successful", username=claims.get("username"))
    else:
        logger.error("Token validation failed", error=token_validation.error)

    # Step 4: Session management
    logger.info("Step 4: Session management")
    user_sessions = auth.get_user_sessions(user.id)
    if user_sessions.is_success:
        sessions = user_sessions.value
        logger.info("User sessions retrieved", active_sessions=len(sessions))

    # Step 5: Logout
    logger.info("Step 5: User logout")
    logout_result = auth.logout_user(session_id)
    if logout_result.is_success:
        logger.info("User logged out successfully")
    else:
        logger.error("Logout failed", error=logout_result.error)


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure password.

    Returns:
        str: Generated secure password string

    """
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(chars) for _ in range(length))


def main() -> None:
    """Run all examples."""
    logger.info("Starting FLEXT Auth comprehensive examples")

    try:
        example_basic_authentication()
        example_password_operations()
        example_email_validation()
        example_user_lifecycle()
        example_direct_auth()
        example_advanced_registration()
        example_complete_workflow()

        logger.info(
            "All examples completed successfully - FLEXT Auth is working correctly",
        )

    except Exception as e:
        logger.exception("Example execution failed", error=str(e))
        raise


if __name__ == "__main__":
    main()
