"""FLEXT Auth CLI - Command line interface for authentication operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys

from flext_auth import FlextAuth
from flext_auth.config import FlextAuthConfig
from flext_cli import FlextCliCommands
from flext_core import FlextContainer, FlextLogger, FlextResult, FlextUtilities


class FlextAuthCli:
    """FLEXT Auth CLI - Command line interface unified class following FLEXT architecture patterns.

    This class consolidates all CLI-related functionality following FLEXT architecture patterns.
    Note: Not extending FlextService as this is a CLI utility class, not a domain service.
    """

    def __init__(self) -> None:
        """Initialize FlextAuthCli with FLEXT foundation dependencies."""
        self._container = FlextContainer.get_global()
        self._logger = FlextLogger(__name__)
        self._cli_api = FlextCliCommands()

    def create_auth_cli(self) -> FlextResult[FlextCliCommands]:
        """Create FLEXT Auth CLI using flext-cli foundation - simplified using SOLID principles.

        Returns:
            FlextResult[FlextCliCommands]: Success with CLI instance

        """
        self._logger.info("FLEXT Auth CLI initialized using flext-cli foundation")
        return FlextResult[FlextCliCommands].ok(self._cli_api)

    def authenticate_user(
        self,
        username: str,
        password: str,
        jwt_expiry: int | None = None,
        bcrypt_rounds: int | None = None,
        environment: str = "development",
    ) -> FlextResult[None]:
        """Authenticate user with configurable parameters - simplified using SOLID principles.

        Returns:
            FlextResult[None]: Success if authentication succeeds, error if fails

        """
        username_validation = FlextUtilities.Validation.validate_string(
            username, field_name="username"
        )
        if username_validation.is_failure:
            return FlextResult[None].fail(
                username_validation.error or "Username validation failed"
            )

        password_validation = FlextUtilities.Validation.validate_string(
            password, field_name="password"
        )
        if password_validation.is_failure:
            return FlextResult[None].fail(
                password_validation.error or "Password validation failed"
            )

        try:
            config = FlextAuthConfig.create_for_environment(environment)
        except Exception as e:
            return FlextResult[None].fail(f"Configuration creation failed: {e}")

        # Apply parameter overrides if provided
        if jwt_expiry is not None:
            config.jwt_expiry_minutes = jwt_expiry
        if bcrypt_rounds is not None:
            config.bcrypt_rounds = bcrypt_rounds

        auth = FlextAuth(config=config)
        auth_result = auth.authenticate_user(username, password)

        if auth_result.is_success:
            self._logger.info(f"Authentication successful for {username}")
            self._logger.info(f"JWT Expiry: {config.jwt_expiry_minutes} minutes")
            self._logger.info(f"Bcrypt Rounds: {config.bcrypt_rounds}")
        else:
            self._logger.error(f"Authentication failed: {auth_result.error}")
            return FlextResult[None].fail(auth_result.error or "Authentication failed")

        return FlextResult[None].ok(None)

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        *,
        max_attempts: int | None = None,
        session_expiry: int | None = None,
        environment: str = "development",
    ) -> FlextResult[None]:
        """Register new user with configurable parameters - simplified using SOLID principles.

        Returns:
            FlextResult[None]: Success if registration succeeds, error if fails

        """
        username_validation = FlextUtilities.Validation.validate_string(
            username, field_name="username"
        )
        if username_validation.is_failure:
            return FlextResult[None].fail(
                username_validation.error or "Username validation failed"
            )

        email_validation = FlextUtilities.Validation.validate_email(email)
        if email_validation.is_failure:
            return FlextResult[None].fail(
                email_validation.error or "Email validation failed"
            )

        password_validation = FlextUtilities.Validation.validate_string(
            password, field_name="password"
        )
        if password_validation.is_failure:
            return FlextResult[None].fail(
                password_validation.error or "Password validation failed"
            )

        try:
            config = FlextAuthConfig.create_for_environment(environment)
        except Exception as e:
            return FlextResult[None].fail(f"Configuration creation failed: {e}")

        # Apply parameter overrides if provided
        if max_attempts is not None:
            config.max_login_attempts = max_attempts
        if session_expiry is not None:
            config.session_expiry_hours = session_expiry

        auth = FlextAuth(config=config)
        auth_result = auth.register_user(username, email, password)

        if auth_result.is_success:
            self._logger.info(f"User registered successfully: {username}")
            return FlextResult[None].ok(None)

        self._logger.error(f"User registration failed: {auth_result.error}")
        return FlextResult[None].fail(auth_result.error or "User registration failed")

    def manage_config(
        self,
        *,
        show: bool = False,
        set_jwt_expiry: int | None = None,
        set_bcrypt_rounds: int | None = None,
        set_max_attempts: int | None = None,
        environment: str = "development",
    ) -> FlextResult[None]:
        """Manage FlextConfig singleton configuration.

        Returns:
            FlextResult[None]: Success if configuration updated, error if fails

        """
        try:
            config = FlextAuthConfig.create_for_environment(environment)
        except Exception as e:
            self._logger.exception("Configuration failed")
            return FlextResult[None].fail(f"Configuration failed: {e}")

        FlextAuthConfig.set_global_instance(config)

        if show or not any([set_jwt_expiry, set_bcrypt_rounds, set_max_attempts]):
            if config:
                self._logger.info("Current FlextConfig Singleton Configuration:")
                self._logger.info(f"  Environment: {environment}")
                self._logger.info(
                    f"  JWT Expiry: {config.jwt_expiry_minutes} minutes",
                )
                self._logger.info(f"  Bcrypt Rounds: {config.bcrypt_rounds}")
                self._logger.info(
                    f"  Max Login Attempts: {config.max_login_attempts}",
                )
                self._logger.info(
                    f"  Session Expiry: {config.session_expiry_hours} hours",
                )
                self._logger.info(
                    f"  Lockout Duration: {config.lockout_duration_minutes} minutes",
                )
            else:
                self._logger.error(
                    "Failed to get config - config object is None",
                )
                return FlextResult[None].fail(
                    "Failed to get config - config object is None",
                )
        else:
            self._logger.info("Configuration updated successfully")
            self._logger.info(f"New JWT Expiry: {config.jwt_expiry_minutes} minutes")
            self._logger.info(f"New Bcrypt Rounds: {config.bcrypt_rounds}")
            self._logger.info(f"New Max Login Attempts: {config.max_login_attempts}")

        return FlextResult[None].ok(None)

    def validate_config(self) -> FlextResult[None]:
        """Validate FlextConfig singleton configuration.

        Returns:
            FlextResult[None]: Success if configuration is valid, error if invalid

        """
        config: FlextAuthConfig = FlextAuthConfig.get_global_instance()
        validation_result: FlextResult[None] = config.validate_business_rules()

        if validation_result.is_success:
            self._logger.info("Configuration validation passed")
            self._logger.info("All configuration parameters are valid")
            self._logger.info(f"Environment: {config.environment}")
        else:
            self._logger.error(
                f"Configuration validation failed: {validation_result.error}",
            )
            return FlextResult[None].fail(
                validation_result.error or "Configuration validation failed",
            )

        return validation_result

    def main(self) -> None:
        """Run the main CLI entry point."""
        cli_result: FlextResult[FlextCliCommands] = self.create_auth_cli()
        if cli_result.is_failure:
            self._logger.error(f"Failed to create CLI: {cli_result.error}")
            sys.exit(1)

        self._logger.info("FLEXT Auth CLI created successfully")


# Global instance for direct access - no wrapper functions
flext_auth_cli = FlextAuthCli()


def main() -> None:
    """Standalone main function for CLI entry point."""
    flext_auth_cli.main()


__all__: list[str] = [
    "FlextAuthCli",
    "flext_auth_cli",
    "main",
]


if __name__ == "__main__":
    main()
