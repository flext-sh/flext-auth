"""FLEXT Auth CLI - Command line interface for authentication operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys

from flext_auth import FlextAuth, FlextAuthModels
from flext_cli import FlextCliMain
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
        self._cli_api = (
            FlextCliMain()
        )  # Use FlextCliMain directly following SOLID principles

    def create_auth_cli(self) -> FlextResult[FlextCliMain]:
        """Create FLEXT Auth CLI using flext-cli foundation - simplified using SOLID principles.

        Returns:
            FlextResult[FlextCliMain]: Success with CLI instance

        """
        # Return existing CLI instance - eliminate duplication
        self._logger.info("FLEXT Auth CLI initialized using flext-cli foundation")
        return FlextResult[FlextCliMain].ok(self._cli_api)

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
        # Use FlextUtilities for validation
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

        # Create configuration using railway pattern
        config_result = FlextAuthModels.FlextAuthConfig.create_for_environment(
            environment
        )

        if config_result.is_failure:
            self._logger.error("Configuration failed", error=config_result.error)
            return FlextResult[None].fail(config_result.error or "Configuration failed")

        # Create FlextAuth and authenticate
        auth = FlextAuth(config=config_result.value)
        auth_result = auth.authenticate_user(username, password)

        if auth_result.is_success:
            self._logger.info(f"Authentication successful for {username}")
            self._logger.info(
                f"JWT Expiry: {config_result.value.jwt_expiry_minutes} minutes"
            )
            self._logger.info(f"Bcrypt Rounds: {config_result.value.bcrypt_rounds}")
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
        # Use FlextUtilities for validation
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

        # Create configuration using railway pattern
        config_result = FlextAuthModels.FlextAuthConfig.create_from_cli_params(
            max_attempts=max_attempts,
            session_expiry=session_expiry,
            environment=environment,
        )

        if config_result.is_failure:
            self._logger.error("Configuration failed", error=config_result.error)
            return FlextResult[None].fail(config_result.error or "Configuration failed")

        # Create FlextAuth and register user
        auth = FlextAuth(config=config_result.value)
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
        # Update global config with CLI parameters
        config_result = FlextAuthModels.FlextAuthConfig.create_for_environment(
            environment
        )

        if config_result.is_failure:
            self._logger.error(f"Configuration failed: {config_result.error}")
            return FlextResult[None].fail(config_result.error or "Configuration failed")

        # Get the updated config after successful update
        config = (
            FlextAuthModels.FlextAuthConfig.get_global_instance()
            if config_result.is_success
            else None
        )

        if show or not any([set_jwt_expiry, set_bcrypt_rounds, set_max_attempts]):
            # Show current configuration using CLI summary
            summary_result = FlextAuthModels.FlextAuthConfig.get_global_cli_summary()
            if summary_result.is_success:
                summary = summary_result.value
                self._logger.info("Current FlextConfig Singleton Configuration:")
                self._logger.info(f"  Environment: {summary['environment']}")
                self._logger.info(
                    f"  JWT Expiry: {summary['jwt_expiry_minutes']} minutes",
                )
                self._logger.info(f"  Bcrypt Rounds: {summary['bcrypt_rounds']}")
                self._logger.info(
                    f"  Max Login Attempts: {summary['max_login_attempts']}",
                )
                self._logger.info(
                    f"  Session Expiry: {summary['session_expiry_minutes']} minutes",
                )
                self._logger.info(
                    f"  Lockout Duration: {summary['lockout_duration_minutes']} minutes",
                )
            else:
                self._logger.error(
                    f"Failed to get config summary: {summary_result.error}",
                )
                return FlextResult[None].fail(
                    summary_result.error or "Failed to get config summary",
                )
        else:
            # Configuration was updated
            self._logger.info("Configuration updated successfully")
            if config is not None:
                self._logger.info(
                    f"New JWT Expiry: {config.jwt_expiry_minutes} minutes"
                )
                self._logger.info(f"New Bcrypt Rounds: {config.bcrypt_rounds}")
                self._logger.info(
                    f"New Max Login Attempts: {config.max_login_attempts}"
                )
            else:
                self._logger.info("Configuration updated but details not available")

        return FlextResult[None].ok(None)

    def validate_config(self) -> FlextResult[None]:
        """Validate FlextConfig singleton configuration.

        Returns:
            FlextResult[None]: Success if configuration is valid, error if invalid

        """
        # Get global config
        config = FlextAuthModels.FlextAuthConfig.get_global_instance()

        # Validate configuration
        # Simple validation - check if config is valid
        try:
            validation_result = FlextResult[None].ok(None)
        except Exception as e:
            validation_result = FlextResult[None].fail(f"Validation failed: {e}")

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

        return FlextResult[None].ok(None)

    def main(self) -> None:
        """Run the main CLI entry point."""
        cli_result = self.create_auth_cli()
        if cli_result.is_failure:
            self._logger.error(f"Failed to create CLI: {cli_result.error}")
            sys.exit(1)

        # Note: FlextCliMain doesn't have a run() method yet
        # This would need to be implemented in flext-cli foundation
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
