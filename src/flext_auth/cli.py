"""FLEXT Auth CLI - Command line interface for authentication operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys

from flext_auth import FlextAuth, FlextAuthConfig
from flext_cli import FlextCliMain
from flext_core import FlextContainer, FlextLogger, FlextResult


class FlextAuthCli:
    """FLEXT Auth CLI - Command line interface unified class following FLEXT architecture patterns.

    This class consolidates all CLI-related functionality following FLEXT architecture patterns.
    Note: Not extending FlextDomainService as this is a CLI utility class, not a domain service.
    """

    def __init__(self) -> None:
        """Initialize FlextAuthCli with FLEXT foundation dependencies."""
        self._container = FlextContainer.get_global()
        self._logger = FlextLogger(__name__)

    def create_auth_cli(self) -> FlextResult[FlextCliMain]:
        """Create FLEXT Auth CLI using flext-cli foundation."""
        main_cli = FlextCliMain()

        self._logger.info("FLEXT Auth CLI initialized using flext-cli foundation")

        # Note: FlextCliMain and FlextCliApi don't currently support command registration
        # This would need to be implemented in flext-cli foundation first
        # For now, return the basic CLI main instance

        return FlextResult[FlextCliMain].ok(main_cli)

    def authenticate_user(
        self,
        username: str,
        password: str,
        jwt_expiry: int | None = None,
        bcrypt_rounds: int | None = None,
        environment: str = "development",
    ) -> FlextResult[None]:
        """Authenticate user with configurable parameters."""
        # Use FlextConfig singleton with CLI overrides
        config_result = FlextAuthConfig.create_from_cli_params(
            jwt_expiry=jwt_expiry, bcrypt_rounds=bcrypt_rounds, environment=environment
        )

        if config_result.is_failure:
            self._logger.error("Configuration failed", error=config_result.error)
            return FlextResult[None].fail(config_result.error or "Configuration failed")

        # Create FlextAuth with the configured singleton
        auth: FlextAuth = FlextAuth(config=config_result.value)

        # Perform authentication
        auth_result = auth.authenticate_user(username, password)

        if auth_result.is_success:
            user_data = auth_result.value
            # Log authentication success with user info if available
            username_logged = False
            if isinstance(user_data, dict) and "user" in user_data:
                user_info = user_data["user"]
                if isinstance(user_info, dict) and "username" in user_info:
                    self._logger.info(
                        f"Authentication successful for {user_info['username']}"
                    )
                    username_logged = True

            if not username_logged:
                self._logger.info("Authentication successful")
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
        max_attempts: int | None = None,
        session_expiry: int | None = None,
        environment: str = "development",
    ) -> FlextResult[None]:
        """Register new user with configurable parameters."""
        # Use FlextConfig singleton with CLI overrides
        config_result = FlextAuthConfig.create_from_cli_params(
            max_attempts=max_attempts,
            session_expiry=session_expiry,
            environment=environment,
        )

        if config_result.is_failure:
            self._logger.error(f"Configuration failed: {config_result.error}")
            return FlextResult[None].fail(config_result.error or "Configuration failed")

        # Create FlextAuth with the configured singleton
        auth: FlextAuth = FlextAuth(config=config_result.value)

        # Register user
        register_result = auth.register_user(username, email, password)

        if register_result.is_success:
            user = register_result.value
            self._logger.info(
                f"User registered successfully: {user.username} ({user.email})"
            )
            self._logger.info(
                f"Max Login Attempts: {config_result.value.max_login_attempts}"
            )
            self._logger.info(
                f"Session Expiry: {config_result.value.session_expiry_minutes} minutes"
            )
        else:
            self._logger.error(f"Registration failed: {register_result.error}")
            return FlextResult[None].fail(
                register_result.error or "Registration failed"
            )

        return FlextResult[None].ok(None)

    def manage_config(
        self,
        *,
        show: bool = False,
        set_jwt_expiry: int | None = None,
        set_bcrypt_rounds: int | None = None,
        set_max_attempts: int | None = None,
        environment: str = "development",
    ) -> FlextResult[None]:
        """Manage FlextConfig singleton configuration."""
        # Update global config with CLI parameters
        config_result = FlextAuthConfig.update_global_from_cli(
            jwt_expiry=set_jwt_expiry,
            bcrypt_rounds=set_bcrypt_rounds,
            max_attempts=set_max_attempts,
            environment=environment,
        )

        if config_result.is_failure:
            self._logger.error(f"Configuration failed: {config_result.error}")
            return FlextResult[None].fail(config_result.error or "Configuration failed")

        config = config_result.value

        if show or not any([set_jwt_expiry, set_bcrypt_rounds, set_max_attempts]):
            # Show current configuration using CLI summary
            summary_result = FlextAuthConfig.get_global_cli_summary()
            if summary_result.is_success:
                summary = summary_result.value
                self._logger.info("Current FlextConfig Singleton Configuration:")
                self._logger.info(f"  Environment: {summary['environment']}")
                self._logger.info(
                    f"  JWT Expiry: {summary['jwt_expiry_minutes']} minutes"
                )
                self._logger.info(f"  Bcrypt Rounds: {summary['bcrypt_rounds']}")
                self._logger.info(
                    f"  Max Login Attempts: {summary['max_login_attempts']}"
                )
                self._logger.info(
                    f"  Session Expiry: {summary['session_expiry_minutes']} minutes"
                )
                self._logger.info(
                    f"  Lockout Duration: {summary['lockout_duration_minutes']} minutes"
                )
            else:
                self._logger.error(
                    f"Failed to get config summary: {summary_result.error}"
                )
                return FlextResult[None].fail(
                    summary_result.error or "Failed to get config summary"
                )
        else:
            # Configuration was updated
            self._logger.info("Configuration updated successfully")
            self._logger.info(f"New JWT Expiry: {config.jwt_expiry_minutes} minutes")
            self._logger.info(f"New Bcrypt Rounds: {config.bcrypt_rounds}")
            self._logger.info(f"New Max Login Attempts: {config.max_login_attempts}")

        return FlextResult[None].ok(None)

    def validate_config(self) -> FlextResult[None]:
        """Validate FlextConfig singleton configuration."""
        # Get global config
        config = FlextAuthConfig.get_global_instance()

        # Validate configuration
        validation_result = config.validate_configuration()

        if validation_result.is_success:
            self._logger.info("Configuration validation passed")
            self._logger.info("All configuration parameters are valid")
            self._logger.info(f"Environment: {config.environment}")
        else:
            self._logger.error(
                f"Configuration validation failed: {validation_result.error}"
            )
            return FlextResult[None].fail(
                validation_result.error or "Configuration validation failed"
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
