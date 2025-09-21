"""FLEXT Auth CLI Configuration Integration Example.

This example demonstrates how CLI parameters can override FlextConfig singleton
behavior while maintaining FlextConfig as the single source of truth for
authentication configuration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os

from flext_auth import FlextAuth, FlextAuthConfig


def demonstrate_cli_config_integration() -> None:
    """Demonstrate how CLI parameters integrate with FlextConfig singleton."""
    # =========================================================================
    # 1. BASIC SINGLETON BEHAVIOR
    # =========================================================================

    # Get global singleton instance
    FlextAuthConfig.get_global_instance()

    # =========================================================================
    # 2. CLI PARAMETER OVERRIDES
    # =========================================================================

    # Simulate CLI parameters that would override configuration
    cli_params = {
        "jwt_expiry_minutes": 15,  # Shorter for security
        "bcrypt_rounds": 12,  # Higher security
        "max_login_attempts": 3,  # Stricter login
        "session_expiry_minutes": 30,  # Shorter sessions
    }

    for _key, _value in cli_params.items():
        pass

    # Create new config with CLI overrides
    config_with_overrides_result = FlextAuthConfig.get_or_create_global(
        environment="production",
        **cli_params,
    )

    if config_with_overrides_result.is_success:
        pass

    # =========================================================================
    # 3. FLEXT AUTH WITH CLI CONFIGURATION
    # =========================================================================

    # Create FlextAuth with the CLI-configured singleton
    if config_with_overrides_result.is_success:
        auth = FlextAuth(config=config_with_overrides_result.value)

        # Register a test user with CLI-configured settings
        # Note: This is a test password for demonstration purposes only
        test_password = os.getenv("CLI_TEST_PASSWORD", "CliTestPassword123!")
        register_result = auth.register_user(
            username="cli_test_user",
            email="cli_test@example.com",
            password=test_password,
        )

        if register_result.is_success:
            # Authenticate with CLI-configured settings
            auth_result = auth.authenticate_user("cli_test_user", test_password)

            if auth_result.is_success:
                pass

    # =========================================================================
    # 4. CLI SERVICE SIMULATION
    # =========================================================================

    # CLI service simulation (would be created from flext-cli)

    # Simulate CLI command execution with different parameters
    cli_scenarios: list[dict[str, str | dict[str, int | str]]] = [
        {
            "name": "Development Environment",
            "params": {
                "jwt_expiry_minutes": 120,
                "bcrypt_rounds": 10,
                "max_login_attempts": 10,
                "environment": "development",
            },
        },
        {
            "name": "Production Environment",
            "params": {
                "jwt_expiry_minutes": 15,
                "bcrypt_rounds": 12,
                "max_login_attempts": 3,
                "environment": "production",
            },
        },
        {
            "name": "Testing Environment",
            "params": {
                "jwt_expiry_minutes": 5,
                "bcrypt_rounds": 8,
                "max_login_attempts": 20,
                "environment": "testing",
            },
        },
    ]

    for scenario in cli_scenarios:
        # Create config for this scenario
        params = scenario["params"]
        if isinstance(params, dict):
            # Ensure environment is a string
            if "environment" in params and isinstance(params["environment"], str):
                scenario_config_result = FlextAuthConfig.get_or_create_global(**params)
            else:
                # Skip if environment is not a string
                continue
        else:
            # Skip if params is not a dict
            continue

        if scenario_config_result.is_success:
            scenario_config = scenario_config_result.value

            # Validate configuration
            validation_result = scenario_config.validate_configuration()
            if validation_result.is_success:
                pass

    # =========================================================================
    # 5. SINGLETON CONSISTENCY VERIFICATION
    # =========================================================================

    # Verify that the same instance is returned when no overrides are provided
    FlextAuthConfig.get_global_instance()
    FlextAuthConfig.get_global_instance()

    # Verify that overrides create new instances
    override_config_result = FlextAuthConfig.get_or_create_global(
        jwt_expiry_minutes=999,
        environment="override_test",
    )

    if override_config_result.is_success:
        pass


def demonstrate_cli_command_simulation() -> None:
    """Simulate CLI command execution with different parameter combinations."""
    # Simulate different CLI commands with various parameter combinations
    commands: list[dict[str, str | dict[str, int]]] = [
        {
            "command": (
                "flext-auth authenticate --username testuser --password testpass "
                "--jwt-expiry 30"
            ),
            "params": {"jwt_expiry_minutes": 30},
        },
        {
            "command": (
                "flext-auth register --username newuser --email new@example.com "
                "--password newpass --bcrypt-rounds 14"
            ),
            "params": {"bcrypt_rounds": 14},
        },
        {
            "command": "flext-auth config --set-jwt-expiry 60 --set-max-attempts 5",
            "params": {"jwt_expiry_minutes": 60, "max_login_attempts": 5},
        },
    ]

    for cmd_info in commands:
        # Create config with command parameters
        params = cmd_info["params"]
        if isinstance(params, dict):
            config_result = FlextAuthConfig.get_or_create_global(
                environment="cli_simulation",
                **params,
            )
        else:
            # Skip if params is not a dict
            continue

        if config_result.is_success:
            pass


if __name__ == "__main__":
    demonstrate_cli_config_integration()
    demonstrate_cli_command_simulation()
