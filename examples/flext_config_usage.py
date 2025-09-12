"""FLEXT Auth - Example of using FlextConfig as source of truth.

This example demonstrates how to use FlextConfig singleton pattern
in the flext-auth module, showing how parameters can change behavior
and how FlextConfig serves as the single source of truth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import pathlib
import sys

# Add src to path for imports
sys.path.insert(0, os.path.join(pathlib.Path(__file__).parent, "..", "src"))

from flext_auth import FlextAuth, FlextAuthConfig


def main() -> None:
    """Demonstrate FlextConfig usage in flext-auth."""
    # =========================================================================
    # 1. BASIC SINGLETON USAGE - Get global instance
    # =========================================================================

    # Get the global singleton instance (source of truth)
    FlextAuthConfig.get_global_instance()

    # =========================================================================
    # 2. ENVIRONMENT VARIABLE OVERRIDES
    # =========================================================================

    # Set environment variables to override configuration
    os.environ["FLEXT_AUTH_JWT_EXPIRY_MINUTES"] = "60"
    os.environ["FLEXT_AUTH_BCRYPT_ROUNDS"] = "14"
    os.environ["FLEXT_AUTH_MAX_LOGIN_ATTEMPTS"] = "3"
    os.environ["FLEXT_AUTH_SESSION_EXPIRY_MINUTES"] = "120"

    # Clear global instance to force reload from environment
    FlextAuthConfig.clear_global_instance()

    # Get new instance with environment overrides
    FlextAuthConfig.get_global_instance()

    # =========================================================================
    # 3. PARAMETER OVERRIDES - Change behavior with parameters
    # =========================================================================

    # Update singleton configuration with specific parameter overrides for production
    production_config_result = FlextAuthConfig.get_or_create_global(
        jwt_expiry_minutes=15,  # Shorter JWT for security
        bcrypt_rounds=12,       # Higher security
        max_login_attempts=3,   # Strict login attempts
        session_expiry_minutes=30,  # Shorter sessions
        environment="production"
    )

    if production_config_result.is_success:
        pass

    # Update singleton configuration with different parameters for development
    dev_config_result = FlextAuthConfig.get_or_create_global(
        jwt_expiry_minutes=120,  # Longer JWT for development
        bcrypt_rounds=10,        # Lower rounds for speed
        max_login_attempts=10,   # More lenient for development
        session_expiry_minutes=480,  # Longer sessions for development
        environment="development"
    )

    if dev_config_result.is_success:
        pass

    # =========================================================================
    # 4. USING CONFIG IN SERVICES - FlextConfig as source of truth
    # =========================================================================

    # Create FlextAuth instances using FlextConfig singleton as source of truth
    # Method 1: Use global singleton (default)
    FlextAuth.quick_start()  # Uses global FlextConfig singleton automatically

    # Method 2: Use production configuration singleton
    if production_config_result.is_success:
        # The singleton was already updated with production config
        FlextAuth.quick_start()  # Uses updated singleton

    # Method 3: Use development configuration singleton
    if dev_config_result.is_success:
        # The singleton was already updated with development config
        FlextAuth.quick_start()  # Uses updated singleton

    # =========================================================================
    # 5. CONFIGURATION VALIDATION
    # =========================================================================

    # Validate singleton configuration
    current_config = FlextAuthConfig.get_global_instance()
    validation_result = current_config.validate_configuration()
    if validation_result.is_success:
        pass

    # =========================================================================
    # 6. CONFIGURATION EXPORT AND SERIALIZATION
    # =========================================================================

    # Export singleton configuration settings
    singleton_config = FlextAuthConfig.get_global_instance()

    # Export security settings
    security_settings = singleton_config.get_security_settings()
    for _key, _value in security_settings.items():
        pass

    # Export JWT settings (secret excluded for security)
    jwt_settings = singleton_config.get_jwt_settings()
    for _key, _value in jwt_settings.items():
        pass

    # Export session settings
    session_settings = singleton_config.get_session_settings()
    for _key, _value in session_settings.items():
        pass

    # =========================================================================
    # 7. GLOBAL INSTANCE MANAGEMENT
    # =========================================================================

    # Demonstrate singleton instance management

    # Verify current singleton instance
    FlextAuthConfig.get_global_instance()

    # Clear singleton instance
    FlextAuthConfig.clear_global_instance()

    # Get new singleton instance (will be recreated)
    FlextAuthConfig.get_global_instance()

    # =========================================================================
    # 8. ENVIRONMENT-SPECIFIC SINGLETON CONFIGURATION
    # =========================================================================

    # Update singleton for different environments
    environments = ["development", "staging", "production"]

    for env in environments:
        config_result = FlextAuthConfig.get_or_create_global(environment=env)
        if config_result.is_success:
            pass


if __name__ == "__main__":
    main()
