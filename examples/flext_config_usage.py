"""FLEXT Auth - Example of using FlextCore.Config as source of truth.

This example demonstrates how to use FlextCore.Config singleton pattern
in the flext-auth module, showing how parameters can change behavior
and how FlextCore.Config serves as the single source of truth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os

from flext_auth import FlextAuth, FlextAuthConfig
from flext_auth.constants import FlextAuthConstants


def main() -> None:
    """Demonstrate FlextCore.Config usage in flext-auth."""
    # =========================================================================
    # 1. BASIC SINGLETON USAGE - Get global instance
    # =========================================================================

    # Get the global singleton instance (source of truth)
    FlextAuthConfig.get_global_instance()

    # =========================================================================
    # 2. ENVIRONMENT VARIABLE OVERRIDES
    # =========================================================================

    # Set environment variables to override configuration
    os.environ["FLEXT_AUTH_JWT_EXPIRY_MINUTES"] = str(
        FlextAuthConstants.Jwt.DEFAULT_EXPIRY_MINUTES * 2
    )
    os.environ["FLEXT_AUTH_BCRYPT_ROUNDS"] = str(
        FlextAuthConstants.Credentials.Password.BCRYPT_ROUNDS + 2
    )
    os.environ["FLEXT_AUTH_MAX_LOGIN_ATTEMPTS"] = str(
        FlextAuthConstants.Security.MAX_LOGIN_ATTEMPTS
    )
    os.environ["FLEXT_AUTH_SESSION_EXPIRY_MINUTES"] = str(
        FlextAuthConstants.Session.DEFAULT_EXPIRY_MINUTES
    )

    # Clear global instance to force reload from environment
    FlextAuthConfig.reset_global_instance()

    # Get new instance with environment overrides
    FlextAuthConfig.get_global_instance()

    # =========================================================================
    # 3. PARAMETER OVERRIDES - Change behavior with parameters
    # =========================================================================

    # Update singleton configuration with specific parameter overrides for production
    production_config_result = FlextAuthConfig.get_or_create_global(
        jwt_expiry_minutes=FlextAuthConstants.Jwt.DEFAULT_EXPIRY_MINUTES
        // 2,  # Shorter JWT for security
        bcrypt_rounds=FlextAuthConstants.Credentials.Password.BCRYPT_ROUNDS,  # Higher security
        max_login_attempts=FlextAuthConstants.Security.MAX_LOGIN_ATTEMPTS,  # Strict login attempts
        session_expiry_minutes=FlextAuthConstants.Jwt.DEFAULT_EXPIRY_MINUTES,  # Shorter sessions
        environment="production",
    )

    if production_config_result.is_success:
        pass

    # Update singleton configuration with different parameters for development
    dev_config_result = FlextAuthConfig.get_or_create_global(
        jwt_expiry_minutes=FlextAuthConstants.Session.DEFAULT_EXPIRY_MINUTES,  # Longer JWT for development
        bcrypt_rounds=FlextAuthConstants.Credentials.Password.MIN_BCRYPT_ROUNDS,  # Lower rounds for speed
        max_login_attempts=FlextAuthConstants.Session.MAX_SESSIONS_PER_USER
        * 2,  # More lenient for development
        session_expiry_minutes=FlextAuthConstants.Session.MAX_EXPIRY_MINUTES
        // 3,  # Longer sessions for development
        environment="development",
    )

    if dev_config_result.is_success:
        pass

    # =========================================================================
    # 4. USING CONFIG IN SERVICES - FlextCore.Config as source of truth
    # =========================================================================

    # Create FlextAuth instances using FlextCore.Config singleton as source of truth
    # Method 1: Use global singleton (default)
    FlextAuth.quick_start()  # Uses global FlextCore.Config singleton automatically

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
    # Note: get_security_settings() doesn't exist, use direct attributes
    security_settings = {
        "max_login_attempts": singleton_config.max_login_attempts,
        "bcrypt_rounds": singleton_config.bcrypt_rounds,
        "min_password_length": singleton_config.min_password_length,
    }
    for _key, _value in security_settings.items():
        pass

    # Export JWT settings (secret excluded for security)
    # Note: get_jwt_settings() doesn't exist, use direct attributes
    jwt_settings = {
        "jwt_algorithm": singleton_config.jwt_algorithm,
        "jwt_expiry_minutes": singleton_config.jwt_expiry_minutes,
        "jwt_issuer": singleton_config.jwt_issuer,
    }
    for _key, _value in jwt_settings.items():
        pass

    # Export session settings
    # Note: get_session_settings() doesn't exist, use direct attributes
    session_settings = {
        "session_expiry_minutes": singleton_config.session_expiry_minutes,
        "jwt_expiry_minutes": singleton_config.jwt_expiry_minutes,
    }
    for _key, _value in session_settings.items():
        pass

    # =========================================================================
    # 7. GLOBAL INSTANCE MANAGEMENT
    # =========================================================================

    # Demonstrate singleton instance management

    # Verify current singleton instance
    FlextAuthConfig.get_global_instance()

    # Clear singleton instance
    FlextAuthConfig.reset_global_instance()

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
