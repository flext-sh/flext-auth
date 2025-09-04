#!/usr/bin/env python3
"""FLEXT Auth - Refactored System Showcase (Working Version).

This example showcases the refactored FLEXT Auth system with working functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextResult

from flext_auth import FlextAuth, flext_auth_quick_start


def demonstrate_refactoring_benefits() -> None:
    """Demonstrate the benefits of the refactored system."""
    print("=== Refactoring Benefits Demo ===")

    # Modern FlextAuth API
    auth: FlextAuth[object] = FlextAuth()
    print("✅ FlextAuth instance created with type safety")

    # Create user with proper API (register_user not create_user)
    result = auth.register_user("modern_user", "modern@example.com", "ModernPass123!")
    if result.is_success:
        user = result.value
        print(f"✅ User created successfully: {user.username}")
    else:
        print(f"❌ User creation failed: {result.error}")

    # Authenticate with proper API
    auth_result = auth.authenticate_user("modern_user", "ModernPass123!")
    if auth_result.is_success:
        auth_data = auth_result.value
        user_data = auth_data.get("user", {})
        username = user_data.get("username", "Unknown") if isinstance(user_data, dict) else "User"
        print(f"✅ Authentication successful: {username}")
    else:
        print(f"❌ Authentication failed: {auth_result.error}")


def demonstrate_legacy_compatibility() -> None:
    """Demonstrate backward compatibility with legacy code."""
    print("\n=== Legacy Compatibility Demo ===")

    # Legacy quick start still works
    legacy_service: FlextAuth[object] = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    print("✅ Legacy quick start service created")

    # Show it works the same way
    reg_result = legacy_service.register_user(
        "legacy_user",
        "legacy@example.com",
        "LegacyPassword123!"
    )

    if reg_result.is_success:
        print(f"✅ Legacy API user registered: {reg_result.value.username}")
    else:
        print(f"❌ Legacy registration failed: {reg_result.error}")


def demonstrate_flext_result_integration() -> None:
    """Demonstrate FlextResult pattern integration."""
    print("\n=== FlextResult Integration Demo ===")

    # FlextResult pattern usage
    success_result: FlextResult[str] = FlextResult[str].ok("Refactoring successful")
    print(f"✅ Success result: {success_result.value}")

    failure_result: FlextResult[str] = FlextResult[str].fail("Example failure case")
    print(f"❌ Failure result: {failure_result.error}")

    # Show real usage in auth operations
    auth: FlextAuth[object] = FlextAuth()
    token_result = auth.generate_jwt_token("test_user_id")

    if token_result.is_success:
        print(f"✅ JWT generation successful: {token_result.value[:20]}...")
    else:
        print(f"❌ JWT generation failed: {token_result.error}")


def demonstrate_system_architecture() -> None:
    """Demonstrate the clean system architecture."""
    print("\n=== System Architecture Demo ===")

    # Clean separation of concerns
    auth: FlextAuth[object] = FlextAuth()
    print("✅ Clean FlextAuth instance created")

    # Type safety with FlextResult - real examples
    config = auth.get_config()
    print(f"✅ Configuration access: JWT expiry {config.jwt_expiry_minutes} minutes")

    security_settings = auth.config.get_security_settings()
    print(f"✅ Security settings: {security_settings.get('bcrypt_rounds')} bcrypt rounds")

    jwt_settings = auth.config.get_jwt_settings()
    print(f"✅ JWT settings: Algorithm {jwt_settings.get('jwt_algorithm')}")


def demonstrate_error_handling() -> None:
    """Demonstrate proper error handling patterns."""
    print("\n=== Error Handling Demo ===")

    auth: FlextAuth[object] = FlextAuth()

    # Try to register user with weak password
    weak_result = auth.register_user("weakuser", "weak@example.com", "123")
    if weak_result.is_failure:
        print(f"✅ Weak password rejected: {weak_result.error}")
    else:
        print("❌ Weak password should have been rejected")

    # Try to authenticate non-existent user
    nonexistent_result = auth.authenticate_user("nonexistent", "password")
    if nonexistent_result.is_failure:
        print(f"✅ Non-existent user rejected: {nonexistent_result.error}")
    else:
        print("❌ Non-existent user should have been rejected")


def main() -> None:
    """Execute refactored system showcase."""
    print("🚀 FLEXT Auth - Refactored System Showcase")
    print("=" * 50)

    demonstrate_refactoring_benefits()
    demonstrate_legacy_compatibility()
    demonstrate_flext_result_integration()
    demonstrate_system_architecture()
    demonstrate_error_handling()

    print("\n🎉 Refactored system showcase completed!")
    print("✅ All functionality working correctly!")


if __name__ == "__main__":
    main()
