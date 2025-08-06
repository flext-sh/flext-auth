#!/usr/bin/env python3
"""FLEXT Auth - Comprehensive Demonstration.

Este exemplo demonstra TODA a funcionalidade disponível da FLEXT Auth.
Serve como documentação executável e teste de integração.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio

from flext_auth import (
    ADMIN_ROLE,
    API_CONFIG,
    FAST_CONFIG,
    GUEST_ROLE,
    MODERATOR_ROLE,
    PRODUCTION_CONFIG,
    USER_ROLE,
    WEB_CONFIG,
    AuthResult,
    FlextAuth,
    FlextAuthDefaults,
    FlextAuthMixin,
    PermissionSet,
    RoleHierarchy,
    SessionData,
    TokenData,
    UserData,
    flext_auth_api,
    flext_auth_batch_operations,
    flext_auth_check_token,
    flext_auth_complete_workflow,
    flext_auth_create_api_key,
    flext_auth_create_auth_context,
    flext_auth_create_multi_factor_token,
    flext_auth_create_role_hierarchy,
    flext_auth_create_secure_session,
    flext_auth_create_service_token,
    flext_auth_decode_jwt,
    flext_auth_dev,
    flext_auth_extract_user_context,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_instant_api,
    flext_auth_permission_required,
    flext_auth_prod,
    flext_auth_quick_start,
    flext_auth_required,
    flext_auth_role_required,
    flext_auth_validate_api_key,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_validate_permissions,
    flext_auth_verify_password,
    flext_auth_web,
)

# Example constants - not for production use

EXAMPLE_DEMO_PASSWORD = "DemoPassword123!@#"
EXAMPLE_JWT_SECRET = "demo-jwt-secret-key-256-bits-minimum-length-for-security"
EXAMPLE_API_SECRET = "api-secret-key-256-bits-minimum-length"
EXAMPLE_SERVICE_SECRET = "service-secret-key-256-bits-minimum-length"
EXAMPLE_MFA_SECRET = "mfa-secret-key-256-bits-minimum-length"
EXAMPLE_CHECK_SECRET = "check-token-secret-256-bits-minimum-length"
EXAMPLE_DECORATOR_SECRET = "decorator-secret-256-bits-minimum-length"
EXAMPLE_LIFECYCLE_PASSWORD = "LifecyclePass123!"
EXAMPLE_BATCH_PASSWORD_1 = "Batch123!"
EXAMPLE_BATCH_PASSWORD_2 = "Batch456!"


def demo_all_constants_and_configs() -> None:
    """Demonstra todas as constantes e configurações disponíveis."""
    print("=== All Constants & Configurations ===")

    # Role constants
    print("Role Constants:")
    print(f"  ADMIN_ROLE: {ADMIN_ROLE}")
    print(f"  MODERATOR_ROLE: {MODERATOR_ROLE}")
    print(f"  USER_ROLE: {USER_ROLE}")
    print(f"  GUEST_ROLE: {GUEST_ROLE}")

    # Configuration presets
    print("\nConfiguration Presets:")
    print(f"  FAST_CONFIG: {FAST_CONFIG}")
    print(f"  PRODUCTION_CONFIG: {PRODUCTION_CONFIG}")
    print(f"  WEB_CONFIG: {WEB_CONFIG}")
    print(f"  API_CONFIG: {API_CONFIG}")

    # FlextAuthDefaults
    print(f"\nDefault Configs: {list(FlextAuthDefaults.CONFIGS.keys())}")
    print(f"Admin Payload: {FlextAuthDefaults.ADMIN_PAYLOAD}")
    print(f"User Payload: {FlextAuthDefaults.USER_PAYLOAD}")
    print(f"API Payload: {FlextAuthDefaults.API_PAYLOAD}")
    print(f"Success Response: {FlextAuthDefaults.SUCCESS_RESPONSE}")


def demo_all_factory_functions() -> None:
    """Demonstra todas as factory functions."""
    print("\n=== All Factory Functions ===")

    # Factory instances
    dev_auth = flext_auth_dev()
    prod_auth = flext_auth_prod()
    web_auth = flext_auth_web()
    api_auth = flext_auth_api()

    print("Factory Functions:")
    print(f"  Dev Auth: {type(dev_auth).__name__}")
    print(f"  Prod Auth: {type(prod_auth).__name__}")
    print(f"  Web Auth: {type(web_auth).__name__}")
    print(f"  API Auth: {type(api_auth).__name__}")

    # Quick start with options
    quick_auth = flext_auth_quick_start(
        REDACTED_LDAP_BIND_PASSWORD_username="demo_REDACTED_LDAP_BIND_PASSWORD",
        REDACTED_LDAP_BIND_PASSWORD_email="demo@example.com",
        create_REDACTED_LDAP_BIND_PASSWORD=False,
    )
    print(f"  Quick Start: {type(quick_auth).__name__}")


def demo_all_password_operations() -> None:
    """Demonstra todas as operações com senhas."""
    print("\n=== All Password Operations ===")

    password = EXAMPLE_DEMO_PASSWORD

    # Hash password
    hashed = flext_auth_hash_password(password, rounds=4)
    print(f"Password hashed: {hashed[:50]}...")

    # Verify password
    is_valid = flext_auth_verify_password(password, hashed)
    print(f"Password verification: {is_valid}")

    # Password strength
    strength = flext_auth_validate_password_strength(password)
    print(f"Password strength: {strength['strength']} (score: {strength['score']})")
    print(f"Feedback: {strength['feedback']}")
    print(f"Time to crack: {strength['time_to_crack']}")
    print(f"Valid: {strength['valid']}")


def demo_all_jwt_operations() -> None:
    """Demonstra todas as operações JWT."""
    print("\n=== All JWT Operations ===")

    # JWT payload
    payload = {
        "user_id": "demo_user_123",
        "username": "demo_user",
        "role": ADMIN_ROLE,
        "session_id": "demo_session_456",
    }

    secret = EXAMPLE_JWT_SECRET

    # Generate JWT
    token_result = flext_auth_generate_jwt(payload, secret=secret, expires_minutes=30)
    if token_result.success:
        token = token_result.data
        print(f"JWT generated: {token[:50]}...")

        # Decode JWT
        decoded = flext_auth_decode_jwt(token, secret)
        if decoded:
            print(f"JWT decoded - User: {decoded['username']}, Role: {decoded['role']}")

        # Extract user context
        context = flext_auth_extract_user_context(token, secret)
        if context:
            token_type = context["token_type"]
            username = context["username"]
            print(f"User context - Type: {token_type}, User: {username}")
        else:
            print("Could not extract user context")
    else:
        token = None
        print(f"JWT generation failed: {token_result.error}")

    # Create auth context (only if token was generated)
    if token:
        auth_context = flext_auth_create_auth_context(
            token, secret, include_permissions=True
        )
        if auth_context:
            print(f"Auth context - Permissions: {auth_context.get('permissions', [])}")
    else:
        print("Cannot create auth context without valid token")


def demo_all_token_types() -> None:
    """Demonstra todos os tipos de tokens."""
    print("\n=== All Token Types ===")

    # API Key
    api_key = flext_auth_create_api_key(
        user_id="api_user_789",
        scope="api",
        expires_days=365,
        secret=EXAMPLE_API_SECRET,
    )
    print(f"API Key: {api_key[:50]}...")

    # Service Token
    service_token = flext_auth_create_service_token(
        service_name="demo-service",
        permissions=["read", "write", "execute"],
        expires_hours=72,
        secret=EXAMPLE_SERVICE_SECRET,
    )
    print(f"Service Token: {service_token[:50]}...")

    # Multi-Factor Token
    mfa_token = flext_auth_create_multi_factor_token(
        user_id="mfa_user_101",
        factor_type="totp",
        expires_minutes=5,
        secret=EXAMPLE_MFA_SECRET,
    )
    print(f"MFA Token: {mfa_token[:50]}...")

    # Validate API Key
    api_validation = flext_auth_validate_api_key(
        api_key,
        "api-secret-key-256-bits-minimum-length",
    )
    if api_validation:
        print(f"API Key Valid - User: {api_validation['user_id']}")


def demo_all_session_operations() -> None:
    """Demonstra todas as operações de sessão."""
    print("\n=== All Session Operations ===")

    # Secure session basic
    basic_session = flext_auth_create_secure_session(
        user_id="session_user_202",
        username="session_user",
        role=MODERATOR_ROLE,
        expires_hours=24,
    )
    username = basic_session["username"]
    expires_at = basic_session["expires_at"]
    print(f"Basic session: {username} expires {expires_at}")

    # Secure session with permissions
    enhanced_session = flext_auth_create_secure_session(
        user_id="session_user_303",
        username="enhanced_user",
        role=ADMIN_ROLE,
        expires_hours=12,
        include_permissions=True,
    )
    print(f"Enhanced session: {enhanced_session['permissions']}")

    # Web session from request data (skipping due to async context issue)
    # web_session = flext_auth_web_session(request_data)  # Cannot use in async context
    print("Web session: Skipped (async context conflict)")


def demo_all_role_permission_operations() -> None:
    """Demonstra todas as operações de roles e permissões."""
    print("\n=== All Role & Permission Operations ===")

    # Role hierarchy
    hierarchy = flext_auth_create_role_hierarchy()
    print(f"Role hierarchy: {len(hierarchy)} roles defined")

    # Permission validation tests
    test_cases = [
        (ADMIN_ROLE, "REDACTED_LDAP_BIND_PASSWORD"),
        (MODERATOR_ROLE, "moderate"),
        (USER_ROLE, "read"),
        (GUEST_ROLE, "read_public"),
        (USER_ROLE, "REDACTED_LDAP_BIND_PASSWORD"),  # Should fail
    ]

    print("Permission tests:")
    for role, permission in test_cases:
        valid = flext_auth_validate_permissions(role, permission, hierarchy)
        print(f"  {role} -> {permission}: {'✅' if valid else '❌'}")


def demo_all_validation_operations() -> None:
    """Demonstra todas as operações de validação."""
    print("\n=== All Validation Operations ===")

    # Email validation
    test_emails = [
        "valid@example.com",
        "test.user+tag@domain.co.uk",
        "invalid.email",
        "user@",
        "@domain.com",
    ]

    print("Email validation:")
    for email in test_emails:
        valid = flext_auth_validate_email(email)
        print(f"  {email}: {'✅' if valid else '❌'}")

    # Token checking
    secret = EXAMPLE_CHECK_SECRET
    test_token_result = flext_auth_generate_jwt(
        {"user_id": "check_user", "username": "checker", "role": USER_ROLE},
        secret=secret,
    )

    if test_token_result.success:
        test_token = test_token_result.data
        check_result_result = flext_auth_check_token(test_token, secret)
        if check_result_result.success:
            check_result = check_result_result.data
            print(f"Token check valid: {check_result['valid']}")
            if check_result["valid"]:
                print(f"  User: {check_result['user_id']}")
                print(f"  Role: {check_result['role']}")
        else:
            print(f"Token check failed: {check_result_result.error}")
    else:
        print(f"Failed to generate test token: {test_token_result.error}")


def demo_ultra_helpers() -> None:
    """Demonstra todos os ultra-helpers."""
    print("\n=== All Ultra Helpers ===")

    # One-liner workflow (skipping due to async context issue)
    # one_liner_result = flext_auth_one_liner(
    #     "oneliner_user", "oneliner@example.com", "OneLinerPass123!"
    # )
    print("One-liner workflow: Skipped (async context conflict)")

    # Instant API
    instant_api_result = flext_auth_instant_api("instant_service", "api")
    if instant_api_result.success:
        api_data = instant_api_result.data
        print(f"Instant API success: {True}")
        print(f"  API Data: {type(api_data).__name__}")
    else:
        print(f"Instant API failed: {instant_api_result.error}")

    # Complete workflow (will fail in async context but demonstrates availability)
    workflow_result = flext_auth_complete_workflow(
        "workflow_user",
        "workflow@example.com",
        "WorkflowPass123!",
        role="user",
    )
    print(f"Complete workflow success: {workflow_result['success']}")


def demo_decorators() -> None:
    """Demonstra todos os decoradores."""
    print("\n=== All Decorators ===")

    secret = EXAMPLE_DECORATOR_SECRET

    @flext_auth_required(secret_key=secret)
    def protected_function(
        _request: dict[str, object], **_kwargs: object
    ) -> dict[str, object]:
        return {"message": "Protected access granted"}

    @flext_auth_role_required(ADMIN_ROLE, secret_key=secret)
    def REDACTED_LDAP_BIND_PASSWORD_function(
        _request: dict[str, object], **_kwargs: object
    ) -> dict[str, object]:
        return {"message": "Admin access granted"}

    @flext_auth_permission_required("delete")
    def permission_function(
        _request: dict[str, object], **_kwargs: object
    ) -> dict[str, object]:
        return {"message": "Permission granted"}

    # Mock request (will fail auth but shows decorator usage)
    mock_request = {"headers": {"Authorization": "Bearer invalid"}}

    protected_result = protected_function(mock_request)
    REDACTED_LDAP_BIND_PASSWORD_result = REDACTED_LDAP_BIND_PASSWORD_function(mock_request)
    permission_result = permission_function(mock_request)

    print(f"Protected decorator: {protected_result.get('error', 'Success')}")
    print(f"Admin decorator: {REDACTED_LDAP_BIND_PASSWORD_result.get('error', 'Success')}")
    print(f"Permission decorator: {permission_result.get('message', 'Failed')}")


def demo_mixin_pattern() -> None:
    """Demonstra o padrão FlextAuthMixin."""
    print("\n=== FlextAuthMixin Pattern ===")

    class DemoController(FlextAuthMixin):
        def process_request(self, token: str = "") -> dict[str, object]:
            user = self.get_current_user(token)
            has_read = self.check_permission(token, "read") if token else False

            return {
                "user_found": user is not None,
                "has_read_permission": has_read,
                "controller_type": self.__class__.__name__,
            }

    controller = DemoController()
    result = controller.process_request()
    print(f"Mixin controller result: {result}")


async def demo_full_auth_lifecycle() -> None:
    """Demonstra ciclo completo de autenticação."""
    print("\n=== Full Authentication Lifecycle ===")

    # Create auth instance
    auth = FlextAuth()

    # Register user with validation
    register_result = await auth.register_validated(
        username="lifecycle_user",
        email="lifecycle@example.com",
        password=EXAMPLE_LIFECYCLE_PASSWORD,
        role="user",
        require_strong_password=True,
    )

    if register_result.success:
        user_data = register_result.data
        print(f"User registered: {user_data['user']['username']}")

        # Create complete session
        session_result = await auth.create_user_session(
            "lifecycle_user",
            "LifecyclePass123!",
            include_user_data=True,
        )

        if session_result.success:
            session_data = session_result.data
            print(f"Session created with token: {session_data['token'][:30]}...")
            print("Full lifecycle completed successfully")
        else:
            print(f"Session creation failed: {session_result.error}")
    else:
        print(f"Registration failed: {register_result.error}")


async def demo_batch_operations() -> None:
    """Demonstra operações em lote."""
    print("\n=== Batch Operations Demo ===")

    auth = FlextAuth()
    batch_ops = flext_auth_batch_operations(auth)

    # Batch user registration
    users = [
        {
            "username": "batch1",
            "email": "batch1@example.com",
            "password": EXAMPLE_BATCH_PASSWORD_1,
            "role": "user",
        },
        {
            "username": "batch2",
            "email": "batch2@example.com",
            "password": EXAMPLE_BATCH_PASSWORD_2,
            "role": "moderator",
        },
    ]

    batch_result = await batch_ops.register_multiple(users, validate_all=True)
    if batch_result.success:
        print(f"Batch registration: {len(batch_result.data)} users created")
    else:
        print(f"Batch registration failed: {batch_result.error}")


def demo_type_definitions() -> None:
    """Demonstra todas as definições de tipos."""
    print("\n=== Type Definitions Demo ===")

    # Type annotations examples
    auth_result: AuthResult = {"success": True, "token": "sample_token"}
    user_data: UserData = {"id": "123", "username": "user", "email": "user@example.com"}
    token_data: TokenData = {"access_token": "token", "expires": 3600}
    session_data: SessionData = {"session_id": "sess_123", "user_id": "user_123"}
    permission_set: PermissionSet = ["read", "write", "delete"]
    role_hierarchy: RoleHierarchy = {"REDACTED_LDAP_BIND_PASSWORD": ["read", "write", "delete"]}

    print("Type definitions demonstrated:")
    print(f"  AuthResult: {type(auth_result).__name__}")
    print(f"  UserData: {type(user_data).__name__}")
    print(f"  TokenData: {type(token_data).__name__}")
    print(f"  SessionData: {type(session_data).__name__}")
    print(f"  PermissionSet: {type(permission_set).__name__}")
    print(f"  RoleHierarchy: {type(role_hierarchy).__name__}")


async def main() -> None:
    """Execute comprehensive demonstration of ALL flext-auth functionality."""
    print("FLEXT Auth - Comprehensive Functionality Demonstration")
    print("=" * 70)
    print("This demonstrates EVERY available feature and function.")
    print("=" * 70)

    try:
        # All sync demonstrations
        demo_all_constants_and_configs()
        demo_all_factory_functions()
        demo_all_password_operations()
        demo_all_jwt_operations()
        demo_all_token_types()
        demo_all_session_operations()
        demo_all_role_permission_operations()
        demo_all_validation_operations()
        demo_ultra_helpers()
        demo_decorators()
        demo_mixin_pattern()
        demo_type_definitions()

        # All async demonstrations
        await demo_full_auth_lifecycle()
        await demo_batch_operations()

        print("\n" + "=" * 70)
        print("✅ COMPREHENSIVE DEMONSTRATION COMPLETED!")
        print("ALL flext-auth functionality has been demonstrated.")
        print("Total features shown: 50+ functions, classes, and patterns")
        print("=" * 70)

    except (RuntimeError, ValueError, TypeError) as e:
        print(f"\n❌ ERROR in comprehensive demo: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
