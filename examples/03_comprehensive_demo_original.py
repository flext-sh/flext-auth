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
    FlextAuth,
    FlextAuthMixin,
    FlextUserRole,
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
    flext_auth_extract_user_context,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_instant_api,
    flext_auth_permission_required,
    flext_auth_quick_start,
    flext_auth_required,
    flext_auth_role_required,
    flext_auth_validate_api_key,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_validate_permissions,
    flext_auth_verify_password,
)

# Example constants - not for production use
# These are intentionally hardcoded for demonstration purposes only
EXAMPLE_DEMO_PASSWORD = "DemoPassword123!@#"  # noqa: S105 - Example password for documentation
EXAMPLE_JWT_SECRET = "demo-jwt-secret-key-256-bits-minimum-length-for-security"  # noqa: S105 - Example JWT secret for documentation
EXAMPLE_API_SECRET = "api-secret-key-256-bits-minimum-length"  # noqa: S105 - Example API secret for documentation
EXAMPLE_SERVICE_SECRET = "service-secret-key-256-bits-minimum-length"  # noqa: S105 - Example service secret for documentation
EXAMPLE_MFA_SECRET = "mfa-secret-key-256-bits-minimum-length"  # noqa: S105 - Example MFA secret for documentation
EXAMPLE_CHECK_SECRET = "check-token-secret-256-bits-minimum-length"  # noqa: S105 - Example check secret for documentation
EXAMPLE_DECORATOR_SECRET = "decorator-secret-256-bits-minimum-length"  # noqa: S105 - Example decorator secret for documentation
EXAMPLE_LIFECYCLE_PASSWORD = "LifecyclePass123!"  # noqa: S105 - Example password for documentation
EXAMPLE_BATCH_PASSWORD_1 = "Batch123!"  # noqa: S105 - Example password for documentation
EXAMPLE_BATCH_PASSWORD_2 = "Batch456!"  # noqa: S105 - Example password for documentation


def demo_all_constants_and_configs() -> None:
    """Demonstra todas as constantes e configurações disponíveis."""
    # Role constants
    print(
        f"Available roles: {FlextUserRole.USER}, {FlextUserRole.ADMIN}, {FlextUserRole.MODERATOR}"
    )

    # Configuration presets
    auth = FlextAuth()
    print(f"Default auth service created: {type(auth).__name__}")


def demo_all_factory_functions() -> None:
    """Demonstra todas as factory functions."""
    # Factory instances - use FlextAuth with config instead
    _ = FlextAuth()  # dev_auth
    _ = FlextAuth()  # prod_auth
    _ = FlextAuth()  # web_auth
    _ = FlextAuth()  # api_auth

    # Quick start with options
    flext_auth_quick_start(
        REDACTED_LDAP_BIND_PASSWORD_username="demo_REDACTED_LDAP_BIND_PASSWORD",
        REDACTED_LDAP_BIND_PASSWORD_email="demo@example.com",
        create_REDACTED_LDAP_BIND_PASSWORD=False,
    )


def demo_all_password_operations() -> None:
    """Demonstra todas as operações com senhas."""
    password = EXAMPLE_DEMO_PASSWORD

    # Hash password
    hashed = flext_auth_hash_password(password, rounds=4)

    # Verify password
    flext_auth_verify_password(password, hashed)

    # Password strength
    flext_auth_validate_password_strength(password)


def demo_all_jwt_operations() -> None:
    """Demonstra todas as operações JWT."""
    # JWT payload
    payload = {
        "user_id": "demo_user_123",
        "username": "demo_user",
        "role": FlextUserRole.ADMIN,
        "session_id": "demo_session_456",
    }

    secret = EXAMPLE_JWT_SECRET

    # Generate JWT
    token_result = flext_auth_generate_jwt(payload, secret=secret, expires_minutes=30)
    if token_result.success:
        token = token_result.data

        # Decode JWT
        decoded = flext_auth_decode_jwt(token, secret)
        if decoded:
            pass

        # Extract user context
        context = flext_auth_extract_user_context(token, secret)
        if context:
            context["token_type"]
            context["username"]
    else:
        token = None

    # Create auth context (only if token was generated)
    if token:
        auth_context = flext_auth_create_auth_context(
            token,
            secret,
            include_permissions=True,
        )
        if auth_context:
            pass


def demo_all_token_types() -> None:
    """Demonstra todos os tipos de tokens."""
    # API Key
    api_key = flext_auth_create_api_key(
        user_id="api_user_789",
        scope="api",
        expires_days=365,
        secret=EXAMPLE_API_SECRET,
    )

    # Service Token
    flext_auth_create_service_token(
        service_name="demo-service",
        permissions=["read", "write", "execute"],
        expires_hours=72,
        secret=EXAMPLE_SERVICE_SECRET,
    )

    # Multi-Factor Token
    flext_auth_create_multi_factor_token(
        user_id="mfa_user_101",
        factor_type="totp",
        expires_minutes=5,
        secret=EXAMPLE_MFA_SECRET,
    )

    # Validate API Key
    api_validation = flext_auth_validate_api_key(
        api_key,
        "api-secret-key-256-bits-minimum-length",
    )
    if api_validation:
        pass


def demo_all_session_operations() -> None:
    """Demonstra todas as operações de sessão."""
    # Secure session basic
    basic_session = flext_auth_create_secure_session(
        user_id="session_user_202",
        username="session_user",
        role=FlextUserRole.MODERATOR,
        expires_hours=24,
    )
    basic_session["username"]
    basic_session["expires_at"]

    # Secure session with permissions
    flext_auth_create_secure_session(
        user_id="session_user_303",
        username="enhanced_user",
        role=FlextUserRole.ADMIN,
        expires_hours=12,
        include_permissions=True,
    )

    # Web session from request data (skipping due to async context issue)
    # web_session = flext_auth_web_session(request_data)  # Cannot use in async context


def demo_all_role_permission_operations() -> None:
    """Demonstra todas as operações de roles e permissões."""
    # Role hierarchy
    hierarchy = flext_auth_create_role_hierarchy()

    # Permission validation tests
    test_cases = [
        (FlextUserRole.ADMIN, "REDACTED_LDAP_BIND_PASSWORD"),
        (FlextUserRole.MODERATOR, "moderate"),
        (FlextUserRole.USER, "read"),
        (FlextUserRole.GUEST, "read_public"),
        (FlextUserRole.USER, "REDACTED_LDAP_BIND_PASSWORD"),  # Should fail
    ]

    for role, permission in test_cases:
        flext_auth_validate_permissions(role, permission, hierarchy)


def demo_all_validation_operations() -> None:
    """Demonstra todas as operações de validação."""
    # Email validation
    test_emails = [
        "valid@example.com",
        "test.user+tag@domain.co.uk",
        "invalid.email",
        "user@",
        "@domain.com",
    ]

    for email in test_emails:
        flext_auth_validate_email(email)

    # Token checking
    secret = EXAMPLE_CHECK_SECRET
    test_token_result = flext_auth_generate_jwt(
        {"user_id": "check_user", "username": "checker", "role": FlextUserRole.USER},
        secret=secret,
    )

    if test_token_result.success:
        test_token = test_token_result.data
        check_result_result = flext_auth_check_token(test_token, secret)
        if check_result_result.success:
            check_result = check_result_result.data
            if check_result["valid"]:
                pass


def demo_ultra_helpers() -> None:
    """Demonstra todos os ultra-helpers."""
    # One-liner workflow (skipping due to async context issue)
    # one_liner_result = flext_auth_one_liner(
    #     "oneliner_user", "oneliner@example.com", "OneLinerPass123!"
    # )

    # Instant API
    instant_api_result = flext_auth_instant_api("instant_service", "api")
    if instant_api_result.success:
        pass

    # Complete workflow (will fail in async context but demonstrates availability)
    flext_auth_complete_workflow(
        "workflow_user",
        "workflow@example.com",
        "WorkflowPass123!",
        role="user",
    )


def demo_decorators() -> None:
    """Demonstra todos os decoradores."""
    secret = EXAMPLE_DECORATOR_SECRET

    @flext_auth_required(secret_key=secret)
    def protected_function(
        _request: dict[str, object],
        **_kwargs: object,
    ) -> dict[str, object]:
        return {"message": "Protected access granted"}

    @flext_auth_role_required(FlextUserRole.ADMIN, secret_key=secret)
    def REDACTED_LDAP_BIND_PASSWORD_function(
        _request: dict[str, object],
        **_kwargs: object,
    ) -> dict[str, object]:
        return {"message": "Admin access granted"}

    @flext_auth_permission_required("delete")
    def permission_function(
        _request: dict[str, object],
        **_kwargs: object,
    ) -> dict[str, object]:
        return {"message": "Permission granted"}

    # Mock request (will fail auth but shows decorator usage)
    mock_request = {"headers": {"Authorization": "Bearer invalid"}}

    protected_function(mock_request)
    REDACTED_LDAP_BIND_PASSWORD_function(mock_request)
    permission_function(mock_request)


def demo_mixin_pattern() -> None:
    """Demonstra o padrão FlextAuthMixin."""

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
    controller.process_request()


async def demo_full_auth_lifecycle() -> None:
    """Demonstra ciclo completo de autenticação."""
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
        # Create complete session
        session_result = await auth.create_user_session(
            "lifecycle_user",
            "LifecyclePass123!",
            include_user_data=True,
        )

        if session_result.success:
            pass


async def demo_batch_operations() -> None:
    """Demonstra operações em lote."""
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
        pass


def demo_type_definitions() -> None:
    """Demonstra todas as definições de tipos."""
    # Type annotations examples


async def main() -> None:
    """Execute comprehensive demonstration of ALL flext-auth functionality."""
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

    except (RuntimeError, ValueError, TypeError) as e:
        # Re-raise with additional context for debugging
        msg = f"Demonstration failed: {type(e).__name__}: {e}"
        raise RuntimeError(msg) from e


if __name__ == "__main__":
    asyncio.run(main())
