"""Exemplo simples de uso do flext-auth.

Demonstra a interface pública e helpers para redução de código.
"""

import asyncio

from flext_auth import (
    FlextAuth,
    flext_auth_create_secure_session,
    flext_auth_decode_jwt,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_verify_password,
)


def demo_helpers() -> None:
    """Demonstra helpers utilitários."""
    # Password operations
    password = "SecurePassword123!"
    hashed = flext_auth_hash_password(password)
    if hashed.is_success:
        flext_auth_verify_password(password, hashed.data)

    # Email validation
    flext_auth_validate_email("user@example.com")

    # Password strength
    flext_auth_validate_password_strength(password)

    # JWT operations
    payload = {"user_id": "123", "username": "testuser"}
    secret = "my-secret-key-12345678901234567890"
    token_result = flext_auth_generate_jwt(payload, secret=secret, expires_minutes=60)
    if token_result.is_success:
        flext_auth_decode_jwt(token_result.data, secret)

    # Secure session
    flext_auth_create_secure_session("user123", "john", "REDACTED_LDAP_BIND_PASSWORD", 24)


async def demo_main_class() -> None:
    """Demonstra classe principal FlextAuth."""
    # Initialize
    auth = FlextAuth(
        {
            "security": {"password_rounds": 4},  # Fast for demo
        },
    )

    # Register user
    try:
        result = await auth.register("demo", "demo@example.com", "DemoPassword123!")
        if result.is_success:
            pass
    except Exception:
        pass

    # Validate invalid token
    await auth.validate("invalid_token")


def demo_quick_start() -> None:
    """Demonstra quick start."""
    # Single line setup
    flext_auth_quick_start()

    # Custom setup
    flext_auth_quick_start(
        REDACTED_LDAP_BIND_PASSWORD_username="superREDACTED_LDAP_BIND_PASSWORD",
        REDACTED_LDAP_BIND_PASSWORD_email="REDACTED_LDAP_BIND_PASSWORD@company.com",
        REDACTED_LDAP_BIND_PASSWORD_password="SuperSecret123!",
    )


def demo_code_reduction() -> None:
    """Demonstra redução de código."""


async def main() -> None:
    """Executa demonstrações."""
    demo_helpers()
    await demo_main_class()
    demo_quick_start()
    demo_code_reduction()


if __name__ == "__main__":
    asyncio.run(main())
