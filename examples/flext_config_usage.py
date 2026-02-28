"""FLEXT Auth settings usage with current configuration API."""

from __future__ import annotations

from flext_auth import FlextAuth, FlextAuthConstants, FlextAuthSettings


def main() -> None:
    """Demonstrate settings overrides and service wiring."""
    base = FlextAuthSettings()
    if base.expiry_minutes < 1:
        return

    production_result = FlextAuthSettings.get_or_create_global(
        expiry_minutes=FlextAuthConstants.Auth.Jwt.DEFAULT_EXPIRY_MINUTES // 2,
        hash_rounds=FlextAuthConstants.Auth.Credentials.Password.BCRYPT_ROUNDS,
        max_attempts=FlextAuthConstants.Auth.MAX_ATTEMPTS_DEFAULT,
        session_expiry_minutes=FlextAuthConstants.Auth.SESSION_EXPIRY_DEFAULT_MINUTES,
        environment="production",
    )
    if production_result.is_failure:
        return

    production = production_result.value
    validation = production.validate_auth_configuration()
    if validation.is_failure:
        return

    _ = production.get_security_settings()
    _ = production.get_jwt_settings()

    # Service receives validated settings directly
    _ = FlextAuth(config=production)


if __name__ == "__main__":
    main()
