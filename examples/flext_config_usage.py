"""FLEXT Auth settings usage with current configuration API."""

from __future__ import annotations

from flext_auth import FlextAuth, FlextAuthSettings


def main() -> None:
    """Demonstrate settings overrides and service wiring."""
    base = FlextAuthSettings.get_global()
    if base.expiry_minutes < 1:
        return
    production = FlextAuthSettings.get_global()
    if production.expiry_minutes < 1:
        return
    _ = FlextAuth(config=production)


if __name__ == "__main__":
    main()
