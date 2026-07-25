"""FLEXT Auth settings usage with current configuration API."""

from __future__ import annotations

from flext_auth import FlextAuth, FlextAuthSettings


class FlextAuthConfigUsageExample:
    """Single owner for configuration usage examples."""

    @staticmethod
    def main() -> None:
        """Demonstrate settings overrides and service wiring."""
        base = FlextAuthSettings.fetch_global()
        if base.expiry_minutes < 1:
            return
        production = FlextAuthSettings.fetch_global()
        if production.expiry_minutes < 1:
            return
        _ = FlextAuth(settings=production)


if __name__ == "__main__":
    FlextAuthConfigUsageExample.main()
