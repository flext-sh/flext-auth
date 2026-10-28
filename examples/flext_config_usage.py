"""FLEXT Auth settings usage with current configuration API.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import settings


class FlextAuthConfigUsageExample:
    """Single owner for configuration usage examples."""

    @staticmethod
    def main() -> None:
        """Demonstrate settings overrides and service wiring."""
        if settings.Auth.expiry_minutes < 1:
            return


if __name__ == "__main__":
    FlextAuthConfigUsageExample.main()
