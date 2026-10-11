"""FLEXT Auth API facade.

Public entrypoint kept as a strict facade over service classes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuthApplicationService, t


class FlextAuth(FlextAuthApplicationService):
    """Authentication facade composing identity, token, session and providers."""


auth: FlextAuth = FlextAuth.fetch_global()
"""Process-wide FlextAuth facade singleton resolved from the global container."""


__all__: t.MutableSequenceOf[str] = ["FlextAuth", "auth"]
