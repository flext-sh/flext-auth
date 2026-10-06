"""FlextAuthConfig — frozen config singleton for flext-auth (ADR-005 §7).

Business rules live in ``config/*.yaml`` under the ``Auth:`` key and are
validated into the typed models of ``FlextAuthConfigModels`` (ADR-012).
Access is ``config.Auth.<domain>[<key>...]``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth._models.config import FlextAuthConfigModels
from flext_core import FlextConfig, FlextSettings


class FlextAuthConfig(FlextSettings, FlextConfig):
    """Auth config auto-loaded from ``config/*.yaml`` and validated via models.

    MRO carries ``FlextSettings`` FIRST (ENFORCE-042); unlike never-instantiated
    namespace holders, this class IS instantiated by ``fetch_global``, so the
    instance-inert holder contract does not apply and pydantic settings
    construction machinery stays intact.
    """

    Auth: FlextAuthConfigModels.Auth


config: FlextAuthConfig = FlextAuthConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_auth import config``."""

__all__: list[str] = ["FlextAuthConfig", "config"]
