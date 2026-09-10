"""FlextAuthConfig — frozen config singleton for flext-auth (ADR-005 §7).

Model-less: business rules live in ``config/*.yaml`` under the ``Auth:`` key and
are exposed through the open ``config.Auth`` namespace (``extra="allow"``), with
no per-domain model. Access is ``config.Auth.<domain>[<key>...]``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.models import m
from flext_core import FlextConfig


class _AuthNamespace(m.BaseModel):
    """Open, frozen namespace exposing every ``config/*.yaml`` domain model-less."""

    model_config = m.ConfigDict(extra="allow", frozen=True)


class FlextAuthConfig(FlextConfig):
    """Auth config auto-loaded model-less from ``config/*.yaml``."""

    Auth: _AuthNamespace = _AuthNamespace()


config: FlextAuthConfig = FlextAuthConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_auth import config``."""

__all__: list[str] = ["FlextAuthConfig", "config"]
