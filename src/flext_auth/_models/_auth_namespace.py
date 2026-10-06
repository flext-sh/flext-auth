"""Auth namespace module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_auth/_models/_auth_namespace
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.models import m


class _AuthNamespace(m.BaseModel):
    """Open, frozen namespace exposing every ``config/*.yaml`` domain model-less."""

    model_config = m.ConfigDict(extra="allow", frozen=True)
