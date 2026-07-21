"""FlextAuthConfig — frozen, validated config singleton for flext-auth.

Every ``config/*.yaml`` file is auto-discovered and deep-merged at first
``fetch_global`` call (model-less, ``extra="allow"`` at the FlextConfig base).
The flat YAML is then validated into the pure-Pydantic ``_models.config``
shapes and exposed as typed domain objects under ``config.Auth`` — never a
model-less dict subscript.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path
from typing import ClassVar

from flext_auth._models.config import FlextAuthConfigModels
from flext_core import FlextConfig


class FlextAuthConfig(FlextConfig):
    """Auth config auto-loaded from ``config/*.yaml`` and validated via models."""

    CONFIG_DIR: ClassVar[str] = str(
        Path(__file__).resolve().parents[2] / "config",
    )

    @cached_property
    def Auth(self) -> FlextAuthConfigModels.Auth:
        """Validated ``Auth`` business-rule config namespace."""
        root = FlextAuthConfigModels.Root.model_validate(
            dict(self.model_extra or {}),
        )
        return root.Auth


config: FlextAuthConfig = FlextAuthConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_auth import config``."""

__all__: list[str] = ["FlextAuthConfig", "config"]
