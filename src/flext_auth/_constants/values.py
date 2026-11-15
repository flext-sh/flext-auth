"""Authentication constants namespace values — real class for stand-in composition.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar


class FlextAuthValues:
    """Authentication constants referenced by the facade."""

    REGISTRY_PROVIDERS_CATEGORY: ClassVar[str] = "auth_providers"
    REGISTRY_CONFIG_CATEGORY: ClassVar[str] = "auth_providersconfig"
    REGISTRY_METADATA_CATEGORY: ClassVar[str] = "auth_providers_metadata"
    PROVIDER_VERSION: ClassVar[str] = "1.0.0"


__all__: list[str] = ["FlextAuthValues"]