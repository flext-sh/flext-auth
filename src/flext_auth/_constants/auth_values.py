"""Authentication constants namespace values."""

from __future__ import annotations

from typing import Final

from flext_auth._constants.auth_security import FlextAuthConstantsAuthSecurity


class FlextAuthConstantsAuthValues(FlextAuthConstantsAuthSecurity):
    """Complete authentication constants namespace."""

    REGISTRY_PROVIDERS_CATEGORY: Final[str] = "auth_providers"
    REGISTRY_CONFIG_CATEGORY: Final[str] = f"{REGISTRY_PROVIDERS_CATEGORY}config"
    REGISTRY_METADATA_CATEGORY: Final[str] = f"{REGISTRY_PROVIDERS_CATEGORY}_metadata"


__all__: list[str] = ["FlextAuthConstantsAuthValues"]
