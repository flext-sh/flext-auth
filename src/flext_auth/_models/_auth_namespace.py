from __future__ import annotations

from flext_auth._config import FlextAuthConfig, __all__, config
from flext_auth.models import m


class _AuthNamespace(m.BaseModel):
    """Open, frozen namespace exposing every ``config/*.yaml`` domain model-less."""

    model_config = m.ConfigDict(extra="allow", frozen=True)
