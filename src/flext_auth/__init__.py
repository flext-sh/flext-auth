# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext auth package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_api import d, e, h, r, s, x

    from flext_auth.__version__ import *
    from flext_auth._managers import *
    from flext_auth._utilities import *
    from flext_auth.api import *
    from flext_auth.constants import *
    from flext_auth.models import *
    from flext_auth.protocols import *
    from flext_auth.providers import *
    from flext_auth.settings import *
    from flext_auth.transports import *
    from flext_auth.typings import *
    from flext_auth.utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = merge_lazy_imports(
    (
        "flext_auth._managers",
        "flext_auth._utilities",
        "flext_auth.providers",
        "flext_auth.transports",
    ),
    {
        "FlextAuth": "flext_auth.api",
        "FlextAuthConstants": "flext_auth.constants",
        "FlextAuthModels": "flext_auth.models",
        "FlextAuthProtocols": "flext_auth.protocols",
        "FlextAuthSettings": "flext_auth.settings",
        "FlextAuthTypes": "flext_auth.typings",
        "FlextAuthUtilities": "flext_auth.utilities",
        "__author__": "flext_auth.__version__",
        "__author_email__": "flext_auth.__version__",
        "__description__": "flext_auth.__version__",
        "__license__": "flext_auth.__version__",
        "__title__": "flext_auth.__version__",
        "__url__": "flext_auth.__version__",
        "__version__": "flext_auth.__version__",
        "__version_info__": "flext_auth.__version__",
        "_managers": "flext_auth._managers",
        "_utilities": "flext_auth._utilities",
        "api": "flext_auth.api",
        "c": ("flext_auth.constants", "FlextAuthConstants"),
        "constants": "flext_auth.constants",
        "d": "flext_api",
        "e": "flext_api",
        "h": "flext_api",
        "m": ("flext_auth.models", "FlextAuthModels"),
        "models": "flext_auth.models",
        "p": ("flext_auth.protocols", "FlextAuthProtocols"),
        "protocols": "flext_auth.protocols",
        "providers": "flext_auth.providers",
        "r": "flext_api",
        "s": "flext_api",
        "settings": "flext_auth.settings",
        "t": ("flext_auth.typings", "FlextAuthTypes"),
        "transports": "flext_auth.transports",
        "typings": "flext_auth.typings",
        "u": ("flext_auth.utilities", "FlextAuthUtilities"),
        "utilities": "flext_auth.utilities",
        "x": "flext_api",
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
