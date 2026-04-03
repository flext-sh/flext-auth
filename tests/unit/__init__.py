# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_auth import (
        test_api,
        test_config,
        test_constants,
        test_token_real_flows,
        test_typings,
    )
    from flext_auth.test_api import (
        HttpRequest,
        contact,
        credential_hash,
        failed_attempts,
        full_name,
        is_active,
        last_access,
        locked_until,
        name,
        permissions,
        roles,
        session_id,
        token,
        unique_id,
    )
    from flext_auth.test_constants import TestFlextAuthConstants
    from flext_auth.test_token_real_flows import TestTokenRealFlows
    from flext_auth.test_typings import TestFlextAuthTypes
    from flext_core import FlextTypes
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "HttpRequest": "flext_auth.test_api",
    "TestFlextAuthConstants": "flext_auth.test_constants",
    "TestFlextAuthTypes": "flext_auth.test_typings",
    "TestTokenRealFlows": "flext_auth.test_token_real_flows",
    "c": ("flext_core.constants", "FlextConstants"),
    "contact": "flext_auth.test_api",
    "credential_hash": "flext_auth.test_api",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "failed_attempts": "flext_auth.test_api",
    "full_name": "flext_auth.test_api",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "is_active": "flext_auth.test_api",
    "last_access": "flext_auth.test_api",
    "locked_until": "flext_auth.test_api",
    "m": ("flext_core.models", "FlextModels"),
    "name": "flext_auth.test_api",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "permissions": "flext_auth.test_api",
    "r": ("flext_core.result", "FlextResult"),
    "roles": "flext_auth.test_api",
    "s": ("flext_core.service", "FlextService"),
    "session_id": "flext_auth.test_api",
    "t": ("flext_core.typings", "FlextTypes"),
    "test_api": "flext_auth.test_api",
    "test_config": "flext_auth.test_config",
    "test_constants": "flext_auth.test_constants",
    "test_token_real_flows": "flext_auth.test_token_real_flows",
    "test_typings": "flext_auth.test_typings",
    "token": "flext_auth.test_api",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "unique_id": "flext_auth.test_api",
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
