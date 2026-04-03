# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_auth import (
        certificates,
        conftest,
        constants,
        fixtures,
        helpers,
        models,
        protocols,
        test_api,
        test_config,
        test_constants,
        test_token_real_flows,
        test_typings,
        typings,
        unit,
        utilities,
    )
    from flext_auth.conftest import mock_get_global, reset_singletons
    from flext_auth.constants import FlextAuthTestConstants, FlextAuthTestConstants as c
    from flext_auth.fixtures import (
        CertificateFixture,
        cert_pem,
        fingerprint,
        generate_client_cert,
        key_pem,
        mock_cert_pem,
        mock_fingerprint,
        mock_key_pem,
        subject_cn,
    )
    from flext_auth.helpers import TestsProtocols, TestsTypings, TestsUtilities
    from flext_auth.models import FlextAuthTestModels, FlextAuthTestModels as m
    from flext_auth.protocols import FlextAuthTestProtocols, FlextAuthTestProtocols as p
    from flext_auth.typings import FlextAuthTestTypes, FlextAuthTestTypes as t
    from flext_auth.unit import (
        HttpRequest,
        TestFlextAuthConstants,
        TestFlextAuthTypes,
        TestTokenRealFlows,
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
    from flext_auth.utilities import FlextAuthTestUtilities, FlextAuthTestUtilities as u
    from flext_core import FlextTypes
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
    (
        "flext_auth.fixtures",
        "flext_auth.helpers",
        "flext_auth.unit",
    ),
    {
        "FlextAuthTestConstants": "flext_auth.constants",
        "FlextAuthTestModels": "flext_auth.models",
        "FlextAuthTestProtocols": "flext_auth.protocols",
        "FlextAuthTestTypes": "flext_auth.typings",
        "FlextAuthTestUtilities": "flext_auth.utilities",
        "c": ("flext_auth.constants", "FlextAuthTestConstants"),
        "certificates": "flext_auth.certificates",
        "conftest": "flext_auth.conftest",
        "constants": "flext_auth.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "fixtures": "flext_auth.fixtures",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "helpers": "flext_auth.helpers",
        "m": ("flext_auth.models", "FlextAuthTestModels"),
        "mock_get_global": "flext_auth.conftest",
        "models": "flext_auth.models",
        "p": ("flext_auth.protocols", "FlextAuthTestProtocols"),
        "protocols": "flext_auth.protocols",
        "r": ("flext_core.result", "FlextResult"),
        "reset_singletons": "flext_auth.conftest",
        "s": ("flext_core.service", "FlextService"),
        "t": ("flext_auth.typings", "FlextAuthTestTypes"),
        "test_api": "flext_auth.test_api",
        "test_config": "flext_auth.test_config",
        "test_constants": "flext_auth.test_constants",
        "test_token_real_flows": "flext_auth.test_token_real_flows",
        "test_typings": "flext_auth.test_typings",
        "typings": "flext_auth.typings",
        "u": ("flext_auth.utilities", "FlextAuthTestUtilities"),
        "unit": "flext_auth.unit",
        "utilities": "flext_auth.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
