# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from tests import (
        conftest,
        constants,
        fixtures,
        helpers,
        models,
        protocols,
        typings,
        unit,
        utilities,
    )
    from tests.conftest import mock_get_global, reset_singletons
    from tests.constants import FlextAuthTestConstants, FlextAuthTestConstants as c
    from tests.fixtures import (
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
    from tests.helpers import TestsProtocols, TestsTypings, TestsUtilities
    from tests.models import FlextAuthTestModels, FlextAuthTestModels as m
    from tests.protocols import FlextAuthTestProtocols, FlextAuthTestProtocols as p
    from tests.typings import FlextAuthTestTypes, FlextAuthTestTypes as t
    from tests.unit import (
        TestFlextAuthConstants,
        TestFlextAuthTypes,
        TestTokenRealFlows,
    )
    from tests.unit.test_api import HttpRequest
    from tests.utilities import FlextAuthTestUtilities, FlextAuthTestUtilities as u

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
    (
        "tests.fixtures",
        "tests.helpers",
        "tests.unit",
    ),
    {
        "FlextAuthTestConstants": "tests.constants",
        "FlextAuthTestModels": "tests.models",
        "FlextAuthTestProtocols": "tests.protocols",
        "FlextAuthTestTypes": "tests.typings",
        "FlextAuthTestUtilities": "tests.utilities",
        "c": ("tests.constants", "FlextAuthTestConstants"),
        "certificates": "tests.fixtures.certificates",
        "conftest": "tests.conftest",
        "constants": "tests.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "fixtures": "tests.fixtures",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "helpers": "tests.helpers",
        "m": ("tests.models", "FlextAuthTestModels"),
        "mock_get_global": "tests.conftest",
        "models": "tests.models",
        "p": ("tests.protocols", "FlextAuthTestProtocols"),
        "protocols": "tests.protocols",
        "r": ("flext_core.result", "FlextResult"),
        "reset_singletons": "tests.conftest",
        "s": ("flext_core.service", "FlextService"),
        "t": ("tests.typings", "FlextAuthTestTypes"),
        "typings": "tests.typings",
        "u": ("tests.utilities", "FlextAuthTestUtilities"),
        "unit": "tests.unit",
        "utilities": "tests.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
