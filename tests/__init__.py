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
    from flext_tests import d, e, h, r, s, x

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
        certificates,
        generate_client_cert,
        generate_self_signed_cert,
    )
    from tests.helpers import TestsProtocols, TestsTypings, TestsUtilities
    from tests.models import FlextAuthTestModels, FlextAuthTestModels as m
    from tests.protocols import FlextAuthTestProtocols, FlextAuthTestProtocols as p
    from tests.typings import FlextAuthTestTypes, FlextAuthTestTypes as t
    from tests.unit import (
        HttpRequest,
        TestAuthModule,
        TestFlextAuth,
        TestFlextAuthAdditionalCoverage,
        TestFlextAuthAdvancedPatterns,
        TestFlextAuthConfigurationMethods,
        TestFlextAuthConfigurationOverrides,
        TestFlextAuthConstants,
        TestFlextAuthErrorHandling,
        TestFlextAuthErrorHandlingPaths,
        TestFlextAuthErrorHandlingSecond,
        TestFlextAuthErrorPaths,
        TestFlextAuthHandlerRegistration,
        TestFlextAuthInitializationCoverage,
        TestFlextAuthLogging,
        TestFlextAuthModelConfiguration,
        TestFlextAuthPasswordMethods,
        TestFlextAuthProcessorRegistration,
        TestFlextAuthProviderRegistry,
        TestFlextAuthQuickStart,
        TestFlextAuthQuickStartFunction,
        TestFlextAuthQuickStartMethod,
        TestFlextAuthSecurity,
        TestFlextAuthServiceInitialization,
        TestFlextAuthSessionManagement,
        TestFlextAuthSessionMethods,
        TestFlextAuthSettingsBasic,
        TestFlextAuthStorageOperations,
        TestFlextAuthTokenMethods,
        TestFlextAuthTokenOperations,
        TestFlextAuthTypes,
        TestFlextAuthUserMethods,
        TestJwtTokenGenerator,
        TestProviderTokenFlows,
        TestTokenRealFlows,
        test_api,
        test_config,
        test_constants,
        test_token_real_flows,
        test_typings,
    )
    from tests.utilities import FlextAuthTestUtilities, FlextAuthTestUtilities as u

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = merge_lazy_imports(
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
        "conftest": "tests.conftest",
        "constants": "tests.constants",
        "d": "flext_tests",
        "e": "flext_tests",
        "fixtures": "tests.fixtures",
        "h": "flext_tests",
        "helpers": "tests.helpers",
        "m": ("tests.models", "FlextAuthTestModels"),
        "mock_get_global": "tests.conftest",
        "models": "tests.models",
        "p": ("tests.protocols", "FlextAuthTestProtocols"),
        "protocols": "tests.protocols",
        "r": "flext_tests",
        "reset_singletons": "tests.conftest",
        "s": "flext_tests",
        "t": ("tests.typings", "FlextAuthTestTypes"),
        "typings": "tests.typings",
        "u": ("tests.utilities", "FlextAuthTestUtilities"),
        "unit": "tests.unit",
        "utilities": "tests.utilities",
        "x": "flext_tests",
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
