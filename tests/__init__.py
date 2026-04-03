# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.decorators import FlextDecorators as d
from flext_core.exceptions import FlextExceptions as e
from flext_core.handlers import FlextHandlers as h
from flext_core.lazy import install_lazy_exports, merge_lazy_imports
from flext_core.mixins import FlextMixins as x
from flext_core.result import FlextResult as r
from flext_core.service import FlextService as s
from tests.conftest import mock_get_global, reset_singletons
from tests.constants import FlextAuthTestConstants, FlextAuthTestConstants as c
from tests.fixtures.certificates import (
    CertificateFixture,
    generate_client_cert,
    generate_self_signed_cert,
)
from tests.helpers.protocols import TestsProtocols
from tests.helpers.typings import TestsTypings
from tests.helpers.utilities import TestsUtilities
from tests.models import FlextAuthTestModels, FlextAuthTestModels as m
from tests.protocols import FlextAuthTestProtocols, FlextAuthTestProtocols as p
from tests.typings import FlextAuthTestTypes, FlextAuthTestTypes as t
from tests.unit.test_api import (
    HttpRequest,
    TestAuthModule,
    TestFlextAuth,
    TestFlextAuthAdditionalCoverage,
    TestFlextAuthAdvancedPatterns,
    TestFlextAuthConfigurationMethods,
    TestFlextAuthConfigurationOverrides,
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
    TestFlextAuthStorageOperations,
    TestFlextAuthTokenMethods,
    TestFlextAuthTokenOperations,
    TestFlextAuthUserMethods,
    TestProviderTokenFlows,
)
from tests.unit.test_config import TestFlextAuthSettingsBasic, TestJwtTokenGenerator
from tests.unit.test_constants import TestFlextAuthConstants
from tests.unit.test_token_real_flows import TestTokenRealFlows
from tests.unit.test_typings import TestFlextAuthTypes
from tests.utilities import FlextAuthTestUtilities, FlextAuthTestUtilities as u

if _t.TYPE_CHECKING:
    import tests.conftest as _tests_conftest

    conftest = _tests_conftest
    import tests.constants as _tests_constants

    constants = _tests_constants
    import tests.fixtures as _tests_fixtures

    fixtures = _tests_fixtures
    import tests.helpers as _tests_helpers

    helpers = _tests_helpers
    import tests.models as _tests_models

    models = _tests_models
    import tests.protocols as _tests_protocols

    protocols = _tests_protocols
    import tests.typings as _tests_typings

    typings = _tests_typings
    import tests.unit as _tests_unit

    unit = _tests_unit
    import tests.unit.test_api as _tests_unit_test_api

    test_api = _tests_unit_test_api
    import tests.unit.test_config as _tests_unit_test_config

    test_config = _tests_unit_test_config
    import tests.unit.test_constants as _tests_unit_test_constants

    test_constants = _tests_unit_test_constants
    import tests.unit.test_token_real_flows as _tests_unit_test_token_real_flows

    test_token_real_flows = _tests_unit_test_token_real_flows
    import tests.unit.test_typings as _tests_unit_test_typings

    test_typings = _tests_unit_test_typings
    import tests.utilities as _tests_utilities

    utilities = _tests_utilities
    import tests.fixtures.certificates as _tests_fixtures_certificates

    certificates = _tests_fixtures_certificates

    _ = (
        CertificateFixture,
        FlextAuthTestConstants,
        FlextAuthTestModels,
        FlextAuthTestProtocols,
        FlextAuthTestTypes,
        FlextAuthTestUtilities,
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
        TestsProtocols,
        TestsTypings,
        TestsUtilities,
        c,
        certificates,
        conftest,
        constants,
        d,
        e,
        fixtures,
        generate_client_cert,
        generate_self_signed_cert,
        h,
        helpers,
        m,
        mock_get_global,
        models,
        p,
        protocols,
        r,
        reset_singletons,
        s,
        t,
        test_api,
        test_config,
        test_constants,
        test_token_real_flows,
        test_typings,
        typings,
        u,
        unit,
        utilities,
        x,
    )
_LAZY_IMPORTS = merge_lazy_imports(
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

__all__ = [
    "CertificateFixture",
    "FlextAuthTestConstants",
    "FlextAuthTestModels",
    "FlextAuthTestProtocols",
    "FlextAuthTestTypes",
    "FlextAuthTestUtilities",
    "HttpRequest",
    "TestAuthModule",
    "TestFlextAuth",
    "TestFlextAuthAdditionalCoverage",
    "TestFlextAuthAdvancedPatterns",
    "TestFlextAuthConfigurationMethods",
    "TestFlextAuthConfigurationOverrides",
    "TestFlextAuthConstants",
    "TestFlextAuthErrorHandling",
    "TestFlextAuthErrorHandlingPaths",
    "TestFlextAuthErrorHandlingSecond",
    "TestFlextAuthErrorPaths",
    "TestFlextAuthHandlerRegistration",
    "TestFlextAuthInitializationCoverage",
    "TestFlextAuthLogging",
    "TestFlextAuthModelConfiguration",
    "TestFlextAuthPasswordMethods",
    "TestFlextAuthProcessorRegistration",
    "TestFlextAuthProviderRegistry",
    "TestFlextAuthQuickStart",
    "TestFlextAuthQuickStartFunction",
    "TestFlextAuthQuickStartMethod",
    "TestFlextAuthSecurity",
    "TestFlextAuthServiceInitialization",
    "TestFlextAuthSessionManagement",
    "TestFlextAuthSessionMethods",
    "TestFlextAuthSettingsBasic",
    "TestFlextAuthStorageOperations",
    "TestFlextAuthTokenMethods",
    "TestFlextAuthTokenOperations",
    "TestFlextAuthTypes",
    "TestFlextAuthUserMethods",
    "TestJwtTokenGenerator",
    "TestProviderTokenFlows",
    "TestTokenRealFlows",
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "c",
    "certificates",
    "conftest",
    "constants",
    "d",
    "e",
    "fixtures",
    "generate_client_cert",
    "generate_self_signed_cert",
    "h",
    "helpers",
    "m",
    "mock_get_global",
    "models",
    "p",
    "protocols",
    "r",
    "reset_singletons",
    "s",
    "t",
    "test_api",
    "test_config",
    "test_constants",
    "test_token_real_flows",
    "test_typings",
    "typings",
    "u",
    "unit",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
