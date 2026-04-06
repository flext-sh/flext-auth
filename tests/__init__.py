# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _t.TYPE_CHECKING:
    import tests.conftest as _tests_conftest

    conftest = _tests_conftest
    import tests.constants as _tests_constants
    from tests.conftest import (
        auth_settings,
        mock_get_global,
        pytest_plugins,
        reset_auth_singleton,
    )

    constants = _tests_constants
    import tests.fixtures as _tests_fixtures
    from tests.constants import FlextAuthTestConstants, FlextAuthTestConstants as c

    fixtures = _tests_fixtures
    import tests.helpers as _tests_helpers
    from tests.fixtures import (
        CertificateFixture,
        certificates,
        generate_client_cert,
        generate_self_signed_cert,
    )

    helpers = _tests_helpers
    import tests.models as _tests_models
    from tests.helpers import TestsProtocols, TestsTypings, TestsUtilities

    models = _tests_models
    import tests.protocols as _tests_protocols
    from tests.models import FlextAuthTestModels, FlextAuthTestModels as m

    protocols = _tests_protocols
    import tests.typings as _tests_typings
    from tests.protocols import FlextAuthTestProtocols, FlextAuthTestProtocols as p

    typings = _tests_typings
    import tests.unit as _tests_unit
    from tests.typings import FlextAuthTestTypes, FlextAuthTestTypes as t

    unit = _tests_unit
    import tests.utilities as _tests_utilities
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

    utilities = _tests_utilities
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from tests.utilities import FlextAuthTestUtilities, FlextAuthTestUtilities as u
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
        "auth_settings": "tests.conftest",
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
        "pytest_plugins": "tests.conftest",
        "r": ("flext_core.result", "FlextResult"),
        "reset_auth_singleton": "tests.conftest",
        "s": ("flext_core.service", "FlextService"),
        "t": ("tests.typings", "FlextAuthTestTypes"),
        "typings": "tests.typings",
        "u": ("tests.utilities", "FlextAuthTestUtilities"),
        "unit": "tests.unit",
        "utilities": "tests.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)

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
    "auth_settings",
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
    "pytest_plugins",
    "r",
    "reset_auth_singleton",
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
