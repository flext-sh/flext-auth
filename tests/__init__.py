# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests import (
        conftest as conftest,
        constants as constants,
        fixtures as fixtures,
        helpers as helpers,
        models as models,
        protocols as protocols,
        typings as typings,
        unit as unit,
        utilities as utilities,
    )
    from tests.conftest import (
        mock_get_global as mock_get_global,
        reset_singletons as reset_singletons,
    )
    from tests.constants import (
        FlextAuthTestConstants as FlextAuthTestConstants,
        FlextAuthTestConstants as c,
    )
    from tests.fixtures import certificates as certificates
    from tests.fixtures.certificates import (
        CertificateFixture as CertificateFixture,
        generate_client_cert as generate_client_cert,
        generate_self_signed_cert as generate_self_signed_cert,
    )
    from tests.helpers.protocols import TestsProtocols as TestsProtocols
    from tests.helpers.typings import TestsTypings as TestsTypings
    from tests.helpers.utilities import TestsUtilities as TestsUtilities
    from tests.models import (
        FlextAuthTestModels as FlextAuthTestModels,
        FlextAuthTestModels as m,
    )
    from tests.protocols import (
        FlextAuthTestProtocols as FlextAuthTestProtocols,
        FlextAuthTestProtocols as p,
    )
    from tests.typings import (
        FlextAuthTestTypes as FlextAuthTestTypes,
        FlextAuthTestTypes as t,
    )
    from tests.unit import (
        test_api as test_api,
        test_config as test_config,
        test_constants as test_constants,
        test_token_real_flows as test_token_real_flows,
        test_typings as test_typings,
    )
    from tests.unit.test_api import (
        HttpRequest as HttpRequest,
        TestAuthModule as TestAuthModule,
        TestFlextAuth as TestFlextAuth,
        TestFlextAuthAdditionalCoverage as TestFlextAuthAdditionalCoverage,
        TestFlextAuthAdvancedPatterns as TestFlextAuthAdvancedPatterns,
        TestFlextAuthConfigurationMethods as TestFlextAuthConfigurationMethods,
        TestFlextAuthConfigurationOverrides as TestFlextAuthConfigurationOverrides,
        TestFlextAuthErrorHandling as TestFlextAuthErrorHandling,
        TestFlextAuthErrorHandlingPaths as TestFlextAuthErrorHandlingPaths,
        TestFlextAuthErrorHandlingSecond as TestFlextAuthErrorHandlingSecond,
        TestFlextAuthErrorPaths as TestFlextAuthErrorPaths,
        TestFlextAuthHandlerRegistration as TestFlextAuthHandlerRegistration,
        TestFlextAuthInitializationCoverage as TestFlextAuthInitializationCoverage,
        TestFlextAuthLogging as TestFlextAuthLogging,
        TestFlextAuthModelConfiguration as TestFlextAuthModelConfiguration,
        TestFlextAuthPasswordMethods as TestFlextAuthPasswordMethods,
        TestFlextAuthProcessorRegistration as TestFlextAuthProcessorRegistration,
        TestFlextAuthProviderRegistry as TestFlextAuthProviderRegistry,
        TestFlextAuthQuickStart as TestFlextAuthQuickStart,
        TestFlextAuthQuickStartFunction as TestFlextAuthQuickStartFunction,
        TestFlextAuthQuickStartMethod as TestFlextAuthQuickStartMethod,
        TestFlextAuthSecurity as TestFlextAuthSecurity,
        TestFlextAuthServiceInitialization as TestFlextAuthServiceInitialization,
        TestFlextAuthSessionManagement as TestFlextAuthSessionManagement,
        TestFlextAuthSessionMethods as TestFlextAuthSessionMethods,
        TestFlextAuthStorageOperations as TestFlextAuthStorageOperations,
        TestFlextAuthTokenMethods as TestFlextAuthTokenMethods,
        TestFlextAuthTokenOperations as TestFlextAuthTokenOperations,
        TestFlextAuthUserMethods as TestFlextAuthUserMethods,
        TestProviderTokenFlows as TestProviderTokenFlows,
    )
    from tests.unit.test_config import (
        TestFlextAuthSettingsBasic as TestFlextAuthSettingsBasic,
        TestJwtTokenGenerator as TestJwtTokenGenerator,
    )
    from tests.unit.test_constants import (
        TestFlextAuthConstants as TestFlextAuthConstants,
    )
    from tests.unit.test_token_real_flows import (
        TestTokenRealFlows as TestTokenRealFlows,
    )
    from tests.unit.test_typings import TestFlextAuthTypes as TestFlextAuthTypes
    from tests.utilities import (
        FlextAuthTestUtilities as FlextAuthTestUtilities,
        FlextAuthTestUtilities as u,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "CertificateFixture": ["tests.fixtures.certificates", "CertificateFixture"],
    "FlextAuthTestConstants": ["tests.constants", "FlextAuthTestConstants"],
    "FlextAuthTestModels": ["tests.models", "FlextAuthTestModels"],
    "FlextAuthTestProtocols": ["tests.protocols", "FlextAuthTestProtocols"],
    "FlextAuthTestTypes": ["tests.typings", "FlextAuthTestTypes"],
    "FlextAuthTestUtilities": ["tests.utilities", "FlextAuthTestUtilities"],
    "HttpRequest": ["tests.unit.test_api", "HttpRequest"],
    "TestAuthModule": ["tests.unit.test_api", "TestAuthModule"],
    "TestFlextAuth": ["tests.unit.test_api", "TestFlextAuth"],
    "TestFlextAuthAdditionalCoverage": [
        "tests.unit.test_api",
        "TestFlextAuthAdditionalCoverage",
    ],
    "TestFlextAuthAdvancedPatterns": [
        "tests.unit.test_api",
        "TestFlextAuthAdvancedPatterns",
    ],
    "TestFlextAuthConfigurationMethods": [
        "tests.unit.test_api",
        "TestFlextAuthConfigurationMethods",
    ],
    "TestFlextAuthConfigurationOverrides": [
        "tests.unit.test_api",
        "TestFlextAuthConfigurationOverrides",
    ],
    "TestFlextAuthConstants": ["tests.unit.test_constants", "TestFlextAuthConstants"],
    "TestFlextAuthErrorHandling": ["tests.unit.test_api", "TestFlextAuthErrorHandling"],
    "TestFlextAuthErrorHandlingPaths": [
        "tests.unit.test_api",
        "TestFlextAuthErrorHandlingPaths",
    ],
    "TestFlextAuthErrorHandlingSecond": [
        "tests.unit.test_api",
        "TestFlextAuthErrorHandlingSecond",
    ],
    "TestFlextAuthErrorPaths": ["tests.unit.test_api", "TestFlextAuthErrorPaths"],
    "TestFlextAuthHandlerRegistration": [
        "tests.unit.test_api",
        "TestFlextAuthHandlerRegistration",
    ],
    "TestFlextAuthInitializationCoverage": [
        "tests.unit.test_api",
        "TestFlextAuthInitializationCoverage",
    ],
    "TestFlextAuthLogging": ["tests.unit.test_api", "TestFlextAuthLogging"],
    "TestFlextAuthModelConfiguration": [
        "tests.unit.test_api",
        "TestFlextAuthModelConfiguration",
    ],
    "TestFlextAuthPasswordMethods": [
        "tests.unit.test_api",
        "TestFlextAuthPasswordMethods",
    ],
    "TestFlextAuthProcessorRegistration": [
        "tests.unit.test_api",
        "TestFlextAuthProcessorRegistration",
    ],
    "TestFlextAuthProviderRegistry": [
        "tests.unit.test_api",
        "TestFlextAuthProviderRegistry",
    ],
    "TestFlextAuthQuickStart": ["tests.unit.test_api", "TestFlextAuthQuickStart"],
    "TestFlextAuthQuickStartFunction": [
        "tests.unit.test_api",
        "TestFlextAuthQuickStartFunction",
    ],
    "TestFlextAuthQuickStartMethod": [
        "tests.unit.test_api",
        "TestFlextAuthQuickStartMethod",
    ],
    "TestFlextAuthSecurity": ["tests.unit.test_api", "TestFlextAuthSecurity"],
    "TestFlextAuthServiceInitialization": [
        "tests.unit.test_api",
        "TestFlextAuthServiceInitialization",
    ],
    "TestFlextAuthSessionManagement": [
        "tests.unit.test_api",
        "TestFlextAuthSessionManagement",
    ],
    "TestFlextAuthSessionMethods": [
        "tests.unit.test_api",
        "TestFlextAuthSessionMethods",
    ],
    "TestFlextAuthSettingsBasic": [
        "tests.unit.test_config",
        "TestFlextAuthSettingsBasic",
    ],
    "TestFlextAuthStorageOperations": [
        "tests.unit.test_api",
        "TestFlextAuthStorageOperations",
    ],
    "TestFlextAuthTokenMethods": ["tests.unit.test_api", "TestFlextAuthTokenMethods"],
    "TestFlextAuthTokenOperations": [
        "tests.unit.test_api",
        "TestFlextAuthTokenOperations",
    ],
    "TestFlextAuthTypes": ["tests.unit.test_typings", "TestFlextAuthTypes"],
    "TestFlextAuthUserMethods": ["tests.unit.test_api", "TestFlextAuthUserMethods"],
    "TestJwtTokenGenerator": ["tests.unit.test_config", "TestJwtTokenGenerator"],
    "TestProviderTokenFlows": ["tests.unit.test_api", "TestProviderTokenFlows"],
    "TestTokenRealFlows": ["tests.unit.test_token_real_flows", "TestTokenRealFlows"],
    "TestsProtocols": ["tests.helpers.protocols", "TestsProtocols"],
    "TestsTypings": ["tests.helpers.typings", "TestsTypings"],
    "TestsUtilities": ["tests.helpers.utilities", "TestsUtilities"],
    "c": ["tests.constants", "FlextAuthTestConstants"],
    "certificates": ["tests.fixtures.certificates", ""],
    "conftest": ["tests.conftest", ""],
    "constants": ["tests.constants", ""],
    "d": ["flext_tests", "d"],
    "e": ["flext_tests", "e"],
    "fixtures": ["tests.fixtures", ""],
    "generate_client_cert": ["tests.fixtures.certificates", "generate_client_cert"],
    "generate_self_signed_cert": [
        "tests.fixtures.certificates",
        "generate_self_signed_cert",
    ],
    "h": ["flext_tests", "h"],
    "helpers": ["tests.helpers", ""],
    "m": ["tests.models", "FlextAuthTestModels"],
    "mock_get_global": ["tests.conftest", "mock_get_global"],
    "models": ["tests.models", ""],
    "p": ["tests.protocols", "FlextAuthTestProtocols"],
    "protocols": ["tests.protocols", ""],
    "r": ["flext_tests", "r"],
    "reset_singletons": ["tests.conftest", "reset_singletons"],
    "s": ["flext_tests", "s"],
    "t": ["tests.typings", "FlextAuthTestTypes"],
    "test_api": ["tests.unit.test_api", ""],
    "test_config": ["tests.unit.test_config", ""],
    "test_constants": ["tests.unit.test_constants", ""],
    "test_token_real_flows": ["tests.unit.test_token_real_flows", ""],
    "test_typings": ["tests.unit.test_typings", ""],
    "typings": ["tests.typings", ""],
    "u": ["tests.utilities", "FlextAuthTestUtilities"],
    "unit": ["tests.unit", ""],
    "utilities": ["tests.utilities", ""],
    "x": ["flext_tests", "x"],
}

_EXPORTS: Sequence[str] = [
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
