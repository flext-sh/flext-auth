# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import *

    from tests import conftest, constants, models, protocols, typings, utilities
    from tests.conftest import *
    from tests.constants import *
    from tests.fixtures import *
    from tests.helpers import *
    from tests.models import *
    from tests.protocols import *
    from tests.typings import *
    from tests.unit import *
    from tests.utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "CertificateFixture": "tests.fixtures.certificates",
    "FlextAuthTestConstants": "tests.constants",
    "FlextAuthTestModels": "tests.models",
    "FlextAuthTestProtocols": "tests.protocols",
    "FlextAuthTestTypes": "tests.typings",
    "FlextAuthTestUtilities": "tests.utilities",
    "HttpRequest": "tests.unit.test_api",
    "TestAuthModule": "tests.unit.test_api",
    "TestFlextAuth": "tests.unit.test_api",
    "TestFlextAuthAdditionalCoverage": "tests.unit.test_api",
    "TestFlextAuthAdvancedPatterns": "tests.unit.test_api",
    "TestFlextAuthConfigurationMethods": "tests.unit.test_api",
    "TestFlextAuthConfigurationOverrides": "tests.unit.test_api",
    "TestFlextAuthConstants": "tests.unit.test_constants",
    "TestFlextAuthErrorHandling": "tests.unit.test_api",
    "TestFlextAuthErrorHandlingPaths": "tests.unit.test_api",
    "TestFlextAuthErrorHandlingSecond": "tests.unit.test_api",
    "TestFlextAuthErrorPaths": "tests.unit.test_api",
    "TestFlextAuthHandlerRegistration": "tests.unit.test_api",
    "TestFlextAuthInitializationCoverage": "tests.unit.test_api",
    "TestFlextAuthLogging": "tests.unit.test_api",
    "TestFlextAuthModelConfiguration": "tests.unit.test_api",
    "TestFlextAuthPasswordMethods": "tests.unit.test_api",
    "TestFlextAuthProcessorRegistration": "tests.unit.test_api",
    "TestFlextAuthProviderRegistry": "tests.unit.test_api",
    "TestFlextAuthQuickStart": "tests.unit.test_api",
    "TestFlextAuthQuickStartFunction": "tests.unit.test_api",
    "TestFlextAuthQuickStartMethod": "tests.unit.test_api",
    "TestFlextAuthSecurity": "tests.unit.test_api",
    "TestFlextAuthServiceInitialization": "tests.unit.test_api",
    "TestFlextAuthSessionManagement": "tests.unit.test_api",
    "TestFlextAuthSessionMethods": "tests.unit.test_api",
    "TestFlextAuthSettingsBasic": "tests.unit.test_config",
    "TestFlextAuthStorageOperations": "tests.unit.test_api",
    "TestFlextAuthTokenMethods": "tests.unit.test_api",
    "TestFlextAuthTokenOperations": "tests.unit.test_api",
    "TestFlextAuthTypes": "tests.unit.test_typings",
    "TestFlextAuthUserMethods": "tests.unit.test_api",
    "TestJwtTokenGenerator": "tests.unit.test_config",
    "TestProviderTokenFlows": "tests.unit.test_api",
    "TestTokenRealFlows": "tests.unit.test_token_real_flows",
    "TestsProtocols": "tests.helpers.protocols",
    "TestsTypings": "tests.helpers.typings",
    "TestsUtilities": "tests.helpers.utilities",
    "c": ["tests.constants", "FlextAuthTestConstants"],
    "certificates": "tests.fixtures.certificates",
    "conftest": "tests.conftest",
    "constants": "tests.constants",
    "d": "flext_tests",
    "e": "flext_tests",
    "fixtures": "tests.fixtures",
    "generate_client_cert": "tests.fixtures.certificates",
    "generate_self_signed_cert": "tests.fixtures.certificates",
    "h": "flext_tests",
    "helpers": "tests.helpers",
    "m": ["tests.models", "FlextAuthTestModels"],
    "mock_get_global": "tests.conftest",
    "models": "tests.models",
    "p": ["tests.protocols", "FlextAuthTestProtocols"],
    "protocols": "tests.protocols",
    "r": "flext_tests",
    "reset_singletons": "tests.conftest",
    "s": "flext_tests",
    "t": ["tests.typings", "FlextAuthTestTypes"],
    "test_api": "tests.unit.test_api",
    "test_config": "tests.unit.test_config",
    "test_constants": "tests.unit.test_constants",
    "test_token_real_flows": "tests.unit.test_token_real_flows",
    "test_typings": "tests.unit.test_typings",
    "typings": "tests.typings",
    "u": ["tests.utilities", "FlextAuthTestUtilities"],
    "unit": "tests.unit",
    "utilities": "tests.utilities",
    "x": "flext_tests",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
