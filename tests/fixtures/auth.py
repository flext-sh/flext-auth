"""Real authentication composition fixtures.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

import pytest

from flext_auth import FlextAuth
from flext_auth.providers import FlextAuthJwtProvider
from tests import p, t


class TestsFlextAuthFixtures:
    """Typed real API fixtures, without singleton resets or replacement adapters."""

    class PolicyLockedJwtProvider(FlextAuthJwtProvider):
        """Real JWT provider whose explicit domain policy rejects reconfiguration."""

        def __init__(
            self,
            configuration: t.ConfigurationMapping,
            failure: p.Result[p.Auth.FlextAuthBaseProvider],
        ) -> None:
            """Retain the original policy failure and otherwise use real JWT behavior."""
            super().__init__(settings=configuration)
            self._configuration_failure = failure

        @override
        def with_configuration(
            self,
            configuration: t.ConfigurationMapping,
        ) -> p.Result[p.Auth.FlextAuthBaseProvider]:
            """Reject the requested lifecycle with the declared failure unchanged."""
            _ = configuration
            return self._configuration_failure

    @staticmethod
    @pytest.fixture
    def auth_api() -> p.Auth.Service:
        """Compose a fresh registry and real domain services for each test."""
        return FlextAuth()


__all__: list[str] = ["TestsFlextAuthFixtures"]
