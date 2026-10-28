"""Real authentication composition fixtures.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

import pytest

from flext_auth import FlextAuth
from flext_auth.providers import FlextAuthJwtProvider
from tests import p, t


class TestsFlextAuthFixtures:
    """Typed real API fixtures, without singleton resets or replacement adapters."""

    class PolicyLockedJwtProvider(FlextAuthJwtProvider):
        """Real JWT provider whose explicit domain policy rejects reconfiguration."""

        configuration_failure: ClassVar[p.Result[p.Auth.FlextAuthBaseProvider]]

        def __init__(
            self,
            configuration: t.ConfigurationMapping,
            failure: p.Result[p.Auth.FlextAuthBaseProvider],
        ) -> None:
            """Retain the policy failure and otherwise use real JWT behavior."""
            super().__init__(settings=configuration)
            TestsFlextAuthFixtures.PolicyLockedJwtProvider.configuration_failure = (
                failure
            )

        @override
        @staticmethod
        def with_configuration(
            configuration: t.ConfigurationMapping,
        ) -> p.Result[p.Auth.FlextAuthBaseProvider]:
            """Reject the requested lifecycle with the declared failure unchanged.

            Returns:
                The declared policy failure, with its original cause intact.

            """
            _ = configuration
            return TestsFlextAuthFixtures.PolicyLockedJwtProvider.configuration_failure

    @pytest.fixture
    def auth_api() -> p.Auth.Service:
        """Compose a fresh registry and real domain services for each test.

        Returns:
            A real auth API owning its registry and domain services.

        """
        return FlextAuth()


__all__: list[str] = ["TestsFlextAuthFixtures"]
