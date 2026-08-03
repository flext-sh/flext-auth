"""Service base for flext-auth tests."""

from __future__ import annotations

from typing import override

from flext_auth import m
from flext_tests import s as tests_s
from tests.settings import TestsFlextAuthSettings


class TestsFlextAuthServiceBase(tests_s):
    """Auth test service base with source and test settings namespaces."""

    @classmethod
    @override
    def fetch_settings(cls) -> TestsFlextAuthSettings:
        """Return the typed Auth+Tests settings singleton."""
        return TestsFlextAuthSettings.fetch_global()

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        return m.RuntimeBootstrapOptions(settings_type=TestsFlextAuthSettings)


s = TestsFlextAuthServiceBase

__all__: list[str] = ["TestsFlextAuthServiceBase", "s"]
