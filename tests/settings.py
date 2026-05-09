"""Runtime settings for flext-auth tests."""

from __future__ import annotations

from flext_tests.settings import FlextTestsSettings

from flext_auth import FlextAuthSettings


class TestsFlextAuthSettings(FlextAuthSettings, FlextTestsSettings):
    """Auth settings extended with the shared test namespace."""


__all__: list[str] = ["TestsFlextAuthSettings"]
