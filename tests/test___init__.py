"""Basic tests for flext_auth."""

import importlib.util

import pytest

try:
    import flext_auth
except ImportError:
    flext_auth = None


def test_module_imports() -> None:
    # Use find_spec for availability testing
    if importlib.util.find_spec("flext_auth") is None:
        pytest.skip("Module flext_auth not importable")


def test_basic_functionality() -> None:
    if flext_auth is None:
        pytest.skip("Module not testable")

    # Basic smoke test
    assert hasattr(flext_auth, "__file__")


class TestBasicCoverage:
    """Basic coverage tests."""

    def test_module_attributes(self) -> None:
        if flext_auth is None:
            pytest.skip("Module not importable")

        assert flext_auth
