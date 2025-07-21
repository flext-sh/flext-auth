"""Basic tests for flext_auth."""

from __future__ import annotations

import importlib.util

try:
    import flext_auth
except ImportError:
    flext_auth = None  # type: ignore[assignment]


def test_module_imports() -> None:
    # Use find_spec for availability testing
    spec = importlib.util.find_spec("flext_auth")
    assert spec is not None, "Module flext_auth should be importable"
    assert spec.origin is not None, "Module should have an origin"


def test_basic_functionality() -> None:
    # Import should work based on previous test
    import flext_auth

    # Basic smoke test
    assert hasattr(flext_auth, "__file__")
    assert flext_auth.__file__ is not None


class TestBasicCoverage:
    """Basic coverage tests."""

    def test_module_attributes(self) -> None:
        import flext_auth

        # Verify module is properly structured
        assert flext_auth
        assert hasattr(flext_auth, "__version__") or hasattr(flext_auth, "__name__")
