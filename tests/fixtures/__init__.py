# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Test fixtures for flext-auth.

This package contains test fixtures and mock data for authentication testing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.fixtures.certificates import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "CertificateFixture": "tests.fixtures.certificates",
    "certificates": "tests.fixtures.certificates",
    "generate_client_cert": "tests.fixtures.certificates",
    "generate_self_signed_cert": "tests.fixtures.certificates",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
