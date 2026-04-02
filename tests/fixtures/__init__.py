# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Test fixtures for flext-auth.

This package contains test fixtures and mock data for authentication testing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from tests.fixtures import certificates
    from tests.fixtures.certificates import (
        CertificateFixture,
        generate_client_cert,
        generate_self_signed_cert,
    )

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "CertificateFixture": "tests.fixtures.certificates",
    "certificates": "tests.fixtures.certificates",
    "generate_client_cert": "tests.fixtures.certificates",
    "generate_self_signed_cert": "tests.fixtures.certificates",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
