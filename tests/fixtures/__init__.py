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
    from tests.fixtures import certificates as certificates
    from tests.fixtures.certificates import (
        CertificateFixture as CertificateFixture,
        generate_client_cert as generate_client_cert,
        generate_self_signed_cert as generate_self_signed_cert,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "CertificateFixture": ["tests.fixtures.certificates", "CertificateFixture"],
    "certificates": ["tests.fixtures.certificates", ""],
    "generate_client_cert": ["tests.fixtures.certificates", "generate_client_cert"],
    "generate_self_signed_cert": [
        "tests.fixtures.certificates",
        "generate_self_signed_cert",
    ],
}

_EXPORTS: Sequence[str] = [
    "CertificateFixture",
    "certificates",
    "generate_client_cert",
    "generate_self_signed_cert",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
