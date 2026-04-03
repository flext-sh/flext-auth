# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Fixtures package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
    from tests.fixtures import certificates
    from tests.fixtures.certificates import (
        CertificateFixture,
        cert_pem,
        fingerprint,
        generate_client_cert,
        key_pem,
        mock_cert_pem,
        mock_fingerprint,
        mock_key_pem,
        subject_cn,
    )

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "CertificateFixture": "tests.fixtures.certificates",
    "c": ("flext_core.constants", "FlextConstants"),
    "cert_pem": "tests.fixtures.certificates",
    "certificates": "tests.fixtures.certificates",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "fingerprint": "tests.fixtures.certificates",
    "generate_client_cert": "tests.fixtures.certificates",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "key_pem": "tests.fixtures.certificates",
    "m": ("flext_core.models", "FlextModels"),
    "mock_cert_pem": "tests.fixtures.certificates",
    "mock_fingerprint": "tests.fixtures.certificates",
    "mock_key_pem": "tests.fixtures.certificates",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "subject_cn": "tests.fixtures.certificates",
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
