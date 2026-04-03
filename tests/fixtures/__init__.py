# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Fixtures package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_auth import certificates
    from flext_auth.certificates import (
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

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "CertificateFixture": "flext_auth.certificates",
    "c": ("flext_core.constants", "FlextConstants"),
    "cert_pem": "flext_auth.certificates",
    "certificates": "flext_auth.certificates",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "fingerprint": "flext_auth.certificates",
    "generate_client_cert": "flext_auth.certificates",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "key_pem": "flext_auth.certificates",
    "m": ("flext_core.models", "FlextModels"),
    "mock_cert_pem": "flext_auth.certificates",
    "mock_fingerprint": "flext_auth.certificates",
    "mock_key_pem": "flext_auth.certificates",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "subject_cn": "flext_auth.certificates",
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
