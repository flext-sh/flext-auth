# AUTO-GENERATED FILE — Regenerate with: make gen
"""Providers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if TYPE_CHECKING:
    from flext_auth.providers._mixins.codec import (
        FlextAuthProviderCodecMixin as FlextAuthProviderCodecMixin,
    )
    from flext_auth.providers._mixins.tokens import (
        FlextAuthProviderTokenMixin as FlextAuthProviderTokenMixin,
    )
    from flext_auth.providers._mixins.validation import (
        FlextAuthProviderValidationMixin as FlextAuthProviderValidationMixin,
    )
    from flext_auth.providers.apikey import (
        FlextAuthApiKeyProvider as FlextAuthApiKeyProvider,
    )
    from flext_auth.providers.basic import (
        FlextAuthBasicProvider as FlextAuthBasicProvider,
    )
    from flext_auth.providers.certificate import (
        FlextAuthCertificateProvider as FlextAuthCertificateProvider,
    )
    from flext_auth.providers.jwt import FlextAuthJwtProvider as FlextAuthJwtProvider
    from flext_auth.providers.jwt_token_validator import (
        FlextAuthJwtTokenValidator as FlextAuthJwtTokenValidator,
    )
    from flext_auth.providers.kerberos import (
        FlextAuthKerberosProvider as FlextAuthKerberosProvider,
    )
    from flext_auth.providers.kerberos_support import (
        FlextAuthKerberosSupport as FlextAuthKerberosSupport,
    )
    from flext_auth.providers.ldap import FlextAuthLdapProvider as FlextAuthLdapProvider
    from flext_auth.providers.mixin import (
        FlextAuthProviderMixin as FlextAuthProviderMixin,
    )
    from flext_auth.providers.oauth2 import (
        FlextAuthOAuth2Provider as FlextAuthOAuth2Provider,
    )
    from flext_auth.providers.oauth2_config import (
        FlextAuthOAuth2Config as FlextAuthOAuth2Config,
    )
    from flext_auth.providers.oauth2_introspection import (
        FlextAuthOAuth2Introspection as FlextAuthOAuth2Introspection,
    )
    from flext_auth.providers.oauth2_tokens import (
        FlextAuthOAuth2Tokens as FlextAuthOAuth2Tokens,
    )
    from flext_auth.providers.oidc import FlextAuthOidcProvider as FlextAuthOidcProvider
    from flext_auth.providers.rfc import FlextAuthRfcProvider as FlextAuthRfcProvider
    from flext_auth.providers.saml import FlextAuthSamlProvider as FlextAuthSamlProvider
_LAZY_IMPORTS = merge_lazy_imports(
    ("._mixins",),
    build_lazy_import_map(
        {
            "._mixins": ("_mixins",),
            "._mixins.codec": ("FlextAuthProviderCodecMixin",),
            "._mixins.tokens": ("FlextAuthProviderTokenMixin",),
            "._mixins.validation": ("FlextAuthProviderValidationMixin",),
            ".apikey": ("FlextAuthApiKeyProvider",),
            ".basic": ("FlextAuthBasicProvider",),
            ".certificate": ("FlextAuthCertificateProvider",),
            ".jwt": ("FlextAuthJwtProvider",),
            ".jwt_token_validator": ("FlextAuthJwtTokenValidator",),
            ".kerberos": ("FlextAuthKerberosProvider",),
            ".kerberos_support": ("FlextAuthKerberosSupport",),
            ".ldap": ("FlextAuthLdapProvider",),
            ".mixin": ("FlextAuthProviderMixin",),
            ".oauth2": ("FlextAuthOAuth2Provider",),
            ".oauth2_config": ("FlextAuthOAuth2Config",),
            ".oauth2_introspection": ("FlextAuthOAuth2Introspection",),
            ".oauth2_tokens": ("FlextAuthOAuth2Tokens",),
            ".oidc": ("FlextAuthOidcProvider",),
            ".rfc": ("FlextAuthRfcProvider",),
            ".saml": ("FlextAuthSamlProvider",),
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
        "pytest_addoption",
        "pytest_collect_file",
        "pytest_collection_modifyitems",
        "pytest_configure",
        "pytest_runtest_setup",
        "pytest_runtest_teardown",
        "pytest_sessionfinish",
        "pytest_sessionstart",
        "pytest_terminal_summary",
        "pytest_warning_recorded",
    ),
    module_name=__name__,
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
