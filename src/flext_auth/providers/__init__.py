# AUTO-GENERATED FILE — Regenerate with: make gen
"""Providers package."""

from __future__ import annotations

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

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
