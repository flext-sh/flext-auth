"""Public auth registry lifecycle through real composed APIs and providers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_auth import FlextAuth, FlextAuthRegistry
from flext_auth._registry import FlextAuthRegistryBase
from flext_auth.providers import FlextAuthBasicProvider, FlextAuthJwtTokenValidator
from tests import c, m, p, r, tm, u
from tests.fixtures.auth import TestsFlextAuthFixtures


class TestsFlextAuthRegistryComposition:
    """Registry lifetime and metadata do not replace real auth behavior."""

    @staticmethod
    def test_provider_credentials_preserve_secret_exclusion_and_lookup_failure(
        auth_api: p.Auth.Service,
    ) -> None:
        """Exclude credential secrets without masking provider lookup errors."""
        request = m.Auth.CredentialValidation(
            username="provider-user",
            password=c.TEST_CREDENTIAL,
        )
        tm.that("password" not in request.model_dump(), eq=True)
        expected = auth_api.fetch_provider("absent-provider")
        rejected = auth_api.authenticate_with_provider(
            request.username,
            request.password,
            provider="absent-provider",
        )
        tm.fail(rejected, code=expected.error_code)
        tm.that(rejected.error, eq=expected.error)
        tm.that(rejected.error_data, eq=expected.error_data)

    @staticmethod
    def test_api_registries_are_isolated_and_sharing_is_explicit(
        auth_api: p.Auth.Service,
    ) -> None:
        """Independent APIs isolate registrations; explicit injection shares them."""
        independent = FlextAuth()
        shared = FlextAuth(registry=auth_api.registry)
        provider = FlextAuthBasicProvider()
        tm.ok(auth_api.register_provider("custom", provider), eq=True)
        tm.that(auth_api.registry is independent.registry, eq=False)
        tm.that(shared.registry is auth_api.registry, eq=True)
        tm.that(tm.ok(shared.fetch_provider("custom")) is provider, eq=True)
        tm.fail(independent.fetch_provider("custom"))
        builtin = c.Auth.ProviderTypes.BASIC.value
        tm.ok(auth_api.unregister(builtin), eq=True)
        after_removal = FlextAuth(registry=auth_api.registry)
        tm.fail(after_removal.fetch_provider(builtin))
        tm.that(tm.ok(after_removal.fetch_provider("custom")) is provider, eq=True)

    @staticmethod
    def test_provider_identity_metadata_and_config_survive_registration(
        auth_api: p.Auth.Service,
    ) -> None:
        """The single record retains the provider and original domain metadata."""
        provider = FlextAuthBasicProvider()
        configuration = {"issuer": "initial"}
        metadata = m.Auth.Providers.Metadata(
            name="custom",
            capabilities=tuple(provider.supports()),
        )
        tm.ok(
            auth_api.register_provider(
                "custom",
                provider,
                metadata=metadata,
                configuration=configuration,
            ),
            eq=True,
        )
        tm.that(tm.ok(auth_api.fetch_provider("custom")) is provider, eq=True)
        tm.that(tm.ok(auth_api.fetch_metadata("custom")) is metadata, eq=True)
        tm.that(tm.ok(auth_api.fetch_config("custom")), eq=configuration)
        tm.that(
            tm.ok(
                auth_api.registry.fetch_plugin(
                    c.Auth.REGISTRY_PROVIDERS_CATEGORY, "custom"
                )
            )
            is tm.ok(auth_api.fetch_registration("custom")),
            eq=True,
        )

    @staticmethod
    def test_repeated_provider_is_idempotent_conflicts_do_not_overwrite(
        auth_api: p.Auth.Service,
    ) -> None:
        """Only the identical provider repeats; removal releases the name."""
        first = FlextAuthBasicProvider()
        second = FlextAuthBasicProvider()
        tm.ok(auth_api.register_provider("custom", first), eq=True)
        tm.ok(auth_api.register_provider("custom", first), eq=True)
        conflict = auth_api.register_provider("custom", second)
        tm.fail(conflict)
        tm.that(tm.ok(auth_api.fetch_provider("custom")) is first, eq=True)
        tm.ok(auth_api.unregister("custom"), eq=True)
        tm.ok(auth_api.register_provider("custom", second), eq=True)
        tm.that(tm.ok(auth_api.fetch_provider("custom")) is second, eq=True)

    @staticmethod
    def test_config_validation_precedes_removal_and_preserves_cause(
        auth_api: p.Auth.Service,
    ) -> None:
        """Invalid ingress preserves the old record and its ValidationError."""
        provider = FlextAuthBasicProvider()
        configuration = {"issuer": "initial"}
        tm.ok(
            auth_api.register_provider("custom", provider, configuration=configuration)
        )
        original = tm.ok(auth_api.fetch_registration("custom"))
        rejected = auth_api.update_config("custom", {"issuer": ["invalid-scalar"]})
        tm.fail(rejected)
        tm.that(rejected.exception, is_=c.ValidationError)
        tm.that(tm.ok(auth_api.fetch_registration("custom")) is original, eq=True)
        tm.that(tm.ok(auth_api.fetch_provider("custom")) is provider, eq=True)
        replacement = {"issuer": "replacement"}
        tm.fail(auth_api.update_config("custom", replacement))
        tm.that(tm.ok(auth_api.fetch_registration("custom")) is original, eq=True)
        tm.that(tm.ok(auth_api.fetch_config("custom")), eq=configuration)

    @staticmethod
    def test_supported_config_replacement_changes_real_token_consumption(
        auth_api: p.Auth.Service,
    ) -> None:
        """JWT replacement uses the new issuer without changing signing policy."""
        identity = tm.ok(
            auth_api.register_user(
                "reconfigured-user",
                "reconfigured@example.com",
                c.TEST_CREDENTIAL,
            )
        )
        old_token = tm.ok(auth_api.create_token(identity.unique_id))
        previous = tm.ok(auth_api.fetch_provider("jwt"))
        old_claims = tm.ok(
            FlextAuthJwtTokenValidator(previous).validate_token(old_token)
        )
        configuration = dict(tm.ok(auth_api.fetch_config("jwt")))
        issuer = f"{configuration.get('issuer') or 'configured'}-replacement"
        configuration["issuer"] = issuer
        tm.ok(auth_api.update_config("jwt", configuration), eq=True)
        replacement = tm.ok(auth_api.fetch_provider("jwt"))
        tm.that(replacement is previous, eq=False)
        validator = FlextAuthJwtTokenValidator(replacement)
        current_token = tm.ok(auth_api.create_token(identity.unique_id))
        claims = tm.ok(validator.validate_token(current_token))
        tm.that(claims["iss"], eq=issuer)
        tm.that(claims["iss"] != old_claims.get("iss"), eq=True)
        tm.ok(auth_api.session_service.validate_token(current_token))

    @staticmethod
    def test_lookup_and_removal_preserve_core_failure_details(
        auth_api: p.Auth.Service,
    ) -> None:
        """Domain boundaries retain core not-found codes, data and causes."""
        fetched = auth_api.registry.fetch_plugin(
            c.Auth.REGISTRY_PROVIDERS_CATEGORY, "absent"
        )
        domain = auth_api.fetch_provider("absent")
        tm.fail(domain)
        tm.that(domain.error, eq=fetched.error)
        tm.that(domain.error_code, eq=fetched.error_code)
        tm.that(domain.error_data, eq=fetched.error_data)
        core_removed = auth_api.registry.unregister_plugin(
            c.Auth.REGISTRY_PROVIDERS_CATEGORY, "absent"
        )
        removed = auth_api.unregister("absent")
        tm.that(removed.error, eq=core_removed.error)
        tm.that(removed.error_code, eq=core_removed.error_code)

    @staticmethod
    def test_rejected_reconfiguration_preserves_original_cause_and_record(
        auth_api: p.Auth.Service,
    ) -> None:
        """A real provider's policy failure crosses the registry boundary unchanged."""
        cause = ValueError("provider policy rejects reconfiguration")
        failure = r[p.Auth.FlextAuthBaseProvider].fail(str(cause), exception=cause)
        configuration = tm.ok(auth_api.fetch_config("jwt"))
        provider = TestsFlextAuthFixtures.PolicyLockedJwtProvider(
            configuration, failure
        )
        tm.ok(
            auth_api.register_provider("locked", provider, configuration=configuration)
        )
        original = tm.ok(auth_api.fetch_registration("locked"))
        rejected = auth_api.update_config("locked", configuration)
        tm.fail(rejected)
        tm.that(rejected.exception is cause, eq=True)
        tm.that(rejected.error, eq=failure.error)
        tm.that(rejected.error_data, eq=failure.error_data)
        tm.that(tm.ok(auth_api.fetch_registration("locked")) is original, eq=True)
        tm.that(tm.ok(auth_api.fetch_provider("locked")) is provider, eq=True)

    @staticmethod
    def test_required_registry_port_is_validated_and_excluded() -> None:
        """Standalone domain services cannot create or hide their own registry."""
        with pytest.raises(c.ValidationError):
            FlextAuthRegistry.model_validate({})
        with pytest.raises(c.ValidationError):
            FlextAuthRegistryBase.model_validate({"registry": "invalid"})
        port = FlextAuthRegistryBase(registry=u.build_registry())
        tm.that("registry" not in port.model_dump(), eq=True)
        tm.that(
            "registry" not in port.model_json_schema().get("properties", {}), eq=True
        )

    @staticmethod
    def test_composed_identity_and_token_services_use_the_same_real_store(
        auth_api: p.Auth.Service,
    ) -> None:
        """Register, authenticate and issue a real JWT through the API graph."""
        identity = tm.ok(
            auth_api.register_user(
                "composed-user",
                "composed@example.com",
                c.TEST_CREDENTIAL,
            )
        )
        authenticated = tm.ok(
            auth_api.authenticate({
                "username": identity.name,
                "password": c.TEST_CREDENTIAL,
            })
        )
        tm.that(authenticated.unique_id, eq=identity.unique_id)
        token = tm.ok(auth_api.create_token(identity.unique_id))
        tm.ok(auth_api.session_service.validate_token(token))
        tm.ok(auth_api.unregister("jwt"), eq=True)
        tm.fail(auth_api.session_service.validate_token(token))


__all__: list[str] = ["TestsFlextAuthRegistryComposition"]
