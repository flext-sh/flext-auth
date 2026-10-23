"""Public auth registry lifecycle through real composed APIs and providers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_auth import FlextAuth, FlextAuthRegistry
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
        tm.ok("password" not in request.model_dump())
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
        tm.fail(auth_api.registry is independent.registry)
        tm.ok(shared.registry is auth_api.registry)
        tm.ok(tm.ok(shared.fetch_provider("custom")) is provider)
        tm.fail(independent.fetch_provider("custom"))
        builtin = c.Auth.ProviderTypes.BASIC.value
        tm.ok(auth_api.unregister(builtin), eq=True)
        after_removal = FlextAuth(registry=auth_api.registry)
        tm.fail(after_removal.fetch_provider(builtin))
        tm.ok(tm.ok(after_removal.fetch_provider("custom")) is provider)

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
        tm.ok(tm.ok(auth_api.fetch_provider("custom")) is provider)
        tm.ok(tm.ok(auth_api.fetch_metadata("custom")) is metadata)
        tm.that(tm.ok(auth_api.fetch_config("custom")), eq=configuration)
        registration = tm.ok(auth_api.fetch_registration("custom"))
        tm.ok(registration.provider is provider)
        tm.ok(registration.metadata is metadata)
        tm.that(registration.configuration, eq=configuration)

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
        tm.ok(tm.ok(auth_api.fetch_provider("custom")) is first)
        tm.ok(auth_api.unregister("custom"), eq=True)
        tm.ok(auth_api.register_provider("custom", second), eq=True)
        tm.ok(tm.ok(auth_api.fetch_provider("custom")) is second)

    @staticmethod
    def test_invalid_registration_input_and_unsupported_reconfiguration_preserve_record(
        auth_api: p.Auth.Service,
    ) -> None:
        """Validate untrusted input before requesting a typed reconfiguration."""
        provider = FlextAuthBasicProvider()
        configuration = {"issuer": "initial"}
        tm.ok(
            auth_api.register_provider("custom", provider, configuration=configuration)
        )
        original = tm.ok(auth_api.fetch_registration("custom"))
        with pytest.raises(c.ValidationError):
            m.Auth.ProviderWrapper.model_validate({
                "category": c.Auth.REGISTRY_PROVIDERS_CATEGORY,
                "provider": provider,
                "configuration": {"issuer": ["invalid-scalar"]},
            })
        tm.ok(tm.ok(auth_api.fetch_registration("custom")) is original)
        tm.ok(tm.ok(auth_api.fetch_provider("custom")) is provider)
        replacement = {"issuer": "replacement"}
        tm.fail(auth_api.update_config("custom", replacement))
        tm.ok(tm.ok(auth_api.fetch_registration("custom")) is original)
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
        issuer = f"{identity.unique_id}-replacement"
        configuration = {**tm.ok(auth_api.fetch_config("jwt")), "issuer": issuer}
        tm.ok(auth_api.update_config("jwt", configuration), eq=True)
        replacement = tm.ok(auth_api.fetch_provider("jwt"))
        tm.fail(replacement is previous)
        validator = FlextAuthJwtTokenValidator(replacement)
        current_token = tm.ok(auth_api.create_token(identity.unique_id))
        claims = tm.ok(validator.validate_token(current_token))
        tm.that(claims["iss"], eq=issuer)
        tm.ok(claims["iss"] != old_claims.get("iss"))
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
        tm.ok(rejected.exception is cause)
        tm.that(rejected.error, eq=failure.error)
        tm.that(rejected.error_data, eq=failure.error_data)
        tm.ok(tm.ok(auth_api.fetch_registration("locked")) is original)
        tm.ok(tm.ok(auth_api.fetch_provider("locked")) is provider)

    @staticmethod
    def test_required_registry_port_is_validated_and_excluded() -> None:
        """Standalone domain services cannot create or hide their own registry."""
        with pytest.raises(c.ValidationError):
            FlextAuthRegistry.model_validate({})
        with pytest.raises(c.ValidationError):
            FlextAuthRegistry.model_validate({"registry": "invalid"})
        registry = u.build_registry()
        with pytest.raises(c.ValidationError):
            FlextAuthRegistry.model_validate({
                "registry": registry,
                "runtime_settings": "invalid",
            })
        with pytest.raises(c.ValidationError):
            FlextAuthRegistry.model_validate({
                "registry": registry,
                "unexpected": True,
            })
        port = FlextAuthRegistry(registry=registry)
        tm.ok(port.registry is registry)
        tm.ok("registry" not in port.model_dump())
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
