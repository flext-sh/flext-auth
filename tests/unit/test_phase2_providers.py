"""Tests for Phase 2 authentication providers (OAuth2, OIDC, SAML).

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import pytest

from flext_auth import (
    FlextAuthOAuth2Provider,
    FlextAuthOidcProvider,
    FlextAuthSamlProvider,
)


class TestFlextAuthOAuth2Provider:
    """Test OAuth2 authentication provider."""

    def test_oauth2_initialization(self) -> None:
        """Test OAuth2 provider initialization with required config."""
        config = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "token_endpoint": "https://auth.example.com/token",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "redirect_uri": "https://app.example.com/callback",
        }

        provider = FlextAuthOAuth2Provider(config)

        assert provider is not None
        assert provider.supports() == {"token", "validate", "oauth2", "refresh", "pkce"}

    def test_oauth2_missing_client_id(self) -> None:
        """Test OAuth2 provider fails without client_id."""
        config = {
            "client_secret": "test-client-secret",
            "token_endpoint": "https://auth.example.com/token",
        }

        with pytest.raises(ValueError, match="client_id"):
            FlextAuthOAuth2Provider(config)

    def test_oauth2_missing_token_endpoint(self) -> None:
        """Test OAuth2 provider fails without token_endpoint."""
        config = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
        }

        with pytest.raises(ValueError, match="token_endpoint"):
            FlextAuthOAuth2Provider(config)

    def test_oauth2_metadata(self) -> None:
        """Test OAuth2 provider metadata."""
        config = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "token_endpoint": "https://auth.example.com/token",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "flow": "client_credentials",
        }

        provider = FlextAuthOAuth2Provider(config)
        metadata = provider.get_metadata()

        assert metadata["name"] == "oauth2"
        assert metadata["version"] == "2.0.0"
        assert metadata["flow"] == "client_credentials"
        assert "oauth2" in metadata["capabilities"]

    def test_oauth2_pkce_challenge_generation(self) -> None:
        """Test PKCE code challenge generation."""
        config = {
            "client_id": "test-client-id",
            "token_endpoint": "https://auth.example.com/token",
            "use_pkce": True,
        }

        provider = FlextAuthOAuth2Provider(config)
        code_verifier, code_challenge = provider.generate_pkce_challenge()

        # Verify code verifier is base64-url encoded
        assert len(code_verifier) >= 43
        assert len(code_verifier) <= 128
        assert code_verifier.replace("-", "").replace("_", "").isalnum()

        # Verify code challenge is base64-url encoded
        assert len(code_challenge) == 43
        assert code_challenge.replace("-", "").replace("_", "").isalnum()

    def test_oauth2_authorization_url_generation(self) -> None:
        """Test OAuth2 authorization URL generation."""
        config = {
            "client_id": "test-client-id",
            "token_endpoint": "https://auth.example.com/token",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "redirect_uri": "https://app.example.com/callback",
            "scope": "read write",
            "use_pkce": True,
        }

        provider = FlextAuthOAuth2Provider(config)
        result = provider.get_authorization_url(state="test-state")

        assert result.is_success
        auth_url = result.unwrap()

        # Verify URL structure
        assert "https://auth.example.com/authorize" in auth_url
        assert "client_id=test-client-id" in auth_url
        assert "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback" in auth_url
        assert "scope=read+write" in auth_url
        assert "state=test-state" in auth_url
        assert "code_challenge=" in auth_url
        assert "code_challenge_method=S256" in auth_url


class TestFlextAuthOidcProvider:
    """Test OIDC authentication provider."""

    def test_oidc_initialization(self) -> None:
        """Test OIDC provider initialization with required config."""
        config = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "userinfo_endpoint": "https://auth.example.com/userinfo",
        }

        provider = FlextAuthOidcProvider(config)

        assert provider is not None
        capabilities = provider.supports()
        assert "oidc" in capabilities
        assert "id_token" in capabilities
        assert "userinfo" in capabilities

    def test_oidc_missing_issuer(self) -> None:
        """Test OIDC provider fails without issuer."""
        config = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "token_endpoint": "https://auth.example.com/token",
        }

        with pytest.raises(ValueError, match="issuer"):
            FlextAuthOidcProvider(config)

    def test_oidc_scope_includes_openid(self) -> None:
        """Test OIDC provider ensures 'openid' scope is included."""
        config = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            "scope": "profile email",
        }

        provider = FlextAuthOidcProvider(config)
        metadata = provider.get_metadata()

        # Verify openid scope was added
        assert "openid" in metadata["scope"]

    def test_oidc_metadata(self) -> None:
        """Test OIDC provider metadata."""
        config = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            "id_token_signing_alg": "RS256",
        }

        provider = FlextAuthOidcProvider(config)
        metadata = provider.get_metadata()

        assert metadata["name"] == "oidc"
        assert metadata["issuer"] == "https://auth.example.com"
        assert metadata["id_token_signing_alg"] == "RS256"
        assert "oidc" in metadata["capabilities"]
        assert "id_token" in metadata["capabilities"]

    def test_oidc_authorization_url_with_nonce(self) -> None:
        """Test OIDC authorization URL generation with nonce."""
        config = {
            "client_id": "test-client-id",
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "validate_nonce": True,
        }

        provider = FlextAuthOidcProvider(config)
        result = provider.get_authorization_url(state="test-state", nonce="test-nonce")

        assert result.is_success
        auth_url = result.unwrap()

        # Verify nonce parameter is included
        assert "nonce=test-nonce" in auth_url


class TestFlextAuthSamlProvider:
    """Test SAML authentication provider."""

    def test_saml_initialization(self) -> None:
        """Test SAML provider initialization with required config."""
        config = {
            "entity_id": "https://app.example.com/saml/metadata",
            "sso_url": "https://idp.example.com/saml/sso",
            "x509_cert": "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----",
            "assertion_consumer_service_url": "https://app.example.com/saml/acs",
        }

        provider = FlextAuthSamlProvider(config)

        assert provider is not None
        capabilities = provider.supports()
        assert "saml" in capabilities
        assert "sso" in capabilities
        assert "metadata" in capabilities

    def test_saml_missing_entity_id(self) -> None:
        """Test SAML provider fails without entity_id."""
        config = {
            "sso_url": "https://idp.example.com/saml/sso",
            "x509_cert": "test-cert",
            "assertion_consumer_service_url": "https://app.example.com/saml/acs",
        }

        with pytest.raises(ValueError, match="entity_id"):
            FlextAuthSamlProvider(config)

    def test_saml_missing_sso_url(self) -> None:
        """Test SAML provider fails without sso_url."""
        config = {
            "entity_id": "https://app.example.com/saml/metadata",
            "x509_cert": "test-cert",
            "assertion_consumer_service_url": "https://app.example.com/saml/acs",
        }

        with pytest.raises(ValueError, match="sso_url"):
            FlextAuthSamlProvider(config)

    def test_saml_missing_x509_cert(self) -> None:
        """Test SAML provider fails without x509_cert."""
        config = {
            "entity_id": "https://app.example.com/saml/metadata",
            "sso_url": "https://idp.example.com/saml/sso",
            "assertion_consumer_service_url": "https://app.example.com/saml/acs",
        }

        with pytest.raises(ValueError, match="x509_cert"):
            FlextAuthSamlProvider(config)

    def test_saml_metadata(self) -> None:
        """Test SAML provider metadata."""
        config = {
            "entity_id": "https://app.example.com/saml/metadata",
            "sso_url": "https://idp.example.com/saml/sso",
            "slo_url": "https://idp.example.com/saml/slo",
            "x509_cert": "test-cert",
            "assertion_consumer_service_url": "https://app.example.com/saml/acs",
            "sign_requests": True,
        }

        provider = FlextAuthSamlProvider(config)
        metadata = provider.get_metadata()

        assert metadata["name"] == "saml"
        assert metadata["entity_id"] == "https://app.example.com/saml/metadata"
        assert metadata["sso_url"] == "https://idp.example.com/saml/sso"
        assert metadata["slo_url"] == "https://idp.example.com/saml/slo"
        assert metadata["sign_requests"] is True
        assert "saml" in metadata["capabilities"]
        assert "slo" in metadata["capabilities"]

    def test_saml_request_id_generation(self) -> None:
        """Test SAML request ID generation."""
        config = {
            "entity_id": "https://app.example.com/saml/metadata",
            "sso_url": "https://idp.example.com/saml/sso",
            "x509_cert": "test-cert",
            "assertion_consumer_service_url": "https://app.example.com/saml/acs",
        }

        provider = FlextAuthSamlProvider(config)
        request_id1 = provider.generate_request_id()
        request_id2 = provider.generate_request_id()

        # Verify request IDs are unique and start with _
        assert request_id1.startswith("_")
        assert request_id2.startswith("_")
        assert request_id1 != request_id2
        assert len(request_id1) == 33  # '_' + 32 hex characters

    def test_saml_sp_metadata_generation(self) -> None:
        """Test SAML SP metadata generation."""
        config = {
            "entity_id": "https://app.example.com/saml/metadata",
            "sso_url": "https://idp.example.com/saml/sso",
            "x509_cert": "test-cert",
            "assertion_consumer_service_url": "https://app.example.com/saml/acs",
        }

        provider = FlextAuthSamlProvider(config)
        result = provider.generate_sp_metadata()

        assert result.is_success
        metadata_xml = result.unwrap()

        # Verify XML structure
        assert "<?xml version=" in metadata_xml
        assert "EntityDescriptor" in metadata_xml
        assert "SPSSODescriptor" in metadata_xml
        assert config["entity_id"] in metadata_xml
        assert config["assertion_consumer_service_url"] in metadata_xml

    def test_saml_authentication_request_url(self) -> None:
        """Test SAML authentication request URL generation."""
        config = {
            "entity_id": "https://app.example.com/saml/metadata",
            "sso_url": "https://idp.example.com/saml/sso",
            "x509_cert": "test-cert",
            "assertion_consumer_service_url": "https://app.example.com/saml/acs",
        }

        provider = FlextAuthSamlProvider(config)
        result = provider.get_authentication_request_url(relay_state="test-relay-state")

        assert result.is_success
        auth_url = result.unwrap()

        # Verify URL structure
        assert "https://idp.example.com/saml/sso" in auth_url
        assert "SAMLRequest=" in auth_url
        assert "RelayState=test-relay-state" in auth_url
