"""Tests for Phase 3 Authentication Providers.

Tests for advanced authentication providers including:
- FlextAuthApiKeyProvider
- FlextAuthBasicProvider
- FlextAuthCertificateProvider
- FlextAuthLdapProvider
- FlextAuthKerberosProvider

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import base64

import pytest

from flext_auth.providers import (
    FlextAuthApiKeyProvider,
    FlextAuthBasicProvider,
    FlextAuthCertificateProvider,
    FlextAuthKerberosProvider,
    FlextAuthLdapProvider,
)

# ===== FlextAuthApiKeyProvider Tests =====


class TestFlextAuthApiKeyProvider:
    """Tests for API Key authentication provider."""

    def test_apikey_initialization(self) -> None:
        """Test API Key provider initialization."""
        config = {
            "key_prefix": "sk_",
            "key_length": 32,
            "hash_algorithm": "sha256",
            "rate_limit_enabled": True,
            "rate_limit_requests": 1000,
        }
        provider = FlextAuthApiKeyProvider(config)

        metadata = provider.get_metadata()
        assert metadata["name"] == "apikey"
        assert metadata["key_prefix"] == "sk_"
        assert metadata["key_length"] == 32
        assert metadata["rate_limit_enabled"] is True

    def test_apikey_capabilities(self) -> None:
        """Test API Key provider capabilities."""
        config = {
            "key_prefix": "sk_",
            "rate_limit_enabled": True,
        }
        provider = FlextAuthApiKeyProvider(config)

        capabilities = provider.supports()
        assert "token" in capabilities
        assert "validate" in capabilities
        assert "apikey" in capabilities
        assert "revoke" in capabilities
        assert "rate_limit" in capabilities

    def test_apikey_generation(self) -> None:
        """Test API key generation."""
        config = {"key_prefix": "sk_", "key_length": 32}
        provider = FlextAuthApiKeyProvider(config)

        result = provider.generate_api_key(
            user_id="user-123", name="Production API Key", scopes=["read", "write"]
        )

        assert result.is_success
        key_data = result.unwrap()
        assert "key_id" in key_data
        assert "api_key" in key_data
        assert "key_hash" in key_data
        assert key_data["api_key"].startswith("sk_")

    def test_apikey_authentication_success(self) -> None:
        """Test successful API key authentication."""
        config = {"key_prefix": "sk_"}
        provider = FlextAuthApiKeyProvider(config)

        # Generate API key
        key_result = provider.generate_api_key(user_id="user-123", name="Test Key")
        assert key_result.is_success
        api_key = key_result.unwrap()["api_key"]

        # Authenticate with API key
        auth_result = provider.authenticate({"api_key": api_key})

        assert auth_result.is_success
        token = auth_result.unwrap()
        assert (
            token.token_type == "api"
        )  # Must match pattern: access|refresh|api|bearer
        assert token.user_id == "user-123"

    def test_apikey_authentication_invalid_key(self) -> None:
        """Test API key authentication with invalid key."""
        config = {"key_prefix": "sk_"}
        provider = FlextAuthApiKeyProvider(config)

        result = provider.authenticate({"api_key": "sk_invalid_key"})

        assert result.is_failure
        assert result.error is not None and "Invalid API key" in result.error

    def test_apikey_revocation(self) -> None:
        """Test API key revocation."""
        config = {"key_prefix": "sk_"}
        provider = FlextAuthApiKeyProvider(config)

        # Generate and authenticate
        key_result = provider.generate_api_key(user_id="user-123", name="Test Key")
        api_key = key_result.unwrap()["api_key"]

        # Revoke key
        revoke_result = provider.revoke(api_key)
        assert revoke_result.is_success

        # Authentication should fail after revocation
        auth_result = provider.authenticate({"api_key": api_key})
        assert auth_result.is_failure


# ===== FlextAuthBasicProvider Tests =====


class FlextAuthTestBasicProvider:
    """Tests for HTTP Basic authentication provider."""

    def test_basic_initialization(self) -> None:
        """Test Basic auth provider initialization."""
        config = {
            "realm": "My API",
            "allow_anonymous": False,
            "case_sensitive": True,
            "require_https": True,
        }
        provider = FlextAuthBasicProvider(config)

        metadata = provider.get_metadata()
        assert metadata["name"] == "basic"
        assert metadata["realm"] == "My API"
        assert metadata["require_https"] is True

    def test_basic_capabilities(self) -> None:
        """Test Basic auth provider capabilities."""
        config = {"realm": "Test", "allow_anonymous": True}
        provider = FlextAuthBasicProvider(config)

        capabilities = provider.supports()
        assert "token" in capabilities
        assert "validate" in capabilities
        assert "basic" in capabilities
        assert "revoke" in capabilities
        assert "anonymous" in capabilities

    def test_basic_user_management(self) -> None:
        """Test Basic auth user management."""
        config = {"realm": "Test"}
        provider = FlextAuthBasicProvider(config)

        # Add user
        add_result = provider.add_user(
            "testuser", "password123", user_id="user-001", roles=["REDACTED_LDAP_BIND_PASSWORD"]
        )
        assert add_result.is_success

        # Duplicate user should fail
        dup_result = provider.add_user("testuser", "password456")
        assert dup_result.is_failure

    def test_basic_authentication_success(self) -> None:
        """Test successful Basic authentication."""
        config = {"realm": "Test", "require_https": False}
        provider = FlextAuthBasicProvider(config)

        # Add user
        provider.add_user("testuser", "password123", user_id="user-001")

        # Create Basic auth header
        credentials = base64.b64encode(b"testuser:password123").decode("utf-8")
        auth_header = f"Basic {credentials}"

        # Authenticate
        result = provider.authenticate({"authorization": auth_header})

        assert result.is_success
        token = result.unwrap()
        assert (
            token.token_type == "bearer"
        )  # Must match pattern: access|refresh|api|bearer
        assert token.username == "testuser"
        assert token.user_id == "user-001"

    def test_basic_authentication_invalid_password(self) -> None:
        """Test Basic authentication with invalid password."""
        config = {"realm": "Test", "require_https": False}
        provider = FlextAuthBasicProvider(config)

        provider.add_user("testuser", "password123", user_id="user-001")

        # Wrong password
        credentials = base64.b64encode(b"testuser:wrongpassword").decode("utf-8")
        auth_header = f"Basic {credentials}"

        result = provider.authenticate({"authorization": auth_header})

        assert result.is_failure
        assert result.error is not None and "Invalid credentials" in result.error

    def test_basic_https_requirement(self) -> None:
        """Test Basic auth HTTPS requirement."""
        config = {"realm": "Test", "require_https": True}
        provider = FlextAuthBasicProvider(config)

        provider.add_user("testuser", "password123")

        credentials = base64.b64encode(b"testuser:password123").decode("utf-8")
        auth_header = f"Basic {credentials}"

        # HTTP URL should fail
        result = provider.authenticate({
            "authorization": auth_header,
            "request_url": "http://api.example.com",
        })

        assert result.is_failure
        assert result.error is not None and "requires HTTPS" in result.error

    def test_basic_anonymous_access(self) -> None:
        """Test Basic auth anonymous access."""
        config = {"realm": "Test", "allow_anonymous": True, "require_https": False}
        provider = FlextAuthBasicProvider(config)

        # Empty credentials for anonymous
        credentials = base64.b64encode(b":").decode("utf-8")
        auth_header = f"Basic {credentials}"

        result = provider.authenticate({"authorization": auth_header})

        assert result.is_success
        token = result.unwrap()
        assert token.username == "anonymous"


# ===== FlextAuthCertificateProvider Tests =====


class TestFlextAuthCertificateProvider:
    """Tests for X.509 Certificate authentication provider."""

    def test_certificate_initialization(self) -> None:
        """Test Certificate provider initialization."""
        config = {
            "ca_cert": "-----BEGIN CERTIFICATE-----\nCA CERT\n-----END CERTIFICATE-----",
            "verify_mode": "required",
            "check_ocsp": True,
            "allow_self_signed": False,
        }
        provider = FlextAuthCertificateProvider(config)

        metadata = provider.get_metadata()
        assert metadata["name"] == "certificate"
        assert metadata["verify_mode"] == "required"
        assert metadata["check_ocsp"] is True

    def test_certificate_initialization_missing_ca(self) -> None:
        """Test Certificate provider initialization without CA cert."""
        with pytest.raises(ValueError, match="ca_cert"):
            FlextAuthCertificateProvider({})

    def test_certificate_capabilities(self) -> None:
        """Test Certificate provider capabilities."""
        config = {
            "ca_cert": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
            "check_ocsp": True,
            "check_crl": True,
        }
        provider = FlextAuthCertificateProvider(config)

        capabilities = provider.supports()
        assert "token" in capabilities
        assert "validate" in capabilities
        assert "certificate" in capabilities
        assert "mtls" in capabilities
        assert "revoke" in capabilities
        assert "ocsp" in capabilities
        assert "crl" in capabilities

    def test_certificate_registration(self) -> None:
        """Test certificate registration."""
        config = {
            "ca_cert": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"
        }
        provider = FlextAuthCertificateProvider(config)

        # Register certificate
        fingerprint = "abc123def456"
        result = provider.register_certificate(
            fingerprint, user_id="user-001", username="testuser", roles=["REDACTED_LDAP_BIND_PASSWORD"]
        )

        assert result.is_success

        # Duplicate registration should fail
        dup_result = provider.register_certificate(fingerprint, user_id="user-002")
        assert dup_result.is_failure

    def test_certificate_authentication_with_real_cert(self) -> None:
        """Test certificate authentication with real self-signed certificate."""
        from tests.fixtures.certificates import generate_self_signed_cert

        # Generate a real self-signed certificate for testing
        cert_fixture = generate_self_signed_cert(
            common_name="test-client.example.com",
            organization="Test Client Org",
            valid_days=365,
        )

        # Create provider without CA (self-signed mode)
        config = {
            "ca_cert": cert_fixture.cert_pem,  # Use same cert as CA for self-signed
            "auto_provision": True,
        }
        provider = FlextAuthCertificateProvider(config)

        # Authenticate with real certificate (should auto-provision)
        result = provider.authenticate({"client_cert": cert_fixture.cert_pem})

        # Should succeed with auto-provisioning
        assert result.is_success
        token = result.unwrap()
        assert (
            token.token_type == "bearer"
        )  # Must match pattern: access|refresh|api|bearer
        assert token.certificate_fingerprint == cert_fixture.fingerprint
        assert "test-client.example.com" in token.certificate_subject


# ===== FlextAuthLdapProvider Tests =====


class TestFlextAuthLdapProvider:
    """Tests for LDAP authentication provider."""

    def test_ldap_initialization(self) -> None:
        """Test LDAP provider initialization."""
        config = {
            "server": "ldaps://ldap.example.com:636",
            "base_dn": "ou=users,dc=example,dc=com",
            "bind_dn": "cn=service,dc=example,dc=com",
            "bind_password": "service-pass",
            "use_ssl": True,
        }
        provider = FlextAuthLdapProvider(config)

        metadata = provider.get_metadata()
        assert metadata["name"] == "ldap"
        assert metadata["server"] == "ldaps://ldap.example.com:636"
        assert metadata["use_ssl"] is True

    def test_ldap_initialization_missing_server(self) -> None:
        """Test LDAP provider initialization without server."""
        with pytest.raises(ValueError, match="server"):
            FlextAuthLdapProvider({"base_dn": "dc=example,dc=com"})

    def test_ldap_initialization_missing_base_dn(self) -> None:
        """Test LDAP provider initialization without base_dn."""
        with pytest.raises(ValueError, match="base_dn"):
            FlextAuthLdapProvider({"server": "ldaps://ldap.example.com"})

    def test_ldap_capabilities(self) -> None:
        """Test LDAP provider capabilities."""
        config = {
            "server": "ldaps://ldap.example.com",
            "base_dn": "dc=example,dc=com",
        }
        provider = FlextAuthLdapProvider(config)

        capabilities = provider.supports()
        assert "token" in capabilities
        assert "validate" in capabilities
        assert "ldap" in capabilities
        assert "directory" in capabilities
        assert "groups" in capabilities

    def test_ldap_authentication_requires_flext_ldap(self) -> None:
        """Test LDAP authentication requires flext-ldap integration."""
        config = {
            "server": "ldaps://ldap.example.com",
            "base_dn": "dc=example,dc=com",
        }
        provider = FlextAuthLdapProvider(config)

        result = provider.authenticate({
            "username": "testuser",
            "password": "password",
        })

        assert result.is_failure
        assert result.error is not None and "flext-ldap" in result.error


# ===== FlextAuthKerberosProvider Tests =====


class TestFlextAuthKerberosProvider:
    """Tests for Kerberos authentication provider."""

    def test_kerberos_initialization(self) -> None:
        """Test Kerberos provider initialization."""
        config = {
            "realm": "EXAMPLE.COM",
            "kdc": "kdc.example.com",
            "service_principal": "HTTP/api.example.com@EXAMPLE.COM",
            "ticket_lifetime": 10,
            "forwardable": True,
        }
        provider = FlextAuthKerberosProvider(config)

        metadata = provider.get_metadata()
        assert metadata["name"] == "kerberos"
        assert metadata["realm"] == "EXAMPLE.COM"
        assert metadata["kdc"] == "kdc.example.com"
        assert metadata["forwardable"] is True

    def test_kerberos_initialization_missing_realm(self) -> None:
        """Test Kerberos provider initialization without realm."""
        with pytest.raises(ValueError, match="realm"):
            FlextAuthKerberosProvider({
                "kdc": "kdc.example.com",
                "service_principal": "HTTP/api@REALM",
            })

    def test_kerberos_initialization_missing_kdc(self) -> None:
        """Test Kerberos provider initialization without KDC."""
        with pytest.raises(ValueError, match="kdc"):
            FlextAuthKerberosProvider({
                "realm": "EXAMPLE.COM",
                "service_principal": "HTTP/api@REALM",
            })

    def test_kerberos_initialization_missing_service_principal(self) -> None:
        """Test Kerberos provider initialization without service principal."""
        with pytest.raises(ValueError, match="service_principal"):
            FlextAuthKerberosProvider({
                "realm": "EXAMPLE.COM",
                "kdc": "kdc.example.com",
            })

    def test_kerberos_capabilities(self) -> None:
        """Test Kerberos provider capabilities."""
        config = {
            "realm": "EXAMPLE.COM",
            "kdc": "kdc.example.com",
            "service_principal": "HTTP/api@EXAMPLE.COM",
        }
        provider = FlextAuthKerberosProvider(config)

        capabilities = provider.supports()
        assert "token" in capabilities
        assert "validate" in capabilities
        assert "refresh" in capabilities
        assert "kerberos" in capabilities
        assert "gssapi" in capabilities
        assert "sso" in capabilities
        assert "mutual_auth" in capabilities

    def test_kerberos_authentication_requires_gssapi(self) -> None:
        """Test Kerberos authentication requires GSSAPI integration."""
        config = {
            "realm": "EXAMPLE.COM",
            "kdc": "kdc.example.com",
            "service_principal": "HTTP/api@EXAMPLE.COM",
        }
        provider = FlextAuthKerberosProvider(config)

        # GSSAPI token authentication
        result = provider.authenticate({"gssapi_token": "base64-token"})

        assert result.is_failure
        assert result.error is not None and "gssapi" in result.error.lower()

    def test_kerberos_password_authentication_requires_kerberos_lib(self) -> None:
        """Test Kerberos password authentication requires kerberos library."""
        config = {
            "realm": "EXAMPLE.COM",
            "kdc": "kdc.example.com",
            "service_principal": "HTTP/api@EXAMPLE.COM",
        }
        provider = FlextAuthKerberosProvider(config)

        # Password authentication
        result = provider.authenticate({
            "username": "user@EXAMPLE.COM",
            "password": "password",
        })

        assert result.is_failure
        assert result.error is not None and "kerberos" in result.error.lower()

    def test_kerberos_principal_parsing(self) -> None:
        """Test Kerberos principal name parsing."""
        config = {
            "realm": "EXAMPLE.COM",
            "kdc": "kdc.example.com",
            "service_principal": "HTTP/api@EXAMPLE.COM",
        }
        provider = FlextAuthKerberosProvider(config)

        # User principal
        user_principal = provider._parse_principal("user@EXAMPLE.COM")
        assert user_principal["primary"] == "user"
        assert user_principal["instance"] is None
        assert user_principal["realm"] == "EXAMPLE.COM"

        # Service principal
        service_principal = provider._parse_principal("HTTP/api.example.com@REALM")
        assert service_principal["primary"] == "HTTP"
        assert service_principal["instance"] == "api.example.com"
        assert service_principal["realm"] == "REALM"
