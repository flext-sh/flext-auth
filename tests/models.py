from __future__ import annotations

from typing import Annotated, ClassVar

from flext_tests import FlextTestsModels
from testes import u

from flext_auth import m, t


class TestsFlextAuthModels(FlextTestsModels, m):
    """Test models for flext-auth."""

    class Tests(FlextTestsModels.Tests):
        """Test-specific models."""


class CertificateFixture(m.BaseModel):
    """Certificate fixture data."""

    model_config: ClassVar[t.ConfigDict] = m.ConfigDict(frozen=True)

    cert_pem: Annotated[str, u.Field(description="PEM-encoded certificate")]
    key_pem: Annotated[str, u.Field(description="PEM-encoded private key")]
    fingerprint: Annotated[str, u.Field(description="Certificate fingerprint hash")]
    subject_cn: Annotated[str, u.Field(description="Certificate subject common name")]

    @classmethod
    def generate_self_signed_cert(
        cls,
        common_name: str = "test.example.com",
        organization: str = "Test Organization",
        valid_days: int = 365,
    ) -> CertificateFixture:
        """Generate a mock certificate fixture for testing."""
        mock_cert_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MOCK CERTIFICATE FOR TESTING\n"
            f"Common Name: {common_name}\n"
            f"Organization: {organization}\n"
            f"Valid Days: {valid_days}\n"
            "-----END CERTIFICATE-----"
        )
        mock_key_pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MOCK PRIVATE KEY FOR TESTING\n"
            "-----END PRIVATE KEY-----"
        )
        mock_fingerprint = (
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        )
        return cls(
            cert_pem=mock_cert_pem,
            key_pem=mock_key_pem,
            fingerprint=mock_fingerprint,
            subject_cn=common_name,
        )

    @classmethod
    def generate_client_cert(
        cls, common_name: str = "client.example.com", organization: str = "Test Client"
    ) -> CertificateFixture:
        """Generate a mock client certificate fixture for testing."""
        mock_cert_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MOCK CLIENT CERTIFICATE FOR TESTING\n"
            f"Common Name: {common_name}\n"
            f"Organization: {organization}\n"
            "Type: Client Certificate\n"
            "-----END CERTIFICATE-----"
        )
        mock_key_pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MOCK CLIENT PRIVATE KEY FOR TESTING\n"
            "-----END PRIVATE KEY-----"
        )
        mock_fingerprint = (
            "bbccddeeff00112233445566778899aabbccddeeff0011223344556677889900"
        )
        return cls(
            cert_pem=mock_cert_pem,
            key_pem=mock_key_pem,
            fingerprint=mock_fingerprint,
            subject_cn=common_name,
        )


__all__: list[str] = ["CertificateFixture", "TestsFlextAuthModels", "m"]
