"""Certificate test fixtures for authentication testing.

Simple mock certificate fixtures for testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field


class CertificateFixture(BaseModel):
    """Certificate fixture data."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    cert_pem: str = Field(description="PEM-encoded certificate")
    key_pem: str = Field(description="PEM-encoded private key")
    fingerprint: str = Field(description="Certificate fingerprint hash")
    subject_cn: str = Field(description="Certificate subject common name")


def generate_self_signed_cert(
    common_name: str = "test.example.com",
    organization: str = "Test Organization",
    valid_days: int = 365,
) -> CertificateFixture:
    """Generate a mock certificate fixture for testing.

    Returns hardcoded test data to avoid cryptography library type issues.
    """
    mock_cert_pem = f"-----BEGIN CERTIFICATE-----\nMOCK CERTIFICATE FOR TESTING\nCommon Name: {common_name}\nOrganization: {organization}\nValid Days: {valid_days}\n-----END CERTIFICATE-----"
    mock_key_pem = "-----BEGIN PRIVATE KEY-----\nMOCK PRIVATE KEY FOR TESTING\n-----END PRIVATE KEY-----"
    mock_fingerprint = (
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    )
    return CertificateFixture(
        cert_pem=mock_cert_pem,
        key_pem=mock_key_pem,
        fingerprint=mock_fingerprint,
        subject_cn=common_name,
    )


def generate_client_cert(
    common_name: str = "client.example.com",
    organization: str = "Test Client",
) -> CertificateFixture:
    """Generate a mock client certificate fixture for testing.

    Returns hardcoded test data to avoid cryptography library type issues.
    """
    mock_cert_pem = f"-----BEGIN CERTIFICATE-----\nMOCK CLIENT CERTIFICATE FOR TESTING\nCommon Name: {common_name}\nOrganization: {organization}\nType: Client Certificate\n-----END CERTIFICATE-----"
    mock_key_pem = "-----BEGIN PRIVATE KEY-----\nMOCK CLIENT PRIVATE KEY FOR TESTING\n-----END PRIVATE KEY-----"
    mock_fingerprint = (
        "bbccddeeff00112233445566778899aabbccddeeff0011223344556677889900"
    )
    return CertificateFixture(
        cert_pem=mock_cert_pem,
        key_pem=mock_key_pem,
        fingerprint=mock_fingerprint,
        subject_cn=common_name,
    )
