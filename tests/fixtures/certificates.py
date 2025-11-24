"""Certificate test fixtures for authentication testing.

Simple mock certificate fixtures for testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

from typing import NamedTuple


class CertificateFixture(NamedTuple):
    """Certificate fixture data."""

    cert_pem: str
    key_pem: str
    fingerprint: str
    subject_cn: str


def generate_self_signed_cert(
    common_name: str = "test.example.com",
    organization: str = "Test Organization",
    valid_days: int = 365,
) -> CertificateFixture:
    """Generate a mock certificate fixture for testing.

    Returns hardcoded test data to avoid cryptography library type issues.
    """
    # Mock certificate data for testing
    mock_cert_pem = f"""-----BEGIN CERTIFICATE-----
MOCK CERTIFICATE FOR TESTING
Common Name: {common_name}
Organization: {organization}
Valid Days: {valid_days}
-----END CERTIFICATE-----"""

    mock_key_pem = """-----BEGIN PRIVATE KEY-----
MOCK PRIVATE KEY FOR TESTING
-----END PRIVATE KEY-----"""

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
    # Mock client certificate data for testing
    mock_cert_pem = f"""-----BEGIN CERTIFICATE-----
MOCK CLIENT CERTIFICATE FOR TESTING
Common Name: {common_name}
Organization: {organization}
Type: Client Certificate
-----END CERTIFICATE-----"""

    mock_key_pem = """-----BEGIN PRIVATE KEY-----
MOCK CLIENT PRIVATE KEY FOR TESTING
-----END PRIVATE KEY-----"""

    mock_fingerprint = (
        "bbccddeeff00112233445566778899aabbccddeeff0011223344556677889900"
    )

    return CertificateFixture(
        cert_pem=mock_cert_pem,
        key_pem=mock_key_pem,
        fingerprint=mock_fingerprint,
        subject_cn=common_name,
    )
