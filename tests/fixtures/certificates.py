"""Certificate test fixtures for authentication testing.

Generates self-signed certificates for testing certificate authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


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
    """Generate a self-signed certificate for testing.

    Args:
        common_name: Certificate Common Name (CN)
        organization: Certificate Organization (O)
        valid_days: Number of days the certificate is valid

    Returns:
        CertificateFixture: Generated certificate and key data

    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Create certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(common_name)],
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Calculate fingerprint
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    # Serialize certificate and key to PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    return CertificateFixture(
        cert_pem=cert_pem,
        key_pem=key_pem,
        fingerprint=fingerprint,
        subject_cn=common_name,
    )


def generate_ca_cert(
    common_name: str = "Test CA",
    organization: str = "Test CA Organization",
    valid_days: int = 3650,
) -> CertificateFixture:
    """Generate a CA certificate for testing.

    Args:
        common_name: CA Common Name (CN)
        organization: CA Organization (O)
        valid_days: Number of days the CA certificate is valid

    Returns:
        CertificateFixture: Generated CA certificate and key data

    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create CA subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Create CA certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Calculate fingerprint
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    # Serialize certificate and key to PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    return CertificateFixture(
        cert_pem=cert_pem,
        key_pem=key_pem,
        fingerprint=fingerprint,
        subject_cn=common_name,
    )


def generate_signed_cert(
    ca_cert_pem: str,
    ca_key_pem: str,
    common_name: str = "client.example.com",
    organization: str = "Client Organization",
    valid_days: int = 365,
) -> CertificateFixture:
    """Generate a certificate signed by a CA for testing.

    Args:
        ca_cert_pem: PEM-encoded CA certificate
        ca_key_pem: PEM-encoded CA private key
        common_name: Client certificate Common Name (CN)
        organization: Client certificate Organization (O)
        valid_days: Number of days the certificate is valid

    Returns:
        CertificateFixture: Generated client certificate and key data

    """
    # Load CA certificate and key
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))
    ca_key = serialization.load_pem_private_key(
        ca_key_pem.encode("utf-8"), password=None
    )

    # Generate client private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create client certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Create client certificate (signed by CA)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)  # Use CA's subject as issuer
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(common_name)],
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())  # Sign with CA's private key
    )

    # Calculate fingerprint
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    # Serialize certificate and key to PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    return CertificateFixture(
        cert_pem=cert_pem,
        key_pem=key_pem,
        fingerprint=fingerprint,
        subject_cn=common_name,
    )


__all__ = [
    "CertificateFixture",
    "generate_ca_cert",
    "generate_self_signed_cert",
    "generate_signed_cert",
]
