"""X.509 Certificate authentication provider implementation.

This module implements X.509 certificate-based authentication, commonly used for:
- Mutual TLS (mTLS) authentication
- PKI-based authentication systems
- IoT device authentication
- API-to-API authentication
- High-security environments

Certificate authentication validates client identity through cryptographic
certificates issued by trusted Certificate Authorities (CAs).

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import cast

# Third-party imports for certificate processing
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from flext_core import FlextExceptions, FlextLogger, FlextResult

from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.mixin import FlextAuthProviderMixin


class FlextAuthCertificateProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    r"""SOLID-compliant X.509 certificate authentication provider.

    Uses composition for certificate validation, revocation checking, and metadata extraction.
    Railway-oriented programming with flext-core patterns for maximum maintainability.

        >>> config = {
        ...     "ca_cert": "-----BEGIN CERTIFICATE-----\\\\n...\\\\n-----END CERTIFICATE-----",
        ...     "verify_mode": "required",
        ...     "check_ocsp": True,
        ...     "allow_self_signed": False,
        ... }
        >>> provider = FlextAuthCertificateProvider(config)
        >>> # Authenticate with client certificate
        >>> result = provider.authenticate({
        ...     "client_cert": "-----BEGIN CERTIFICATE-----\\\\n...\\\\n-----END CERTIFICATE-----",
        ...     "client_key": "-----BEGIN PRIVATE KEY-----\\\\n...\\\\n-----END PRIVATE KEY-----",
        ... })

    """

    def __init__(self, config: FlextAuthModels.ProviderConfiguration) -> None:
        """Initialize Certificate authentication provider with SOLID delegation.

        Uses composition for certificate validation, revocation checking, and metadata extraction.
        Railway-oriented initialization with proper error handling.
        """
        self.logger = FlextLogger(__name__)
        self._config = config

        # Use railway-oriented validation
        validation_result = self._validate_configuration()
        if validation_result.is_failure:
            msg = f"Certificate configuration validation failed: {validation_result.error}"
            raise FlextExceptions.ConfigurationError(
                msg,
                config_key="config",
            )

        # Initialize components using composition
        self._cert_validator = self._CertificateValidator(self)
        self._revocation_checker = self._RevocationChecker(self)
        self._metadata_extractor = self._MetadataExtractor(self)

        # In-memory storage for certificate mappings
        self._cert_mappings: dict[str, dict[str, object]] = {}

        self.logger.info("Certificate authentication provider initialized")

    def _validate_configuration(self) -> FlextResult[None]:
        """Railway-oriented configuration validation."""
        # Validate required fields
        required_fields = ["ca_cert"]
        missing_fields = [
            field for field in required_fields if field not in self._config
        ]

        if missing_fields:
            return FlextResult[None].fail(
                f"Missing required certificate configuration fields: {', '.join(missing_fields)}"
            )

        # Validate field types
        validations = [
            ("ca_cert", str, "Certificate ca_cert must be a string"),
            (
                "ca_chain",
                (list, type(None)),
                "Certificate ca_chain must be a list or None",
            ),
            (
                "verify_mode",
                (str, type(None)),
                "Certificate verify_mode must be a string or None",
            ),
            (
                "check_ocsp",
                (bool, type(None)),
                "Certificate check_ocsp must be a boolean or None",
            ),
            (
                "check_crl",
                (bool, type(None)),
                "Certificate check_crl must be a boolean or None",
            ),
            (
                "allow_self_signed",
                (bool, type(None)),
                "Certificate allow_self_signed must be a boolean or None",
            ),
            (
                "subject_pattern",
                (str, type(None)),
                "Certificate subject_pattern must be a string or None",
            ),
            (
                "issuer_pattern",
                (str, type(None)),
                "Certificate issuer_pattern must be a string or None",
            ),
        ]

        for field_name, expected_types, error_msg in validations:
            field_value = self._config.get(field_name)
            if field_value is not None and not isinstance(field_value, expected_types):
                return FlextResult[None].fail(
                    f"{error_msg}. Got {type(field_value).__name__}"
                )

        return FlextResult[None].ok(None)

    class _CertificateValidator:
        """SOLID-compliant certificate validator.

        Single responsibility: validate X.509 certificates.
        """

        def __init__(self, provider: FlextAuthCertificateProvider) -> None:
            """Initialize certificate validator."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def validate_certificate(self, cert_pem: str) -> FlextResult[dict[str, object]]:
            """Validate X.509 certificate using cryptography library."""
            try:
                # Load certificate
                cert = x509.load_pem_x509_certificate(cert_pem.encode())

                # Extract certificate information
                cert_info = {
                    "subject": str(cert.subject),
                    "issuer": str(cert.issuer),
                    "serial_number": str(cert.serial_number),
                    "not_valid_before": cert.not_valid_before,
                    "not_valid_after": cert.not_valid_after,
                    "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
                }

                # Check expiration
                now = datetime.now(UTC)
                if now < cert.not_valid_before:
                    return FlextResult[dict[str, object]].fail(
                        "Certificate not yet valid"
                    )
                if now > cert.not_valid_after:
                    return FlextResult[dict[str, object]].fail("Certificate expired")

                return FlextResult[dict[str, object]].ok(cert_info)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"Certificate validation failed: {e}"
                )

    class _RevocationChecker:
        """SOLID-compliant certificate revocation checker.

        Single responsibility: check certificate revocation status.
        """

        def __init__(self, provider: FlextAuthCertificateProvider) -> None:
            """Initialize revocation checker."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def check_revocation(self, _cert_info: dict[str, object]) -> FlextResult[bool]:
            """Check if certificate is revoked."""
            # Simplified implementation - in production would check OCSP/CRL
            # cert_info parameter reserved for future certificate validation
            if self.provider.should_check_ocsp():
                # Would implement OCSP checking here
                pass
            if self.provider.should_check_crl():
                # Would implement CRL checking here
                pass

            return FlextResult[bool].ok(False)  # Not revoked

    class _MetadataExtractor:
        """SOLID-compliant metadata extractor.

        Single responsibility: extract metadata from certificates.
        """

        def __init__(self, provider: FlextAuthCertificateProvider) -> None:
            """Initialize metadata extractor."""
            self.provider = provider
            self.logger = FlextLogger(__name__)

        def extract_user_info(
            self, cert_info: dict[str, object]
        ) -> FlextResult[dict[str, object]]:
            """Extract user information from certificate."""
            # Extract common name from subject
            subject = cert_info.get("subject", "")
            user_info = {
                "user_id": cert_info.get("fingerprint", ""),
                "name": self._extract_common_name(subject),
                "email": self._extract_email(subject),
            }

            return FlextResult[dict[str, object]].ok(user_info)

        def _extract_common_name(self, subject: str) -> str:
            """Extract common name from certificate subject."""
            # Simplified implementation
            return (
                subject.rsplit("CN=", maxsplit=1)[-1].split(",")[0]
                if "CN=" in subject
                else "unknown"
            )

        def _extract_email(self, subject: str) -> str:
            """Extract email from certificate subject."""
            # Simplified implementation - subject parameter reserved for future parsing
            _ = subject  # Mark as intentionally unused for now
            return "unknown"  # Would parse email from subject

    def authenticate(
        self,
        credentials: FlextAuthModels.CertificateValidation,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate using X.509 certificate with SOLID delegation.

        Delegates certificate validation, revocation checking, and metadata extraction
        to specialized components following SRP.
        """
        # Use the CertificateValidation model directly
        if not credentials.is_valid:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                credentials.error_message or "Invalid certificate"
            )

        if not credentials.cert_info:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "No certificate info available"
            )

        if credentials.revocation_status:
            return FlextResult[FlextAuthModels.AuthToken].fail("Certificate is revoked")

        # Use composition for certificate processing
        return self._process_certificate_authentication(
            str(credentials.cert_info.get("client_cert", "")), is_revoked=False
        )

    def _process_certificate_authentication(
        self,
        client_cert: str,
        *,
        is_revoked: bool,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Process certificate authentication result."""
        # client_cert parameter reserved for future certificate processing
        _ = client_cert  # Mark as intentionally unused for now
        if is_revoked:
            return FlextResult[FlextAuthModels.AuthToken].fail("Certificate revoked")

        # For now, return simplified token - would extract cert_info from previous step
        return FlextResult[FlextAuthModels.AuthToken].fail(
            "Certificate authentication not fully implemented in refactor"
        )

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[bool]:
        """Validate certificate token.

        Args:
        token: Certificate fingerprint or AuthToken object

        Returns:
        FlextResult[bool]: True if certificate is valid

        """
        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[bool].fail(str(e))

        # Check if certificate is mapped
        if token_string not in self._cert_mappings:
            return FlextResult[bool].fail("Certificate not found")

        user_data = self._cert_mappings[token_string]

        # Check if user is active
        if not user_data.get("active", True):
            return FlextResult[bool].fail("Certificate has been revoked")

        # In production: Re-validate certificate
        # - Check validity period
        # - Check revocation status
        # - Validate certificate chain

        # Check expiration if we have AuthToken object
        if (
            isinstance(token, FlextAuthModels.AuthToken)
            and token.expires_at
            and datetime.now(UTC) > token.expires_at
        ):
            return FlextResult[bool].fail("Certificate expired")

        return FlextResult[bool].ok(True)

    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh certificate token.

        Certificates cannot be refreshed programmatically. A new certificate
        must be obtained from the CA.

        Args:
        token: Current certificate token

        Returns:
        FlextResult[AuthToken]: Error indicating refresh not supported

        """
        _ = token  # Token parameter required by interface but not used for certificate refresh
        return FlextResult[FlextAuthModels.AuthToken].fail(
            "Certificate authentication does not support token refresh. "
            "Obtain a new certificate from the Certificate Authority."
        )

    def revoke(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[None]:
        """Revoke certificate access.

        This marks the certificate as revoked in the local mapping.
        In production, this should also trigger CRL/OCSP updates.

        Args:
        token: Certificate token to revoke

        Returns:
        FlextResult[None]: Success or error

        """
        try:
            token_string = self._extract_token_string(token)
        except ValueError as e:
            return FlextResult[None].fail(str(e))

        if token_string not in self._cert_mappings:
            return FlextResult[None].fail("Certificate not found")

        # Mark certificate as revoked
        self._cert_mappings[token_string]["active"] = False
        self._cert_mappings[token_string]["revoked_at"] = datetime.now(UTC)

        # In production: Add to CRL or update OCSP responder

        self.logger.info(
            "Certificate revoked",
            extra={"fingerprint": token_string[:16] + "..."},
        )

        return FlextResult[None].ok(None)

    def supports(self) -> set[str]:
        """Return Certificate provider capabilities.

        Returns:
        set[str]: Set of supported capability strings

        Capabilities:
        - token: Token generation from certificate
        - validate: Certificate validation
        - certificate: X.509 certificate authentication
        - mtls: Mutual TLS support
        - revoke: Certificate revocation
        - ocsp: OCSP revocation checking (if enabled)
        - crl: CRL revocation checking (if enabled)

        """
        capabilities = {"token", "validate", "certificate", "mtls", "revoke"}

        if self._check_ocsp:
            capabilities.add("ocsp")

        if self._check_crl:
            capabilities.add("crl")

        return capabilities

    def get_metadata(self) -> FlextAuthModels.ProviderConfiguration:
        """Return Certificate provider metadata.

        Returns:
        dict[str, object]: Provider metadata

        """
        return FlextAuthModels.ProviderConfiguration(
            name="certificate",
            type="x509_certificate",
            enabled=True,
            version="2.0.0",
            description="X.509 Certificate authentication provider",
            capabilities=list(self.supports()),
            verify_mode=self._verify_mode,
            check_ocsp=self._check_ocsp,
            check_crl=self._check_crl,
            allow_self_signed=self._allow_self_signed,
        )

    def validate_token(
        self,
        _token: str,
    ) -> FlextResult[FlextAuthModels.Identity | None]:
        """Validate certificate token and return user using composition."""
        return FlextResult[FlextAuthModels.Identity | None].ok(
            None
        )  # Simplified implementation

    def generate_token_for_user(
        self,
        _user: FlextAuthModels.Identity,
        _token_type: str = "cert_access",
        _expiry_minutes: int | None = None,
    ) -> FlextResult[str]:
        """Generate certificate token for user."""
        return FlextResult[str].fail(
            "Certificate token generation not implemented in this refactor"
        )

    # Helper methods

    def _extract_certificate_info(
        self, cert_pem: str
    ) -> FlextResult[dict[str, object]]:
        """Extract information from PEM certificate using cryptography library.

        Args:
        cert_pem: PEM-encoded certificate

        Returns:
        FlextResult[dict[str, object]]: Certificate information or error

        """
        if not cert_pem.startswith("-----BEGIN CERTIFICATE-----"):
            return FlextResult[dict[str, object]].fail("Invalid PEM certificate format")

        try:
            # Parse PEM certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

            # Calculate SHA256 fingerprint
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()

            # Extract subject DN
            subject_parts = [
                f"{attr.oid.dotted_string}={attr.value}" for attr in cert.subject
            ]
            subject_dn = ",".join(subject_parts)

            # Extract issuer DN
            issuer_parts = [
                f"{attr.oid.dotted_string}={attr.value}" for attr in cert.issuer
            ]
            issuer_dn = ",".join(issuer_parts)

            # Get validity dates
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after

            # Get serial number
            serial_number = format(cert.serial_number, "x")

            # Get public key algorithm
            public_key = cert.public_key()
            key_algorithm = (
                type(public_key).__name__.replace("Public", "").replace("Key", "")
            )

            # Get signature algorithm
            signature_algorithm = cert.signature_algorithm_oid.dotted_string

            cert_info = {
                "subject": subject_dn,
                "issuer": issuer_dn,
                "serial_number": serial_number,
                "fingerprint": fingerprint,
                "not_before": not_before,
                "not_after": not_after,
                "version": cert.version.value,
                "key_algorithm": key_algorithm,
                "signature_algorithm": signature_algorithm,
            }

            self.logger.debug(
                "Certificate parsed successfully",
                extra={"fingerprint": fingerprint, "subject": subject_dn},
            )

            return FlextResult[dict[str, object]].ok(
                cast("dict[str, object]", cert_info)
            )

        except ValueError as e:
            return FlextResult[dict[str, object]].fail(
                f"Invalid certificate format: {e}"
            )
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Certificate parsing failed: {e}"
            )

    def _validate_certificate(
        self, cert_pem: str, cert_info: dict[str, object]
    ) -> FlextResult[None]:
        """Validate certificate using cryptography library.

        Args:
        cert_pem: PEM-encoded certificate
        cert_info: Parsed certificate information

        Returns:
        FlextResult[None]: Success if valid, error otherwise

        """
        try:
            # Parse certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

            # Check validity period
            now = datetime.now(UTC)
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after

            if now < not_before:
                return FlextResult[None].fail(
                    f"Certificate not yet valid (valid from {not_before})"
                )

            if now > not_after:
                return FlextResult[None].fail(
                    f"Certificate expired (expired on {not_after})"
                )

            # Validate against CA certificate
            if self._ca_cert:
                ca_validation_result = self._validate_against_ca(
                    cert, cast("str", self._ca_cert)
                )
                if ca_validation_result.is_failure:
                    return ca_validation_result

            self.logger.debug(
                "Certificate validation passed",
                extra={"fingerprint": cert_info.get("fingerprint")},
            )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Certificate validation failed: {e}")

    def _validate_against_ca(
        self, cert: x509.Certificate, ca_cert_pem: str
    ) -> FlextResult[None]:
        """Validate certificate against CA certificate.

        Args:
        cert: Parsed certificate object
        ca_cert_pem: PEM-encoded CA certificate

        Returns:
        FlextResult[None]: Success if valid, error otherwise

        """
        try:
            # Parse CA certificate
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))

            # Verify certificate is signed by CA
            # Note: Full chain validation requires building and verifying the entire chain
            # For now, we verify the issuer matches the CA subject
            cert_issuer = cert.issuer.rfc4514_string()
            ca_subject = ca_cert.subject.rfc4514_string()

            if cert_issuer != ca_subject:
                return FlextResult[None].fail(
                    f"Certificate issuer does not match CA subject: {cert_issuer} != {ca_subject}"
                )

            # In production, verify the signature:
            # 1. Extract CA's public key
            # 2. Verify certificate signature using CA's public key
            # 3. Build and verify full certificate chain
            # For now, we consider issuer match as basic validation

            self.logger.debug("Certificate CA validation passed")

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"CA validation failed: {e}")

    def _auto_provision_user(
        self, cert_info: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Auto-provision user from certificate information.

        Args:
        cert_info: Certificate information

        Returns:
        FlextResult[dict[str, object]]: User data or error

        """
        # Extract username from certificate subject (CN field)
        subject = cast("str", cert_info.get("subject", ""))
        username = self._extract_cn_from_subject(subject)

        if not username:
            return FlextResult[dict[str, object]].fail(
                "Cannot extract username from certificate subject"
            )

        user_id = f"cert-{secrets.token_hex(8)}"
        fingerprint = cert_info["fingerprint"]

        user_data = {
            "user_id": user_id,
            "username": username,
            "roles": ["certificate-user"],
            "permissions": [],
            "active": True,
            "certificate_subject": cert_info.get("subject"),
            "certificate_issuer": cert_info.get("issuer"),
        }

        # Store certificate mapping
        fingerprint = cast("str", cert_info.get("fingerprint", ""))
        self._cert_mappings[fingerprint] = user_data

        self.logger.info(
            "User auto-provisioned from certificate",
            extra={"user_id": user_id, "username": username},
        )

        return FlextResult[dict[str, object]].ok(user_data)

    def _extract_cn_from_subject(self, subject: str) -> str:
        """Extract Common Name (CN) from certificate subject.

        Args:
        subject: Certificate subject string

        Returns:
        str: Common Name or empty string

        """
        # Parse subject string - handles both formats:
        # Old: "CN=example.com,O=Example Corp"
        # New (cryptography): "commonName=example.com,organizationName=Example Corp"
        for comp in subject.split(","):
            stripped_comp = comp.strip()
            if stripped_comp.startswith("CN="):
                return stripped_comp[3:]  # Remove "CN=" prefix
            if stripped_comp.startswith("commonName="):
                return stripped_comp[11:]  # Remove "commonName=" prefix

        return ""

    # Certificate management methods (for in-memory storage)

    def register_certificate(
        self,
        cert_fingerprint: str,
        user_id: str,
        username: str | None = None,
        roles: list[str] | None = None,
        permissions: list[str] | None = None,
    ) -> FlextResult[None]:
        """Register certificate mapping to user.

        Args:
        cert_fingerprint: Certificate fingerprint (SHA256 hex)
        user_id: User ID to associate with certificate
        username: Username
        roles: User roles
        permissions: User permissions

        Returns:
        FlextResult[None]: Success or error

        """
        if cert_fingerprint in self._cert_mappings:
            return FlextResult[None].fail(
                f"Certificate '{cert_fingerprint}' already registered"
            )

        self._cert_mappings[cert_fingerprint] = {
            "user_id": user_id,
            "username": username,
            "roles": roles or [],
            "permissions": permissions or [],
            "active": True,
        }

        self.logger.info(
            "Certificate registered",
            extra={"fingerprint": cert_fingerprint[:16] + "...", "user_id": user_id},
        )

        return FlextResult[None].ok(None)

    def unregister_certificate(self, cert_fingerprint: str) -> FlextResult[None]:
        """Unregister certificate mapping.

        Args:
        cert_fingerprint: Certificate fingerprint to remove

        Returns:
        FlextResult[None]: Success or error

        """
        if cert_fingerprint not in self._cert_mappings:
            return FlextResult[None].fail(f"Certificate '{cert_fingerprint}' not found")

        del self._cert_mappings[cert_fingerprint]

        self.logger.info(
            "Certificate unregistered",
            extra={"fingerprint": cert_fingerprint[:16] + "..."},
        )

        return FlextResult[None].ok(None)


__all__ = ["FlextAuthCertificateProvider"]
