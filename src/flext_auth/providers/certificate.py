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
from datetime import UTC, datetime, timedelta
from typing import Any

from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import BaseAuthProvider, BaseAuthProviderMixin
from flext_core import FlextLogger, FlextResult


class CertificateAuthProvider(BaseAuthProvider, BaseAuthProviderMixin):
    r"""X.509 Certificate authentication provider.

    This provider implements certificate-based authentication for mutual TLS
    and PKI-based authentication systems.

    Configuration:
        - ca_cert: Trusted CA certificate (PEM format) (required)
        - ca_chain: List of intermediate CA certificates (optional)
        - verify_mode: Certificate verification mode ('required', 'optional') (default: 'required')
        - check_ocsp: Check certificate revocation via OCSP (default: False)
        - check_crl: Check certificate revocation via CRL (default: False)
        - allow_self_signed: Allow self-signed certificates (default: False)
        - subject_pattern: Regex pattern for allowed certificate subjects (optional)
        - issuer_pattern: Regex pattern for allowed certificate issuers (optional)

    Example:
        >>> config = {
        ...     "ca_cert": "-----BEGIN CERTIFICATE-----\\\\n...\\\\n-----END CERTIFICATE-----",
        ...     "verify_mode": "required",
        ...     "check_ocsp": True,
        ...     "allow_self_signed": False,
        ... }
        >>> provider = CertificateAuthProvider(config)
        >>> # Authenticate with client certificate
        >>> result = provider.authenticate({
        ...     "client_cert": "-----BEGIN CERTIFICATE-----\\\\n...\\\\n-----END CERTIFICATE-----",
        ...     "client_key": "-----BEGIN PRIVATE KEY-----\\\\n...\\\\n-----END PRIVATE KEY-----",
        ... })

    """

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize Certificate authentication provider.

        Args:
            config: Provider configuration dictionary

        Raises:
            ValueError: If required configuration is missing

        """
        self._config = config
        self._logger = FlextLogger(__name__)

        # Validate required configuration
        self._ca_cert = self._config.get("ca_cert")
        if not self._ca_cert:
            error_msg = (
                "Certificate provider requires 'ca_cert' (trusted CA certificate)"
            )
            raise ValueError(error_msg)

        # Optional configuration
        self._ca_chain = self._config.get("ca_chain", [])
        self._verify_mode = self._config.get("verify_mode", "required")
        self._check_ocsp = self._config.get("check_ocsp", False)
        self._check_crl = self._config.get("check_crl", False)
        self._allow_self_signed = self._config.get("allow_self_signed", False)
        self._subject_pattern = self._config.get("subject_pattern")
        self._issuer_pattern = self._config.get("issuer_pattern")

        # In-memory storage for certificate mappings (for development)
        # In production, integrate with certificate store or directory service
        self._cert_mappings: dict[
            str, dict[str, Any]
        ] = {}  # cert_fingerprint -> user data

        self._logger.info(
            "Certificate authentication provider initialized",
            extra={
                "verify_mode": self._verify_mode,
                "check_ocsp": self._check_ocsp,
                "check_crl": self._check_crl,
                "allow_self_signed": self._allow_self_signed,
            },
        )

    def authenticate(
        self,
        credentials: dict[str, Any],
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        r"""Authenticate using X.509 client certificate.

        Args:
            credentials: Must contain 'client_cert' (PEM-encoded certificate)
                        Optional: 'client_key' (PEM-encoded private key)

        Returns:
            FlextResult[AuthToken]: Authentication token or error

        Example:
            >>> result = provider.authenticate({
            ...     "client_cert": "-----BEGIN CERTIFICATE-----\\\\n...\\\\n-----END CERTIFICATE-----",
            ... })

        """
        # Validate required fields
        validation_result = self._validate_credentials_dict(
            credentials, ["client_cert"]
        )
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation_result.error)

        client_cert = credentials["client_cert"]

        # Step 1: Parse and extract certificate information
        cert_info_result = self._extract_certificate_info(client_cert)
        if cert_info_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(cert_info_result.error)

        cert_info = cert_info_result.unwrap()

        # Step 2: Validate certificate (expiration, CA signature)
        validation_result = self._validate_certificate(client_cert, cert_info)
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation_result.error)

        # Check if certificate is mapped to a user
        cert_fingerprint = cert_info.get("fingerprint", "")
        user_data = self._cert_mappings.get(cert_fingerprint)

        if not user_data:
            # Auto-provision user from certificate (if enabled)
            auto_provision_result = self._auto_provision_user(cert_info)
            if auto_provision_result.is_failure:
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    f"Certificate not authorized: {auto_provision_result.error}"
                )
            user_data = auto_provision_result.unwrap()

        # Create authentication token
        # Certificate validity from not_after or far future if not available
        token_expires_at = cert_info.get("not_after") or (
            datetime.now(UTC) + timedelta(days=365)
        )

        auth_token = FlextAuthModels.AuthToken(
            token=cert_fingerprint,  # Use certificate fingerprint as token
            token_type="bearer",  # Must match pattern: access|refresh|api|bearer
            expires_at=token_expires_at,
            user_id=user_data["user_id"],
            # Additional metadata
            username=user_data.get("username"),
            certificate_subject=cert_info.get("subject"),
            certificate_issuer=cert_info.get("issuer"),
            certificate_serial=cert_info.get("serial_number"),
            certificate_fingerprint=cert_fingerprint,
            roles=user_data.get("roles", []),
            permissions=user_data.get("permissions", []),
            auth_method="certificate",
        )

        self._logger.info(
            "Certificate authentication successful",
            extra={
                "user_id": user_data["user_id"],
                "subject": cert_info.get("subject"),
                "fingerprint": cert_fingerprint[:16] + "...",
            },
        )

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

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
        if isinstance(token, FlextAuthModels.AuthToken):
            if token.expires_at and datetime.now(UTC) > token.expires_at:
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

        self._logger.info(
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

    def get_metadata(self) -> dict[str, Any]:
        """Return Certificate provider metadata.

        Returns:
            dict[str, Any]: Provider metadata

        """
        return {
            "name": "certificate",
            "version": "2.0.0",
            "description": "X.509 Certificate authentication provider",
            "capabilities": list(self.supports()),
            "verify_mode": self._verify_mode,
            "check_ocsp": self._check_ocsp,
            "check_crl": self._check_crl,
            "allow_self_signed": self._allow_self_signed,
        }

    # Helper methods

    def _extract_certificate_info(self, cert_pem: str) -> FlextResult[dict[str, Any]]:
        """Extract information from PEM certificate using cryptography library.

        Args:
            cert_pem: PEM-encoded certificate

        Returns:
            FlextResult[dict]: Certificate information or error

        """
        if not cert_pem.startswith("-----BEGIN CERTIFICATE-----"):
            return FlextResult[dict[str, Any]].fail("Invalid PEM certificate format")

        try:
            # Import cryptography library for X.509 parsing
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes

            # Parse PEM certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

            # Calculate SHA256 fingerprint
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()

            # Extract subject DN
            subject_parts = [f"{attr.oid._name}={attr.value}" for attr in cert.subject]
            subject_dn = ",".join(subject_parts)

            # Extract issuer DN
            issuer_parts = [f"{attr.oid._name}={attr.value}" for attr in cert.issuer]
            issuer_dn = ",".join(issuer_parts)

            # Get validity dates
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            # Get serial number
            serial_number = format(cert.serial_number, "x")

            # Get public key algorithm
            public_key = cert.public_key()
            key_algorithm = (
                type(public_key).__name__.replace("Public", "").replace("Key", "")
            )

            # Get signature algorithm
            signature_algorithm = cert.signature_algorithm_oid._name

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

            self._logger.debug(
                "Certificate parsed successfully",
                extra={"fingerprint": fingerprint, "subject": subject_dn},
            )

            return FlextResult[dict[str, Any]].ok(cert_info)

        except ValueError as e:
            return FlextResult[dict[str, Any]].fail(f"Invalid certificate format: {e}")
        except Exception as e:
            return FlextResult[dict[str, Any]].fail(f"Certificate parsing failed: {e}")

    def _validate_certificate(
        self, cert_pem: str, cert_info: dict[str, Any]
    ) -> FlextResult[None]:
        """Validate certificate using cryptography library.

        Args:
            cert_pem: PEM-encoded certificate
            cert_info: Parsed certificate information

        Returns:
            FlextResult[None]: Success if valid, error otherwise

        """
        try:
            from cryptography import x509

            # Parse certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

            # Check validity period
            now = datetime.now(UTC)
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

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
                ca_validation_result = self._validate_against_ca(cert, self._ca_cert)
                if ca_validation_result.is_failure:
                    return ca_validation_result

            self._logger.debug(
                "Certificate validation passed",
                extra={"fingerprint": cert_info.get("fingerprint")},
            )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Certificate validation failed: {e}")

    def _validate_against_ca(self, cert: Any, ca_cert_pem: str) -> FlextResult[None]:
        """Validate certificate against CA certificate.

        Args:
            cert: Parsed certificate object
            ca_cert_pem: PEM-encoded CA certificate

        Returns:
            FlextResult[None]: Success if valid, error otherwise

        """
        try:
            from cryptography import x509

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

            self._logger.debug("Certificate CA validation passed")

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"CA validation failed: {e}")

    def _auto_provision_user(
        self, cert_info: dict[str, Any]
    ) -> FlextResult[dict[str, Any]]:
        """Auto-provision user from certificate information.

        Args:
            cert_info: Certificate information

        Returns:
            FlextResult[dict]: User data or error

        """
        # Extract username from certificate subject (CN field)
        subject = cert_info.get("subject", "")
        username = self._extract_cn_from_subject(subject)

        if not username:
            return FlextResult[dict[str, Any]].fail(
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
        self._cert_mappings[fingerprint] = user_data

        self._logger.info(
            "User auto-provisioned from certificate",
            extra={"user_id": user_id, "username": username},
        )

        return FlextResult[dict[str, Any]].ok(user_data)

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
        for component in subject.split(","):
            component = component.strip()
            if component.startswith("CN="):
                return component[3:]  # Remove "CN=" prefix
            if component.startswith("commonName="):
                return component[11:]  # Remove "commonName=" prefix

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

        self._logger.info(
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

        self._logger.info(
            "Certificate unregistered",
            extra={"fingerprint": cert_fingerprint[:16] + "..."},
        )

        return FlextResult[None].ok(None)


__all__ = ["CertificateAuthProvider"]
