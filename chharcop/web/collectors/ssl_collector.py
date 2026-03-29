"""SSL/TLS certificate collector."""

import socket
from datetime import datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID
from loguru import logger

from chharcop.models import SslData
from chharcop.web.collectors.base import BaseCollector


class SslCollector(BaseCollector):
    """Collector for SSL/TLS certificate information.

    Estableves SSL connection to target and extracts certificate details,
    validates expiration, and classifies certificate type (DV/OV/EV).
    """

    def __init__(self) -> None:
        """Initialize the SSL collector."""
        super().__init__()
        self._name = "SslCollector"

    async def _collect(self, target: str) -> SslData | None:
        """Collect SSL certificate data for domain.

        Args:
            target: Domain to connect to and retrieve certificate

        Returns:
            SslData object with certificate details
        """
        try:
            logger.debug(f"Fetching SSL certificate for {target}")

            # Extract hostname from target (could be full URL)
            hostname = self._extract_hostname(target)
            port = 443

            # Fetch certificate
            cert_pem = self._fetch_certificate(hostname, port)
            if not cert_pem:
                raise ValueError("Failed to retrieve certificate")

            # Parse certificate
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            # Extract subject and issuer
            subject = self._extract_name_dict(cert.subject)
            issuer = self._extract_name_dict(cert.issuer)

            # Check if self-signed
            is_self_signed = subject == issuer

            # Determine certificate type
            cert_type = self._determine_cert_type(cert)

            # Check validity
            now = datetime.utcnow()
            is_valid = cert.not_valid_before <= now <= cert.not_valid_after
            days_until_expiry = (cert.not_valid_after - now).days if is_valid else None

            ssl_data = SslData(
                domain=target,
                subject=subject,
                issuer=issuer,
                not_valid_before=cert.not_valid_before,
                not_valid_after=cert.not_valid_after,
                serial_number=str(cert.serial_number),
                version=cert.version.value,
                signature_algorithm=cert.signature_algorithm_oid._name,
                is_self_signed=is_self_signed,
                cert_type=cert_type,
                is_valid=is_valid,
                days_until_expiry=days_until_expiry,
                certificate_pem=cert_pem.decode() if isinstance(cert_pem, bytes) else cert_pem,
            )

            logger.debug(f"Successfully collected SSL data for {target}")
            return ssl_data

        except Exception as e:
            logger.error(f"SSL collection failed for {target}: {str(e)}")
            raise

    @staticmethod
    def _extract_hostname(target: str) -> str:
        """Extract hostname from target string.

        Args:
            target: Domain name or full URL

        Returns:
            Hostname for certificate retrieval
        """
        if target.startswith("http://") or target.startswith("https://"):
            target = target.split("://")[1]
        return target.split("/")[0].split(":")[0]

    @staticmethod
    def _fetch_certificate(hostname: str, port: int) -> bytes | None:
        """Fetch SSL certificate from server.

        Args:
            hostname: Hostname to connect to
            port: Port number (typically 443)

        Returns:
            PEM-encoded certificate bytes or None
        """
        try:
            context = ssl._create_unverified_context()  # type: ignore[name-defined]
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        from cryptography.hazmat.primitives import serialization
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        return cert.public_bytes(serialization.Encoding.PEM)
        except Exception as e:
            logger.warning(f"Failed to fetch certificate from {hostname}: {str(e)}")
            return None

    @staticmethod
    def _extract_name_dict(name: x509.Name) -> dict[str, str]:
        """Extract name components as dictionary.

        Args:
            name: X509Name object

        Returns:
            Dictionary mapping attribute names to values
        """
        result: dict[str, str] = {}
        for attr in name:
            oid = attr.oid
            value = attr.value
            # Map OID to readable name
            if oid == NameOID.COMMON_NAME:
                result["CN"] = value
            elif oid == NameOID.ORGANIZATION_NAME:
                result["O"] = value
            elif oid == NameOID.COUNTRY_NAME:
                result["C"] = value
            elif oid == NameOID.STATE_OR_PROVINCE_NAME:
                result["ST"] = value
            elif oid == NameOID.LOCALITY_NAME:
                result["L"] = value
            elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                result["OU"] = value
            else:
                result[oid._name] = value
        return result

    @staticmethod
    def _determine_cert_type(cert: x509.Certificate) -> str:
        """Determine certificate type (DV, OV, EV).

        Args:
            cert: X509 certificate object

        Returns:
            Certificate type classification
        """
        try:
            # Check for EV indicators (Organization validation present)
            subject = SslCollector._extract_name_dict(cert.subject)
            if subject.get("O") and subject.get("C"):
                # Has organization name, likely OV or EV
                try:
                    # Check for EV policy extension
                    cert.extensions.get_extension_for_oid(
                        ExtensionOID.CERTIFICATE_POLICIES
                    )
                    return "EV"
                except x509.ExtensionNotFound:
                    return "OV"
            return "DV"
        except Exception as e:
            logger.warning(f"Error determining cert type: {str(e)}")
            return "unknown"


# Import ssl module for context creation
import ssl
