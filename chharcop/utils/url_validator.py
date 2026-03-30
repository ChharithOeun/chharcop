"""URL validation and domain extraction utilities."""

import ipaddress
from urllib.parse import urlparse

from loguru import logger


def _is_private_host(hostname: str) -> bool:
    """Return True if hostname resolves to a private/loopback/link-local address.

    Blocks SSRF attempts targeting internal infrastructure.
    """
    if not hostname:
        return True
    # Strip IPv6 brackets
    hostname = hostname.strip("[]")
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        # Not a raw IP — domain names are fine at this stage
        return False


def validate_url(url: str) -> bool:
    """Validate if string is a valid URL or domain.

    Accepts both full URLs and domain names. Performs basic validation
    without external lookups. Rejects URLs that target private/internal
    IP addresses to prevent SSRF.

    Args:
        url: URL or domain string to validate

    Returns:
        True if valid URL/domain, False otherwise
    """
    try:
        if not url or not isinstance(url, str):
            return False

        url = url.strip()
        if not url:
            return False

        # Reject protocol-relative URLs (potential SSRF / confusion)
        if url.startswith("//"):
            return False

        # Add scheme if missing
        if not url.startswith(("http://", "https://", "ftp://")):
            url = f"https://{url}"

        parsed = urlparse(url)

        # Check for required components
        if not parsed.netloc:
            return False

        # Block private/loopback/internal IP addresses (SSRF prevention)
        hostname = parsed.hostname or ""
        if _is_private_host(hostname):
            logger.debug("Blocked private/internal host in URL: {}", hostname)
            return False

        # Check domain validity
        return is_valid_domain(parsed.netloc)

    except Exception as e:
        logger.debug(f"URL validation failed for {url}: {str(e)}")
        return False


def extract_domain(url: str) -> str | None:
    """Extract domain name from URL.

    Handles full URLs and returns just the domain portion.

    Args:
        url: Full URL or domain string

    Returns:
        Domain name or None if extraction fails
    """
    try:
        if not url or not isinstance(url, str):
            return None

        url = url.strip()

        # Normalise protocol-relative URLs
        if url.startswith("//"):
            url = f"https:{url}"

        # Add scheme if missing
        if not url.startswith(("http://", "https://", "ftp://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove port if present
        domain = domain.split(":")[0]

        # Remove www. prefix if present
        if domain.startswith("www."):
            domain = domain[4:]

        return domain if domain else None

    except Exception as e:
        logger.debug(f"Domain extraction failed for {url}: {str(e)}")
        return None


def is_valid_domain(domain: str) -> bool:
    """Validate domain name format.

    Checks if domain follows valid naming conventions.
    Cross-platform compatible.

    Args:
        domain: Domain name to validate

    Returns:
        True if domain format is valid, False otherwise
    """
    try:
        if not domain or not isinstance(domain, str):
            return False

        domain = domain.lower().strip()

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        # Length checks
        if len(domain) < 1 or len(domain) > 253:
            return False

        # Check for valid characters
        parts = domain.split(".")

        if len(parts) < 1:
            return False

        for part in parts:
            if not part:
                return False
            if len(part) > 63:
                return False
            # Allow alphanumeric and hyphens (but not starting/ending with hyphen)
            if part.startswith("-") or part.endswith("-"):
                return False
            if not all(c.isalnum() or c == "-" for c in part):
                return False

        # Must have at least one dot (except localhost)
        if domain != "localhost" and "." not in domain:
            return False

        return True

    except Exception as e:
        logger.debug(f"Domain validation failed for {domain}: {str(e)}")
        return False


def normalize_url(url: str) -> str:
    """Normalize URL to consistent format.

    Ensures URLs have proper scheme and standard formatting.
    Cross-platform compatible.

    Args:
        url: URL to normalize

    Returns:
        Normalized URL string
    """
    try:
        if not url or not isinstance(url, str):
            return ""

        url = url.strip()

        # Normalise protocol-relative URLs
        if url.startswith("//"):
            url = f"https:{url}"

        # Add scheme if missing
        if not url.startswith(("http://", "https://", "ftp://")):
            url = f"https://{url}"

        parsed = urlparse(url)

        # Rebuild URL with normalized components
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc.lower()
        path = parsed.path or ""
        params = parsed.params or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""

        # Reconstruct
        normalized = f"{scheme}://{netloc}{path}"
        if params:
            normalized += f";{params}"
        if query:
            normalized += f"?{query}"
        if fragment:
            normalized += f"#{fragment}"

        return normalized

    except Exception as e:
        logger.debug(f"URL normalization failed for {url}: {str(e)}")
        return ""
