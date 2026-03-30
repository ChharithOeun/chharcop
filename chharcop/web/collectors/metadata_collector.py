"""Website metadata and structure collector."""

import ipaddress
import re
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from loguru import logger

from chharcop.models import SiteMetadata
from chharcop.web.collectors.base import BaseCollector


class MetadataCollector(BaseCollector):
    """Collector for website metadata and structure information.

    Fetches website content, parses HTML, detects technologies, tracks redirects,
    and identifies trust signals (privacy policy, terms, contact info, etc.).
    """

    # Common technologies to detect
    TECHNOLOGY_PATTERNS = {
        "WordPress": r"wp-content|wp-includes|wordpress",
        "Drupal": r"drupal|sites/all/modules",
        "Joomla": r"joomla|index.php\?option=com_",
        "Magento": r"magento|mage/",
        "Shopify": r"cdn.shopify.com|myshopify.com",
        "Google Analytics": r"google-analytics|UA-\d+",
        "jQuery": r"jquery|\.ajax\(",
        "Bootstrap": r"bootstrap\.css|bootstrap\.js",
        "React": r"react|_react_|__REACT",
        "Vue.js": r"vue\.js|__vue__",
        "Angular": r"angular\.js|ng-app",
        "Node.js": r"node\.js",
        "Express": r"express\.js",
        "Python": r"python|django|flask",
        "PHP": r"\.php|x-powered-by: php",
        "ASP.NET": r"\.asp|x-powered-by: asp",
        "Cloudflare": r"cloudflare|cf_clearance",
    }

    def __init__(self) -> None:
        """Initialize the metadata collector."""
        super().__init__()
        self._name = "MetadataCollector"
        self.timeout = 10.0

    @staticmethod
    def _is_safe_url(url: str) -> bool:
        """Return False if the URL points to a private/loopback/internal address.

        Prevents SSRF via redirect chains leading to internal infrastructure.
        """
        try:
            hostname = urlparse(url).hostname or ""
            hostname = hostname.strip("[]")
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return False
        except ValueError:
            pass  # hostname is a domain name, not a raw IP — allow it
        return True

    async def _collect(self, target: str) -> SiteMetadata | None:
        """Collect website metadata.

        Args:
            target: URL to analyze

        Returns:
            SiteMetadata object with website information
        """
        try:
            logger.debug(f"Starting metadata collection for {target}")

            # Ensure URL has scheme
            if not target.startswith("http://") and not target.startswith("https://"):
                target = f"https://{target}"

            redirect_chain: list[str] = []
            final_url = target

            async with httpx.AsyncClient(
                follow_redirects=True,
                max_redirects=10,
                timeout=self.timeout,
            ) as client:
                try:
                    response = await client.get(target)

                    # Track redirect chain and block SSRF via redirect to private IPs
                    for history_response in response.history:
                        redirect_url = str(history_response.url)
                        if not self._is_safe_url(redirect_url):
                            logger.warning(
                                "Blocked redirect to private/internal address: {}",
                                redirect_url,
                            )
                            raise ValueError(
                                f"Redirect to internal address blocked: {redirect_url}"
                            )
                        redirect_chain.append(redirect_url)
                    final_url = str(response.url)
                    if not self._is_safe_url(final_url):
                        raise ValueError(
                            f"Final URL resolves to internal address: {final_url}"
                        )

                    # Extract metadata from content
                    soup = BeautifulSoup(response.text, "html.parser")

                    # Get title
                    title_tag = soup.find("title")
                    title = title_tag.string if title_tag else None

                    # Get meta description
                    meta_desc = soup.find("meta", attrs={"name": "description"})
                    description = (
                        meta_desc.get("content") if meta_desc else None
                    )

                    # Detect technologies
                    technologies = self._detect_technologies(response)

                    # Check for trust signals
                    has_privacy_policy = self._check_for_link(soup, "privacy")
                    has_terms_of_service = self._check_for_link(soup, "terms")
                    has_contact_page = self._check_for_link(soup, "contact")
                    has_about_page = self._check_for_link(soup, "about")

                    # Count external links
                    external_links = self._count_external_links(soup, final_url)

                    # Get server header
                    server_header = response.headers.get("server")

                    # Calculate response time
                    response_time_ms = (
                        response.elapsed.total_seconds() * 1000
                        if response.elapsed
                        else None
                    )

                    site_metadata = SiteMetadata(
                        url=final_url,
                        title=title,
                        description=description,
                        status_code=response.status_code,
                        redirect_chain=redirect_chain,
                        technologies=technologies,
                        has_privacy_policy=has_privacy_policy,
                        has_terms_of_service=has_terms_of_service,
                        has_contact_page=has_contact_page,
                        has_about_page=has_about_page,
                        external_links_count=external_links,
                        response_time_ms=response_time_ms,
                        server_header=server_header,
                    )

                    logger.debug(
                        f"Successfully collected metadata for {target}"
                    )
                    return site_metadata

                except httpx.RequestError as e:
                    logger.error(f"Request failed for {target}: {str(e)}")
                    raise

        except Exception as e:
            logger.error(f"Metadata collection failed for {target}: {str(e)}")
            raise

    def _detect_technologies(self, response: httpx.Response) -> list[str]:
        """Detect technologies used by website.

        Args:
            response: HTTP response object

        Returns:
            List of detected technologies
        """
        detected: list[str] = []

        # Combine response headers and body for detection
        detection_text = response.text + " ".join(
            f"{k}: {v}" for k, v in response.headers.items()
        )
        detection_text = detection_text.lower()

        for tech, pattern in self.TECHNOLOGY_PATTERNS.items():
            if re.search(pattern, detection_text, re.IGNORECASE):
                detected.append(tech)

        return detected

    @staticmethod
    def _check_for_link(soup: BeautifulSoup, keyword: str) -> bool:
        """Check if page has a link containing keyword.

        Args:
            soup: BeautifulSoup parsed page
            keyword: Keyword to search for in links

        Returns:
            True if link found, False otherwise
        """
        links = soup.find_all("a", href=True)
        for link in links:
            href = link.get("href", "").lower()
            text = link.get_text("").lower()
            if keyword in href or keyword in text:
                return True
        return False

    @staticmethod
    def _count_external_links(soup: BeautifulSoup, page_url: str) -> int:
        """Count external links on page.

        Args:
            soup: BeautifulSoup parsed page
            page_url: Current page URL for domain comparison

        Returns:
            Count of external links
        """
        # Extract domain from page URL
        from urllib.parse import urlparse
        page_domain = urlparse(page_url).netloc.lower()

        external_count = 0
        links = soup.find_all("a", href=True)

        for link in links:
            href = link.get("href", "").lower()

            # Skip anchors and empty links
            if not href or href.startswith("#"):
                continue

            # Skip mailto and other non-http protocols
            if href.startswith(("mailto:", "tel:", "javascript:", "ftp://")):
                continue

            # Parse link domain
            if href.startswith("http"):
                link_domain = urlparse(href).netloc.lower()
                if link_domain != page_domain:
                    external_count += 1
            elif href.startswith("/") or href.startswith("?"):
                # Internal link
                continue
            else:
                # Relative link, likely internal
                continue

        return external_count
