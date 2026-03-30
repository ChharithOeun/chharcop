"""Core orchestrator for Chharcop scanning and evidence collection."""

import asyncio
import uuid
from datetime import datetime
from typing import Any

from loguru import logger

from chharcop.gaming.collectors import (
    BaseGamingCollector,
    DiscordCollector,
    GamertagOsint,
    SteamCollector,
)
from chharcop.models import (
    GamingScanResult,
    ScanResult,
    SocialScanResult,
    WebScanResult,
)
from chharcop.social.scanner import SocialScanner
from chharcop.utils.config import Config
from chharcop.utils.url_validator import extract_domain, validate_url
from chharcop.web.collectors import (
    BaseCollector,
    DnsCollector,
    MetadataCollector,
    SslCollector,
    WhoisCollector,
)


class Chharcop:
    """Main orchestrator class for evidence collection and scanning.

    Provides high-level methods to scan websites, gaming profiles, and
    cross-platform gamertags. Handles concurrent collection and risk assessment.
    """

    def __init__(self, config: Config | None = None) -> None:
        """Initialize Chharcop orchestrator.

        Args:
            config: Optional Config object (creates default if not provided)
        """
        self.config = config or Config()
        self.web_collectors: list[BaseCollector] = [
            WhoisCollector(),
            DnsCollector(),
            SslCollector(),
            MetadataCollector(),
        ]
        self.gaming_collectors: dict[str, BaseGamingCollector] = {
            "steam": SteamCollector(),
            "discord": DiscordCollector(),
        }
        self.social_scanner = SocialScanner()
        logger.info("Chharcop initialized")

    async def scan_website(self, url: str) -> ScanResult:
        """Scan a website for evidence and indicators.

        Runs all web collectors concurrently (WHOIS, DNS, SSL, Metadata).
        Calculates risk score based on findings.

        Args:
            url: URL or domain to scan

        Returns:
            ScanResult with all collected web evidence

        Raises:
            ValueError: If URL is invalid
        """
        if not validate_url(url):
            raise ValueError(f"Invalid URL: {url}")

        scan_id = str(uuid.uuid4())
        domain = extract_domain(url) or url

        logger.info(f"Starting website scan: {url} (ID: {scan_id})")

        try:
            # Run all collectors concurrently
            results = await asyncio.gather(
                *[collector.collect(domain) for collector in self.web_collectors],
                return_exceptions=True,
            )

            # Process results
            web_result = WebScanResult(url=url)
            errors = []

            for i, result in enumerate(results):
                collector = self.web_collectors[i]

                if isinstance(result, Exception):
                    logger.error(f"Collector {collector.name} failed: {str(result)}")
                    continue

                error = result.get("error")
                if error:
                    errors.append(error)
                    logger.warning(f"Collector {collector.name} returned error")
                    continue

                data = result.get("data")
                if not data:
                    continue

                # Assign data to appropriate field
                if collector.name == "WhoisCollector":
                    web_result.whois_data = data
                elif collector.name == "DnsCollector":
                    web_result.dns_data = data
                elif collector.name == "SslCollector":
                    web_result.ssl_data = data
                elif collector.name == "MetadataCollector":
                    web_result.metadata = data

            web_result.errors = errors

            # Build scan result
            scan_result = ScanResult(
                scan_id=scan_id,
                target=url,
                scan_type="website",
                web_results=web_result,
            )

            scan_result.calculate_risk_score()
            logger.info(
                f"Website scan completed: {url} "
                f"(Risk: {scan_result.risk_level}, Score: {scan_result.risk_score})"
            )

            return scan_result

        except Exception as e:
            logger.error(f"Website scan failed for {url}: {str(e)}")
            raise

    async def scan_steam(self, steam_id: str) -> ScanResult:
        """Scan a Steam gaming profile.

        Collects Steam profile data including VAC bans, game library,
        and SteamRep reputation status.

        Args:
            steam_id: Steam ID (64-bit) or vanity URL

        Returns:
            ScanResult with Steam gaming evidence

        Raises:
            ValueError: If Steam API key not configured
        """
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting Steam scan: {steam_id} (ID: {scan_id})")

        try:
            collector = self.gaming_collectors["steam"]
            result = await collector.collect(steam_id)

            gaming_result = GamingScanResult(
                target_identifier=steam_id,
                platform="steam",
            )

            error = result.get("error")
            if error:
                gaming_result.errors.append(error)
                logger.warning("Steam collector returned error")
            else:
                data = result.get("data")
                if data:
                    gaming_result.steam_profile = data

            scan_result = ScanResult(
                scan_id=scan_id,
                target=steam_id,
                scan_type="steam",
                gaming_results=gaming_result,
            )

            scan_result.calculate_risk_score()
            logger.info(
                f"Steam scan completed: {steam_id} "
                f"(Risk: {scan_result.risk_level}, Score: {scan_result.risk_score})"
            )

            return scan_result

        except Exception as e:
            logger.error(f"Steam scan failed for {steam_id}: {str(e)}")
            raise

    async def scan_discord(self, user_id: str) -> ScanResult:
        """Scan a Discord user account.

        Collects Discord user data including account age and scam patterns.

        Args:
            user_id: Discord user ID

        Returns:
            ScanResult with Discord user evidence

        Raises:
            ValueError: If Discord bot token not configured
        """
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting Discord scan: {user_id} (ID: {scan_id})")

        try:
            collector = self.gaming_collectors["discord"]
            result = await collector.collect(user_id)

            gaming_result = GamingScanResult(
                target_identifier=user_id,
                platform="discord",
            )

            error = result.get("error")
            if error:
                gaming_result.errors.append(error)
                logger.warning("Discord collector returned error")
            else:
                data = result.get("data")
                if data:
                    gaming_result.discord_user = data

            scan_result = ScanResult(
                scan_id=scan_id,
                target=user_id,
                scan_type="discord",
                gaming_results=gaming_result,
            )

            scan_result.calculate_risk_score()
            logger.info(
                f"Discord scan completed: {user_id} "
                f"(Risk: {scan_result.risk_level}, Score: {scan_result.risk_score})"
            )

            return scan_result

        except Exception as e:
            logger.error(f"Discord scan failed for {user_id}: {str(e)}")
            raise

    async def scan_gamertag(self, username: str) -> ScanResult:
        """Scan gamertag across multiple platforms.

        Searches for username across gaming platforms to identify and
        correlate matching accounts.

        Args:
            username: Gamertag/username to search

        Returns:
            ScanResult with cross-platform matches
        """
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting gamertag OSINT: {username} (ID: {scan_id})")

        try:
            osint = GamertagOsint()
            result = await osint.collect(username)

            gaming_result = GamingScanResult(
                target_identifier=username,
                platform="cross-platform",
            )

            error = result.get("error")
            if error:
                gaming_result.errors.append(error)
                logger.warning("Gamertag OSINT returned error")
            else:
                data = result.get("data")
                if data and "results" in data:
                    gaming_result.cross_platform_matches = data["results"]

            scan_result = ScanResult(
                scan_id=scan_id,
                target=username,
                scan_type="gamertag",
                gaming_results=gaming_result,
            )

            scan_result.calculate_risk_score()
            logger.info(f"Gamertag OSINT completed: {username} ({len(gaming_result.cross_platform_matches)} matches)")

            return scan_result

        except Exception as e:
            logger.error(f"Gamertag scan failed for {username}: {str(e)}")
            raise

    async def scan_social(self, username: str) -> ScanResult:
        """Scan a username across social media platforms.

        Runs Twitter, Reddit, and cross-platform username OSINT collectors
        concurrently.  Calculates Social Behavior Score (0-100).

        Args:
            username: Username / handle to investigate (without @ or u/)

        Returns:
            ScanResult with social_results populated
        """
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting social scan: {username} (ID: {scan_id})")

        try:
            social_result: SocialScanResult = await self.social_scanner.scan(username)

            scan_result = ScanResult(
                scan_id=scan_id,
                target=username,
                scan_type="social",
                social_results=social_result,
            )

            scan_result.calculate_risk_score()
            logger.info(
                f"Social scan completed: {username} "
                f"(Risk: {scan_result.risk_level}, Score: {scan_result.risk_score})"
            )

            return scan_result

        except Exception as e:
            logger.error(f"Social scan failed for {username}: {str(e)}")
            raise

    async def full_scan(self, target: str) -> ScanResult | list[ScanResult]:
        """Auto-detect target type and run appropriate scan.

        Determines whether target is a URL, Steam ID, Discord ID, or username
        and runs the appropriate scanner(s).

        Args:
            target: Target to scan (URL, Steam ID, Discord ID, username)

        Returns:
            ScanResult or list of ScanResults depending on target type
        """
        logger.info(f"Starting full scan: {target}")

        # Try to detect target type
        if validate_url(target):
            # It's a website
            return await self.scan_website(target)

        elif target.isdigit():
            if len(target) == 17:
                # Likely a Steam ID
                return await self.scan_steam(target)
            else:
                # Might be Discord ID
                return await self.scan_discord(target)

        else:
            # Treat as username/vanity URL - try multiple scans
            results: list[ScanResult] = []

            # Try as Steam vanity URL
            try:
                steam_result = await self.scan_steam(target)
                results.append(steam_result)
            except Exception as e:
                logger.debug(f"Not a Steam profile: {str(e)}")

            # Try as gamertag OSINT
            try:
                gamertag_result = await self.scan_gamertag(target)
                results.append(gamertag_result)
            except Exception as e:
                logger.debug(f"Gamertag OSINT failed: {str(e)}")

            if results:
                return results if len(results) > 1 else results[0]

            raise ValueError(f"Could not determine target type: {target}")
