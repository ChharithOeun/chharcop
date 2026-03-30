"""Social media behavior scanner — main orchestrator."""

import asyncio
from typing import Any

from loguru import logger

from chharcop.models import CollectorError, SocialScanResult
from chharcop.social.collectors.base import BaseSocialCollector
from chharcop.social.collectors.reddit_collector import RedditCollector
from chharcop.social.collectors.twitter_collector import TwitterCollector
from chharcop.social.collectors.username_osint import UsernameOsint
from chharcop.social.patterns import SocialPatterns


class SocialScanner:
    """Orchestrates social media evidence collection for a given username.

    Runs TwitterCollector, RedditCollector, and UsernameOsint in parallel,
    aggregates findings into a SocialScanResult, and calculates a 0-100
    Social Behavior Score on the same scale as the web risk algorithm.
    """

    def __init__(self) -> None:
        """Initialize the social scanner with all collectors."""
        self.collectors: list[BaseSocialCollector] = [
            TwitterCollector(),
            RedditCollector(),
            UsernameOsint(),
        ]
        self._patterns = SocialPatterns()

    async def scan(self, username: str) -> SocialScanResult:
        """Scan a username across all social platforms.

        Runs all collectors concurrently via asyncio.gather().

        Args:
            username: Username / handle to investigate

        Returns:
            SocialScanResult with per-platform findings and risk score
        """
        logger.info(f"SocialScanner: starting scan for '{username}'")

        raw_results = await asyncio.gather(
            *[collector.collect(username) for collector in self.collectors],
            return_exceptions=True,
        )

        profiles: list[dict[str, Any]] = []
        errors: list[CollectorError] = []

        for i, raw in enumerate(raw_results):
            collector = self.collectors[i]

            if isinstance(raw, Exception):
                logger.error(f"SocialScanner: {collector.name} raised {raw}")
                errors.append(
                    CollectorError(
                        collector=collector.name,
                        error_type=type(raw).__name__,
                        error_message=str(raw),
                    )
                )
                continue

            error = raw.get("error")
            if error:
                errors.append(error)
                logger.warning(f"SocialScanner: {collector.name} returned error")
                continue

            data: dict[str, Any] | None = raw.get("data")
            if not data:
                continue

            # UsernameOsint returns a dict keyed by platform presence
            if collector.name == "UsernameOsint":
                for platform, presence in data.get("platforms", {}).items():
                    if presence.get("found"):
                        profiles.append(
                            {
                                "platform": platform,
                                "username": data.get("username", username),
                                "found": True,
                                "account_age_days": None,
                                "flags": presence.get("flags", []),
                                "raw_data": presence,
                            }
                        )
                # Propagate top-level OSINT flags
                for flag in data.get("flags", []):
                    # Inject as a synthetic profile entry so risk scoring sees them
                    profiles.append(
                        {
                            "platform": "cross_platform",
                            "username": username,
                            "found": True,
                            "account_age_days": None,
                            "flags": [flag],
                            "raw_data": {},
                        }
                    )
            else:
                profiles.append(
                    {
                        "platform": data.get("platform", collector.platform),
                        "username": data.get("username", username),
                        "found": True,
                        "account_age_days": data.get("account_age_days"),
                        "flags": data.get("flags", []),
                        "raw_data": data,
                    }
                )

        # Platforms where the account was actually found (Twitter/Reddit collectors)
        platforms_found = [
            p["platform"]
            for p in profiles
            if p.get("found") and p["platform"] != "cross_platform"
        ]

        result = SocialScanResult(
            username=username,
            platforms_found=list(dict.fromkeys(platforms_found)),  # dedup, preserve order
            profiles=profiles,
            errors=errors,
        )

        result.calculate_risk_score()

        logger.info(
            f"SocialScanner: scan complete for '{username}' — "
            f"Risk: {result.risk_level} ({result.risk_score:.0f}/100), "
            f"platforms found: {result.platforms_found}"
        )

        return result
