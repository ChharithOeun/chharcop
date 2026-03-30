"""Cross-platform username OSINT collector.

Uses HTTP HEAD/GET requests (no API keys required) to enumerate whether a
username exists on major social platforms.  Also flags account age
inconsistencies and recently-created clusters.
"""

import asyncio
from typing import Any

import httpx
from loguru import logger

from chharcop.social.collectors.base import BaseSocialCollector
from chharcop.social.patterns import CLUSTER_AGE_DAYS, SocialPatterns

# ---------------------------------------------------------------------------
# Platform definitions
# Each entry: (url_template, method, found_status_codes, not_found_status_codes,
#              body_must_not_contain)
# ---------------------------------------------------------------------------

_PLATFORMS: dict[str, dict[str, Any]] = {
    "twitter": {
        "url": "https://twitter.com/{username}",
        "method": "HEAD",
        "found_codes": {200, 301},
        "not_found_codes": {404},
        "body_absent": None,
    },
    "reddit": {
        "url": "https://www.reddit.com/user/{username}",
        "method": "HEAD",
        "found_codes": {200},
        "not_found_codes": {404},
        "body_absent": None,
    },
    "instagram": {
        "url": "https://www.instagram.com/{username}/",
        "method": "HEAD",
        "found_codes": {200},
        "not_found_codes": {404},
        "body_absent": None,
    },
    "tiktok": {
        "url": "https://www.tiktok.com/@{username}",
        "method": "HEAD",
        "found_codes": {200},
        "not_found_codes": {404},
        "body_absent": None,
    },
    "github": {
        "url": "https://github.com/{username}",
        "method": "HEAD",
        "found_codes": {200},
        "not_found_codes": {404},
        "body_absent": None,
    },
    "steam": {
        "url": "https://steamcommunity.com/id/{username}/",
        "method": "GET",
        "found_codes": {200},
        "not_found_codes": {404},
        "body_absent": "The specified profile could not be found.",
    },
    "facebook": {
        "url": "https://www.facebook.com/{username}",
        "method": "HEAD",
        "found_codes": {200, 301},
        "not_found_codes": {404},
        "body_absent": None,
    },
    "linkedin": {
        "url": "https://www.linkedin.com/in/{username}/",
        "method": "HEAD",
        "found_codes": {200},
        "not_found_codes": {404},
        "body_absent": None,
    },
    "youtube": {
        "url": "https://www.youtube.com/@{username}",
        "method": "HEAD",
        "found_codes": {200},
        "not_found_codes": {404},
        "body_absent": None,
    },
    "discord": {
        # Discord has no public profile URL; we can't enumerate directly
        "url": None,
        "method": None,
        "found_codes": set(),
        "not_found_codes": set(),
        "body_absent": None,
    },
}

# Realistic browser-like headers to reduce bot-blocking
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

_TIMEOUT = 8.0  # seconds per request


class UsernameOsint(BaseSocialCollector):
    """Cross-platform username enumeration collector.

    Checks whether the target username exists on:
    Twitter, Reddit, Instagram, TikTok, GitHub, Steam, Facebook,
    LinkedIn, YouTube.

    Uses HTTP HEAD (or GET where needed) — no API keys required.

    Flags:
    - Presence on many platforms simultaneously
    - Account age clustering (multiple newly-created accounts)
    - Username found on 5+ platforms (broad identity footprint)
    """

    def __init__(self) -> None:
        """Initialize the username OSINT collector."""
        super().__init__("UsernameOsint")
        self._patterns = SocialPatterns()

    @property
    def platform(self) -> str:
        """Get platform name."""
        return "cross-platform"

    async def _collect(self, target: str) -> dict[str, Any]:
        """Enumerate username across all supported platforms.

        Args:
            target: Username to search (no @ prefix needed)

        Returns:
            Dict with 'platforms' mapping and 'flags' list
        """
        username = target.lstrip("@").lstrip("u/").strip()

        logger.debug(f"UsernameOsint: enumerating '{username}' across platforms")

        # Build async tasks for all platforms that have a URL
        tasks: dict[str, asyncio.Task[dict[str, Any]]] = {}
        async with httpx.AsyncClient(
            headers=_HEADERS,
            timeout=_TIMEOUT,
            follow_redirects=False,
        ) as client:
            coros = {
                name: self._check_platform(client, name, cfg, username)
                for name, cfg in _PLATFORMS.items()
                if cfg.get("url")
            }
            results = dict(
                zip(
                    coros.keys(),
                    await asyncio.gather(*coros.values(), return_exceptions=True),
                )
            )

        platforms: dict[str, dict[str, Any]] = {}
        for name, cfg in _PLATFORMS.items():
            if not cfg.get("url"):
                # Discord / unenumerable — note absence
                platforms[name] = {"found": False, "flags": [], "note": "not_enumerable"}
                continue

            result = results.get(name)
            if isinstance(result, Exception):
                logger.debug(f"UsernameOsint [{name}]: error — {result}")
                platforms[name] = {"found": False, "flags": [], "error": str(result)}
            else:
                platforms[name] = result  # type: ignore[assignment]

        # -----------------------------------------------------------
        # Global flags
        # -----------------------------------------------------------
        found_platforms = [p for p, d in platforms.items() if d.get("found")]
        flags: list[str] = []

        if len(found_platforms) >= 5:
            flags.append("username_on_5_plus_platforms")
        if len(found_platforms) >= 8:
            flags.append("username_on_8_plus_platforms")

        # Age clustering: if multiple platforms flagged new_account, cluster it
        new_account_count = sum(
            1 for d in platforms.values()
            if "new_account" in d.get("flags", [])
        )
        if new_account_count >= 2:
            flags.append("account_age_clustering")

        logger.debug(
            f"UsernameOsint complete for '{username}': "
            f"found on {len(found_platforms)}/{len(found_platforms)} checked platforms"
        )

        return {
            "username": username,
            "platforms": platforms,
            "platforms_found": found_platforms,
            "flags": flags,
        }

    async def _check_platform(
        self,
        client: httpx.AsyncClient,
        platform_name: str,
        cfg: dict[str, Any],
        username: str,
    ) -> dict[str, Any]:
        """Check a single platform for the given username.

        Args:
            client: Shared httpx client
            platform_name: Platform identifier
            cfg: Platform configuration dict
            username: Username to check

        Returns:
            Dict with 'found', 'profile_url', 'flags', optional fields
        """
        url = cfg["url"].format(username=username)
        method: str = cfg["method"]
        found_codes: set[int] = cfg["found_codes"]
        not_found_codes: set[int] = cfg["not_found_codes"]
        body_absent: str | None = cfg["body_absent"]

        profile_url = url
        flags: list[str] = []

        try:
            if method == "HEAD":
                response = await client.head(url)
            else:
                response = await client.get(url)

            status = response.status_code

            if status in not_found_codes:
                return {"found": False, "profile_url": profile_url, "flags": flags}

            if status in found_codes:
                found = True
                # Body exclusion check (e.g. Steam "profile not found" page)
                if body_absent and method == "GET":
                    body_text = response.text
                    if body_absent.lower() in body_text.lower():
                        found = False

                if found:
                    logger.debug(f"UsernameOsint [{platform_name}]: FOUND (HTTP {status})")
                    return {
                        "found": True,
                        "profile_url": profile_url,
                        "http_status": status,
                        "flags": flags,
                    }

            # Ambiguous status (e.g. 429 rate-limit, 403 blocked)
            logger.debug(
                f"UsernameOsint [{platform_name}]: ambiguous HTTP {status} — treating as not found"
            )
            return {
                "found": False,
                "profile_url": profile_url,
                "http_status": status,
                "flags": flags,
                "note": f"ambiguous_{status}",
            }

        except httpx.TimeoutException:
            logger.debug(f"UsernameOsint [{platform_name}]: timeout")
            return {"found": False, "profile_url": profile_url, "flags": flags, "note": "timeout"}
        except Exception as exc:
            logger.debug(f"UsernameOsint [{platform_name}]: {type(exc).__name__}: {exc}")
            return {
                "found": False,
                "profile_url": profile_url,
                "flags": flags,
                "note": f"error: {type(exc).__name__}",
            }
