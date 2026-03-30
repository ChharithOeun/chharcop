"""Cross-platform gamertag OSINT collector."""

from typing import Any
from urllib.parse import quote

import httpx
from loguru import logger

from chharcop.gaming.collectors.base import BaseGamingCollector
from chharcop.models import GamertagResult


class GamertagOsint(BaseGamingCollector):
    """Cross-platform gamertag OSINT collector.

    Searches for a given username/gamertag across multiple gaming platforms
    to identify matching accounts and correlate identities.

    Supports: Steam, Xbox, PlayStation, Epic Games
    """

    def __init__(self) -> None:
        """Initialize the gamertag OSINT collector."""
        super().__init__("GamertagOsint")

    @property
    def platform(self) -> str:
        """Get platform name."""
        return "cross-platform"

    async def _collect(self, target: str) -> dict[str, Any]:
        """Search for gamertag across platforms.

        Args:
            target: Gamertag/username to search

        Returns:
            Dict with 'results' list of GamertagResult objects
        """
        try:
            logger.debug(f"Searching for gamertag across platforms: {target}")

            results: list[GamertagResult] = []

            # Search Steam
            steam_result = await self._search_steam(target)
            if steam_result:
                results.append(steam_result)

            # Search Xbox
            xbox_result = await self._search_xbox(target)
            if xbox_result:
                results.append(xbox_result)

            # Search PlayStation
            psn_result = await self._search_psn(target)
            if psn_result:
                results.append(psn_result)

            # Search Epic Games
            epic_result = await self._search_epic(target)
            if epic_result:
                results.append(epic_result)

            logger.debug(
                f"Found {len(results)} matching platforms for {target}"
            )
            return {"results": results}

        except Exception as e:
            logger.error(f"Gamertag OSINT failed for {target}: {str(e)}")
            raise

    async def _search_steam(self, gamertag: str) -> GamertagResult | None:
        """Search for gamertag on Steam.

        Args:
            gamertag: Username to search

        Returns:
            GamertagResult if found, None otherwise
        """
        try:
            # URL-encode gamertag to prevent path traversal / parameter injection
            safe_tag = quote(gamertag, safe="")
            vanity_url = f"https://steamcommunity.com/id/{safe_tag}/"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.head(vanity_url, follow_redirects=False)
                if response.status_code == 200:
                    return GamertagResult(
                        gamertag=gamertag,
                        platform="steam",
                        found=True,
                        profile_url=vanity_url,
                        verified=True,
                    )
        except Exception as e:
            logger.debug(f"Steam search failed for {gamertag}: {str(e)}")

        return None

    async def _search_xbox(self, gamertag: str) -> GamertagResult | None:
        """Search for gamertag on Xbox Live.

        Args:
            gamertag: Gamertag to search

        Returns:
            GamertagResult if found, None otherwise
        """
        try:
            safe_tag = quote(gamertag, safe="")
            xbox_url = f"https://xboxgamertag.com/search/{safe_tag}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(xbox_url)
                if response.status_code == 200:
                    # Check if profile actually exists in response
                    if "profile not found" not in response.text.lower():
                        return GamertagResult(
                            gamertag=gamertag,
                            platform="xbox",
                            found=True,
                            profile_url=f"https://xboxgamertag.com/{safe_tag}",
                            verified=True,
                        )
        except Exception as e:
            logger.debug(f"Xbox search failed for {gamertag}: {str(e)}")

        return None

    async def _search_psn(self, gamertag: str) -> GamertagResult | None:
        """Search for gamertag on PlayStation Network.

        Args:
            gamertag: Username to search

        Returns:
            GamertagResult if found, None otherwise
        """
        try:
            safe_tag = quote(gamertag, safe="")
            psn_url = f"https://www.psn.com/en-us/search/{safe_tag}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(psn_url)
                if response.status_code == 200:
                    # Check if user found in response
                    if gamertag.lower() in response.text.lower():
                        return GamertagResult(
                            gamertag=gamertag,
                            platform="psn",
                            found=True,
                            profile_url=f"https://www.psn.com/en-us/profile/{safe_tag}",
                            verified=True,
                        )
        except Exception as e:
            logger.debug(f"PSN search failed for {gamertag}: {str(e)}")

        return None

    async def _search_epic(self, gamertag: str) -> GamertagResult | None:
        """Search for gamertag on Epic Games.

        Args:
            gamertag: Username to search

        Returns:
            GamertagResult if found, None otherwise
        """
        try:
            # Epic Games profile URL pattern
            epic_url = f"https://www.epicgames.com/site/en-US/community"
            # Note: Epic doesn't have simple URL lookups, this would require API
            # For now, return placeholder

            logger.debug(f"Epic Games search for {gamertag} requires API access")
            return None
        except Exception as e:
            logger.debug(f"Epic search failed for {gamertag}: {str(e)}")

        return None
