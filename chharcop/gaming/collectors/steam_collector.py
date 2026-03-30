"""Steam gaming platform collector."""

import asyncio
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx
from loguru import logger

from chharcop.gaming.collectors.base import BaseGamingCollector
from chharcop.models import SteamProfile
from chharcop.utils.config import Config


class SteamCollector(BaseGamingCollector):
    """Collector for Steam gaming platform profiles and account data.

    Uses Steam Web API to gather player information, ban status, game library,
    and friends. Also checks SteamRep API for scammer/trader reputation flags.

    Requires STEAM_API_KEY environment variable.
    """

    STEAM_API_BASE = "https://api.steampowered.com"
    STEAMREP_API_BASE = "https://steamrep.com/api"

    # Known scam bot patterns
    SCAM_PATTERNS = [
        "steam.support",
        "steam-support",
        "valve.support",
        "csgo.admin",
        "admin-check",
        "account-verify",
        "confirm-inventory",
        "trade-confirm",
        "duplicate-account",
        "trading-bot",
        "dupe-check",
        "anti-cheat",
        "vac-check",
    ]

    def __init__(self) -> None:
        """Initialize the Steam collector."""
        super().__init__("SteamCollector")
        self.config = Config()
        self.api_key = self.config.steam_api_key

    @property
    def platform(self) -> str:
        """Get platform name."""
        return "steam"

    async def _collect(self, target: str) -> SteamProfile | None:
        """Collect Steam profile data.

        Args:
            target: Steam ID (64-bit) or vanity URL

        Returns:
            SteamProfile object with collected data
        """
        if not self.api_key:
            raise ValueError("STEAM_API_KEY environment variable not set")

        try:
            # Convert vanity URL to Steam ID if needed
            steam_id = await self._resolve_vanity_url(target)
            if not steam_id:
                steam_id = target

            logger.debug(f"Collecting Steam data for Steam ID: {steam_id}")

            # Gather all data concurrently
            async with httpx.AsyncClient(timeout=10.0) as client:
                summary_task = self._get_player_summary(client, steam_id)
                bans_task = self._get_player_bans(client, steam_id)
                games_task = self._get_owned_games(client, steam_id)
                friends_task = self._get_friend_list(client, steam_id)
                steamrep_task = self._get_steamrep_status(client, steam_id)

                summary = await summary_task
                bans = await bans_task
                games = await games_task
                friends = await friends_task
                steamrep = await steamrep_task

            if not summary:
                raise ValueError(f"Could not retrieve profile for {steam_id}")

            # Build profile object
            profile = SteamProfile(
                steam_id=steam_id,
                persona_name=summary.get("personaname", ""),
                profile_url=summary.get("profileurl", ""),
                avatar_url=summary.get("avatarfull"),
                account_created=(
                    datetime.fromtimestamp(summary["timecreated"])
                    if "timecreated" in summary
                    else None
                ),
                last_logoff=(
                    datetime.fromtimestamp(summary["lastlogoff"])
                    if "lastlogoff" in summary
                    else None
                ),
                visibility={
                    0: "private",
                    1: "friends_only",
                    2: "friends_of_friends",
                    3: "public",
                }.get(summary.get("communityvisibilitystate", 0), "unknown"),
                vac_banned=bool(bans.get("VACBanned", False)),
                vac_ban_count=bans.get("NumberOfVACBans", 0),
                days_since_last_ban=bans.get("DaysSinceLastBan") or None,
                trade_ban=bans.get("EconomyBan") == "probation",
                community_banned=bool(bans.get("CommunityBanned", False)),
                economy_ban=bans.get("EconomyBan"),
                steamrep_status=steamrep,
                game_count=len(games.get("games", [])),
                friend_count=len(friends),
                level=summary.get("lv", 0),
                primary_group=summary.get("primaryclanid"),
                custom_url=summary.get("customurl"),
            )

            logger.debug(f"Successfully collected Steam profile: {steam_id}")
            return profile

        except Exception as e:
            logger.error(f"Steam collection failed for {target}: {str(e)}")
            raise

    async def _resolve_vanity_url(
        self, vanity_or_id: str
    ) -> str | None:
        """Resolve vanity URL to Steam ID.

        Args:
            vanity_or_id: Vanity URL or Steam ID

        Returns:
            Steam ID or None if resolution fails
        """
        # If it looks like a Steam ID (numeric, 17 digits), return as-is
        if vanity_or_id.isdigit() and len(vanity_or_id) == 17:
            return vanity_or_id

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                url = (
                    f"{self.STEAM_API_BASE}/ISteamUser/ResolveVanityURL/v1/"
                    f"?key={self.api_key}&vanityurl={quote(vanity_or_id, safe='')}"
                )
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                if data.get("response", {}).get("success") == 1:
                    return str(data["response"]["steamid"])
        except Exception as e:
            logger.warning(f"Failed to resolve vanity URL {vanity_or_id}: {str(e)}")

        return None

    async def _get_player_summary(
        self, client: httpx.AsyncClient, steam_id: str
    ) -> dict[str, Any]:
        """Get player summary from Steam API.

        Args:
            client: HTTP client
            steam_id: Steam ID

        Returns:
            Player summary dict
        """
        try:
            url = (
                f"{self.STEAM_API_BASE}/ISteamUser/GetPlayerSummaries/v2/"
                f"?key={self.api_key}&steamids={quote(steam_id, safe='')}&format=json"
            )
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            players = data.get("response", {}).get("players", [])
            return players[0] if players else {}
        except Exception as e:
            logger.error(f"Failed to get player summary: {str(e)}")
            return {}

    async def _get_player_bans(
        self, client: httpx.AsyncClient, steam_id: str
    ) -> dict[str, Any]:
        """Get player ban status from Steam API.

        Args:
            client: HTTP client
            steam_id: Steam ID

        Returns:
            Ban status dict
        """
        try:
            url = (
                f"{self.STEAM_API_BASE}/ISteamUser/GetPlayerBans/v1/"
                f"?key={self.api_key}&steamids={quote(steam_id, safe='')}&format=json"
            )
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            players = data.get("players", [])
            return players[0] if players else {}
        except Exception as e:
            logger.error(f"Failed to get player bans: {str(e)}")
            return {}

    async def _get_owned_games(
        self, client: httpx.AsyncClient, steam_id: str
    ) -> dict[str, Any]:
        """Get player's owned games.

        Args:
            client: HTTP client
            steam_id: Steam ID

        Returns:
            Games dict with 'games' key
        """
        try:
            url = (
                f"{self.STEAM_API_BASE}/IPlayerService/GetOwnedGames/v1/"
                f"?key={self.api_key}&steamid={quote(steam_id, safe='')}&format=json"
            )
            response = await client.get(url)
            response.raise_for_status()
            return response.json().get("response", {})
        except Exception as e:
            logger.error(f"Failed to get owned games: {str(e)}")
            return {"games": []}

    async def _get_friend_list(
        self, client: httpx.AsyncClient, steam_id: str
    ) -> list[dict[str, Any]]:
        """Get player's friend list.

        Args:
            client: HTTP client
            steam_id: Steam ID

        Returns:
            List of friend dicts
        """
        try:
            url = (
                f"{self.STEAM_API_BASE}/ISteamUser/GetFriendList/v1/"
                f"?key={self.api_key}&steamid={quote(steam_id, safe='')}&relationship=friend"
            )
            response = await client.get(url)
            response.raise_for_status()
            return response.json().get("friendslist", {}).get("friends", [])
        except Exception as e:
            logger.error(f"Failed to get friend list: {str(e)}")
            return []

    async def _get_steamrep_status(
        self, client: httpx.AsyncClient, steam_id: str
    ) -> str:
        """Check SteamRep for scammer/trusted status.

        Args:
            client: HTTP client
            steam_id: Steam ID

        Returns:
            Status string: 'scammer', 'trusted', or 'unknown'
        """
        try:
            url = f"{self.STEAMREP_API_BASE}/ISteamRepAPI/GetUserBans/v1/?steamids={quote(steam_id, safe='')}&api=python"
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

            if not data or "steamrep" not in data:
                return "unknown"

            steamrep = data["steamrep"]
            flags = steamrep.get("flags", [])

            if "Banned" in flags:
                return "scammer"
            if "Trusted" in flags:
                return "trusted"

            return "unknown"
        except Exception as e:
            logger.debug(f"Failed to get SteamRep status: {str(e)}")
            return "unknown"
