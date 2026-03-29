"""Discord platform collector."""

from datetime import datetime
from typing import Any

import httpx
from loguru import logger

from chharcop.gaming.collectors.base import BaseGamingCollector
from chharcop.models import DiscordUser
from chharcop.utils.config import Config


class DiscordCollector(BaseGamingCollector):
    """Collector for Discord user accounts and account analysis.

    Uses Discord API to gather user information, checks account age,
    detects known scam patterns, and correlates with suspicious behaviors.

    Requires DISCORD_BOT_TOKEN environment variable.
    """

    DISCORD_API_BASE = "https://discord.com/api/v10"

    # Known scam bot/account patterns
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
        "nitro.gift",
        "gift-card",
        "verify-account",
        "discord-verify",
        "bot-check",
        "bot-verify",
        "anti-cheat",
        "vac-check",
        "trading-bot",
        "dupe-check",
        "phishing",
        "raider",
        "token-seller",
    ]

    def __init__(self) -> None:
        """Initialize the Discord collector."""
        super().__init__("DiscordCollector")
        self.config = Config()
        self.bot_token = self.config.discord_bot_token

    @property
    def platform(self) -> str:
        """Get platform name."""
        return "discord"

    async def _collect(self, target: str) -> DiscordUser | None:
        """Collect Discord user data.

        Args:
            target: Discord user ID

        Returns:
            DiscordUser object with collected data
        """
        if not self.bot_token:
            raise ValueError("DISCORD_BOT_TOKEN environment variable not set")

        try:
            logger.debug(f"Collecting Discord data for user: {target}")

            user_data = await self._get_user(target)
            if not user_data:
                raise ValueError(f"Could not retrieve user data for {target}")

            # Extract account age
            account_created = None
            if "id" in user_data:
                account_created = self._extract_account_creation_date(
                    user_data["id"]
                )

            # Detect scam patterns
            patterns = self._detect_scam_patterns(user_data)

            # Build user object
            discord_user = DiscordUser(
                user_id=user_data.get("id", ""),
                username=user_data.get("username", ""),
                discriminator=user_data.get("discriminator"),
                avatar_url=self._get_avatar_url(user_data),
                account_created=account_created,
                flags=user_data.get("flags", 0),
                public_flags=user_data.get("public_flags", 0),
                bot=user_data.get("bot", False),
                system=user_data.get("system", False),
                known_scam_patterns=patterns,
            )

            logger.debug(f"Successfully collected Discord user data: {target}")
            return discord_user

        except Exception as e:
            logger.error(f"Discord collection failed for {target}: {str(e)}")
            raise

    async def _get_user(self, user_id: str) -> dict[str, Any] | None:
        """Get Discord user information via API.

        Args:
            user_id: Discord user ID

        Returns:
            User data dict or None
        """
        try:
            headers = {"Authorization": f"Bot {self.bot_token}"}
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.DISCORD_API_BASE}/users/{user_id}",
                    headers=headers,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"Discord user not found: {user_id}")
            else:
                logger.error(f"Discord API error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Failed to get Discord user: {str(e)}")
            return None

    @staticmethod
    def _extract_account_creation_date(user_id: str) -> datetime | None:
        """Extract account creation date from Discord user ID.

        Discord user IDs are Snowflakes containing timestamp information.

        Args:
            user_id: Discord user ID

        Returns:
            Extracted datetime or None
        """
        try:
            # Discord Snowflake format: timestamp in milliseconds is in upper 42 bits
            # Epoch is 2015-01-01
            snowflake = int(user_id)
            timestamp_ms = snowflake >> 22
            # Convert to seconds and add Discord epoch offset
            timestamp = (timestamp_ms / 1000.0) + 1420070400
            return datetime.utcfromtimestamp(timestamp)
        except (ValueError, OverflowError):
            return None

    def _detect_scam_patterns(
        self, user_data: dict[str, Any]
    ) -> list[str]:
        """Detect known scam patterns in user data.

        Args:
            user_data: Discord user data dict

        Returns:
            List of detected scam patterns
        """
        detected: list[str] = []
        username = user_data.get("username", "").lower()

        for pattern in self.SCAM_PATTERNS:
            if pattern.lower() in username:
                detected.append(pattern)

        return detected

    @staticmethod
    def _get_avatar_url(user_data: dict[str, Any]) -> str | None:
        """Build avatar URL from user data.

        Args:
            user_data: Discord user data dict

        Returns:
            Avatar URL or None
        """
        if not user_data.get("avatar"):
            return None

        user_id = user_data.get("id")
        avatar_hash = user_data.get("avatar")

        if not user_id or not avatar_hash:
            return None

        # Determine if animated
        is_animated = avatar_hash.startswith("a_")
        ext = "gif" if is_animated else "png"

        return (
            f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{ext}"
        )
