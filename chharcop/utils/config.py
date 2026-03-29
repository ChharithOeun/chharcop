"""Configuration management for Chharcop."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


@dataclass
class Config:
    """Configuration container for Chharcop.

    Loads API keys and sensitive configuration from environment variables.
    Cross-platform compatible using pathlib.
    """

    steam_api_key: str | None = field(default=None)
    discord_bot_token: str | None = field(default=None)
    virustotal_api_key: str | None = field(default=None)
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "chharcop")

    def __post_init__(self) -> None:
        """Load configuration from environment after initialization."""
        self._load_from_env()

    def _load_from_env(self) -> None:
        """Load API keys from environment variables.

        Looks for:
        - STEAM_API_KEY
        - DISCORD_BOT_TOKEN
        - VIRUSTOTAL_API_KEY
        """
        # Load API keys
        if not self.steam_api_key:
            self.steam_api_key = os.environ.get("STEAM_API_KEY")

        if not self.discord_bot_token:
            self.discord_bot_token = os.environ.get("DISCORD_BOT_TOKEN")

        if not self.virustotal_api_key:
            self.virustotal_api_key = os.environ.get("VIRUSTOTAL_API_KEY")

        # Log available keys (without exposing values)
        if self.steam_api_key:
            logger.debug("Steam API key loaded from environment")
        if self.discord_bot_token:
            logger.debug("Discord bot token loaded from environment")
        if self.virustotal_api_key:
            logger.debug("VirusTotal API key loaded from environment")

    def ensure_cache_dir(self) -> Path:
        """Ensure cache directory exists.

        Creates cache directory if it doesn't exist.
        Cross-platform compatible.

        Returns:
            Path to cache directory
        """
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Cache directory ready: {self.cache_dir}")
            return self.cache_dir
        except Exception as e:
            logger.error(f"Failed to create cache directory: {str(e)}")
            return self.cache_dir

    def get_steam_api_key(self) -> str:
        """Get Steam API key.

        Returns:
            Steam API key

        Raises:
            ValueError: If key not configured
        """
        if not self.steam_api_key:
            raise ValueError("STEAM_API_KEY environment variable not set")
        return self.steam_api_key

    def get_discord_bot_token(self) -> str:
        """Get Discord bot token.

        Returns:
            Discord bot token

        Raises:
            ValueError: If token not configured
        """
        if not self.discord_bot_token:
            raise ValueError("DISCORD_BOT_TOKEN environment variable not set")
        return self.discord_bot_token

    def get_virustotal_api_key(self) -> str:
        """Get VirusTotal API key.

        Returns:
            VirusTotal API key

        Raises:
            ValueError: If key not configured
        """
        if not self.virustotal_api_key:
            raise ValueError("VIRUSTOTAL_API_KEY environment variable not set")
        return self.virustotal_api_key
