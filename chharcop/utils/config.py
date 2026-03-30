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
    twitter_bearer_token: str | None = field(default=None)
    reddit_client_id: str | None = field(default=None)
    reddit_client_secret: str | None = field(default=None)
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
        - TWITTER_BEARER_TOKEN
        - REDDIT_CLIENT_ID
        - REDDIT_CLIENT_SECRET
        """
        # Load API keys
        if not self.steam_api_key:
            self.steam_api_key = os.environ.get("STEAM_API_KEY")

        if not self.discord_bot_token:
            self.discord_bot_token = os.environ.get("DISCORD_BOT_TOKEN")

        if not self.virustotal_api_key:
            self.virustotal_api_key = os.environ.get("VIRUSTOTAL_API_KEY")

        if not self.twitter_bearer_token:
            self.twitter_bearer_token = os.environ.get("TWITTER_BEARER_TOKEN")

        if not self.reddit_client_id:
            self.reddit_client_id = os.environ.get("REDDIT_CLIENT_ID")

        if not self.reddit_client_secret:
            self.reddit_client_secret = os.environ.get("REDDIT_CLIENT_SECRET")

        # Log available keys (without exposing values)
        if self.steam_api_key:
            logger.debug("Steam API key loaded from environment")
        if self.discord_bot_token:
            logger.debug("Discord bot token loaded from environment")
        if self.virustotal_api_key:
            logger.debug("VirusTotal API key loaded from environment")
        if self.twitter_bearer_token:
            logger.debug("Twitter bearer token loaded from environment")
        if self.reddit_client_id:
            logger.debug("Reddit client ID loaded from environment")

    def ensure_cache_dir(self) -> Path:
        """Ensure cache directory exists with restricted permissions.

        Creates cache directory if it doesn't exist.
        Sets permissions to 0o700 (owner read/write/execute only) to
        prevent other users from reading cached API responses and scan data.
        Cross-platform compatible (chmod is a no-op on Windows).

        Returns:
            Path to cache directory
        """
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            try:
                self.cache_dir.chmod(0o700)
            except NotImplementedError:
                pass  # Windows does not support POSIX chmod
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
