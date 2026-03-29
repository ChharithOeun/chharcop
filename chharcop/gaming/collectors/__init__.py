"""Gaming platform collectors for evidence gathering."""

from chharcop.gaming.collectors.base import BaseGamingCollector
from chharcop.gaming.collectors.discord_collector import DiscordCollector
from chharcop.gaming.collectors.gamertag_osint import GamertagOsint
from chharcop.gaming.collectors.steam_collector import SteamCollector

__all__ = [
    "BaseGamingCollector",
    "SteamCollector",
    "DiscordCollector",
    "GamertagOsint",
]
