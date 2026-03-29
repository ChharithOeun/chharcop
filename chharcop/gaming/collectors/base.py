"""Base class for gaming platform collectors."""

from abc import ABC, abstractmethod

from loguru import logger

from chharcop.models import CollectorError


class BaseGamingCollector(ABC):
    """Abstract base class for gaming platform collectors.

    Provides common structure for all gaming-based collectors with error handling,
    logging, and configuration support.
    """

    def __init__(self, name: str = "") -> None:
        """Initialize the gaming collector.

        Args:
            name: Optional collector name override
        """
        self._name: str = name or self.__class__.__name__

    @property
    def name(self) -> str:
        """Get the collector name.

        Returns:
            Name of the collector
        """
        return self._name

    @property
    def platform(self) -> str:
        """Get the gaming platform this collector targets.

        Should be overridden by subclasses.

        Returns:
            Platform name (e.g., 'steam', 'discord')
        """
        return "unknown"

    async def collect(self, target: str) -> dict[str, any]:  # type: ignore[type-arg]
        """Collect evidence from the target.

        Main entry point that handles error management and logging.
        Delegates to _collect() for actual implementation.

        Args:
            target: Target identifier (Steam ID, Discord ID, username, etc.)

        Returns:
            Collected data as dictionary with 'data' and 'error' keys

        Raises:
            No exceptions raised; errors captured in return dict
        """
        try:
            logger.debug(
                f"{self.name} ({self.platform}): Starting collection for {target}"
            )
            data = await self._collect(target)
            logger.debug(f"{self.name}: Successfully collected data")
            return {"data": data, "error": None}
        except Exception as e:
            logger.error(
                f"{self.name}: Collection failed - {type(e).__name__}: {str(e)}"
            )
            error = CollectorError(
                collector=self.name,
                error_type=type(e).__name__,
                error_message=str(e),
            )
            return {"data": None, "error": error}

    @abstractmethod
    async def _collect(self, target: str) -> dict[str, any]:  # type: ignore[type-arg]
        """Collect evidence from target (implementation).

        Must be implemented by subclasses.

        Args:
            target: Target identifier to collect from

        Returns:
            Collected data as dictionary
        """
        pass
