"""Base class for web evidence collectors."""

from abc import ABC, abstractmethod

from loguru import logger

from chharcop.models import CollectorError


class BaseCollector(ABC):
    """Abstract base class for web evidence collectors.

    Provides common structure for all web-based collectors with error handling
    and logging infrastructure.
    """

    def __init__(self) -> None:
        """Initialize the collector."""
        self._name: str = self.__class__.__name__

    @property
    def name(self) -> str:
        """Get the collector name.

        Returns:
            Name of the collector
        """
        return self._name

    async def collect(self, target: str) -> dict[str, any]:  # type: ignore[type-arg]
        """Collect evidence from the target.

        Main entry point that handles error management and logging.
        Delegates to _collect() for actual implementation.

        Args:
            target: Target to collect evidence from (domain, URL, etc.)

        Returns:
            Collected data as dictionary with 'data' and 'error' keys

        Raises:
            No exceptions raised; errors captured in return dict
        """
        try:
            logger.debug(f"{self.name}: Starting collection for target: {target}")
            data = await self._collect(target)
            logger.debug(f"{self.name}: Successfully collected data")
            return {"data": data, "error": None}
        except Exception as e:
            logger.error(f"{self.name}: Collection failed - {type(e).__name__}: {str(e)}")
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
            target: Target to collect evidence from

        Returns:
            Collected data as dictionary
        """
        pass
