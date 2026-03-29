"""WHOIS data collector for domain registration information."""

import asyncio
from datetime import datetime, timezone
from typing import Any

import whois
from loguru import logger

from chharcop.models import WhoisData
from chharcop.web.collectors.base import BaseCollector


class WhoisCollector(BaseCollector):
    """Collector for WHOIS domain registration data.

    Gathers domain registration details, registrar information, name servers,
    and registrant information (when not private). Also calculates domain age
    and expiration timeline.
    """

    def __init__(self) -> None:
        """Initialize the WHOIS collector."""
        super().__init__()
        self._name = "WhoisCollector"

    async def _collect(self, target: str) -> WhoisData | None:
        """Collect WHOIS data for domain.

        Runs synchronous whois library in executor to avoid blocking.
        Normalizes and extracts relevant fields.

        Args:
            target: Domain name to query

        Returns:
            WhoisData object with collected information
        """
        loop = asyncio.get_event_loop()

        try:
            # Run whois lookup in executor (blocking call)
            whois_result = await loop.run_in_executor(
                None, lambda: whois.whois(target)
            )

            logger.debug(f"WHOIS lookup successful for {target}")

            # Extract registration dates
            creation_date = self._parse_date(whois_result.creation_date)
            expiration_date = self._parse_date(whois_result.expiration_date)
            updated_date = self._parse_date(whois_result.updated_date)

            # Calculate domain age
            days_old: int | None = None
            if creation_date:
                now = datetime.now(timezone.utc)
                cd = creation_date if creation_date.tzinfo else creation_date.replace(tzinfo=timezone.utc)
                days_old = (now - cd).days

            # Calculate days until expiry
            days_until_expiry: int | None = None
            if expiration_date:
                now = datetime.now(timezone.utc)
                ed = expiration_date if expiration_date.tzinfo else expiration_date.replace(tzinfo=timezone.utc)
                days_until_expiry = (ed - now).days

            # Check for privacy protection
            privacy_protected = False
            if whois_result.registrant_name:
                privacy_protected = "privacy" in whois_result.registrant_name.lower()

            # Extract name servers
            name_servers: list[str] = []
            if whois_result.name_servers:
                name_servers = [
                    str(ns).lower().rstrip(".") for ns in whois_result.name_servers
                ]

            whois_data = WhoisData(
                domain=target,
                registrar=whois_result.registrar,
                registrar_url=getattr(whois_result, "registrar_url", None),
                creation_date=creation_date,
                expiration_date=expiration_date,
                updated_date=updated_date,
                name_servers=name_servers,
                registrant_name=whois_result.registrant_name,
                registrant_email=whois_result.registrant_email,
                registrant_org=whois_result.registrant_org,
                privacy_protected=privacy_protected,
                days_old=days_old,
                days_until_expiry=days_until_expiry,
            )

            logger.debug(f"Successfully parsed WHOIS data: {target}")
            return whois_data

        except Exception as e:
            logger.error(f"WHOIS collection failed for {target}: {str(e)}")
            raise

    @staticmethod
    def _parse_date(date_value: Any) -> datetime | None:
        """Parse date value from WHOIS result.

        Handles various date formats and types returned by whois library.

        Args:
            date_value: Date value from whois result

        Returns:
            Parsed datetime object or None if parsing fails
        """
        if date_value is None:
            return None

        if isinstance(date_value, datetime):
            return date_value

        if isinstance(date_value, list):
            if len(date_value) > 0:
                return WhoisCollector._parse_date(date_value[0])
            return None

        if isinstance(date_value, str):
            try:
                dt = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
                # Normalize to UTC-aware
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except (ValueError, AttributeError):
                return None

        return None
