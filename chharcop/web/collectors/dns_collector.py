"""DNS record collector for domain resolution data."""

from typing import Any

import dns.resolver
from loguru import logger

from chharcop.models import DnsData, DnsRecord
from chharcop.web.collectors.base import BaseCollector


class DnsCollector(BaseCollector):
    """Collector for DNS records and resolution data.

    Queries multiple DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA)
    concurrently to build comprehensive DNS profile.
    """

    def __init__(self) -> None:
        """Initialize the DNS collector."""
        super().__init__()
        self._name = "DnsCollector"
        self.resolver = dns.resolver.Resolver()

    async def _collect(self, target: str) -> DnsData | None:
        """Collect DNS records for domain.

        Args:
            target: Domain name to query

        Returns:
            DnsData object with all collected records
        """
        try:
            logger.debug(f"Starting DNS resolution for {target}")

            # Query multiple record types
            a_records = self._query_records(target, "A")
            aaaa_records = self._query_records(target, "AAAA")
            mx_records = self._query_mx_records(target)
            ns_records = self._query_records(target, "NS")
            txt_records = self._query_records(target, "TXT")
            cname_records = self._query_cname_records(target)
            soa_record = self._query_soa_record(target)

            dns_data = DnsData(
                domain=target,
                a_records=a_records,
                aaaa_records=aaaa_records,
                mx_records=mx_records,
                ns_records=ns_records,
                txt_records=txt_records,
                cname_records=cname_records,
                soa_record=soa_record,
            )

            logger.debug(f"Successfully collected DNS data for {target}")
            return dns_data

        except Exception as e:
            logger.error(f"DNS collection failed for {target}: {str(e)}")
            raise

    def _query_records(self, domain: str, record_type: str) -> list[str]:
        """Query specific DNS record type.

        Args:
            domain: Domain to query
            record_type: Type of record (A, AAAA, NS, etc.)

        Returns:
            List of record values
        """
        records: list[str] = []
        try:
            answers = self.resolver.resolve(domain, record_type)
            for rdata in answers:
                records.append(str(rdata).rstrip("."))
            logger.debug(f"Found {len(records)} {record_type} records for {domain}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            logger.debug(f"No {record_type} records found for {domain}")
        except Exception as e:
            logger.warning(f"Error querying {record_type} for {domain}: {str(e)}")

        return records

    def _query_mx_records(self, domain: str) -> list[DnsRecord]:
        """Query MX (Mail Exchange) records.

        Args:
            domain: Domain to query

        Returns:
            List of DnsRecord objects for MX entries
        """
        records: list[DnsRecord] = []
        try:
            answers = self.resolver.resolve(domain, "MX")
            for rdata in answers:
                record = DnsRecord(
                    record_type="MX",
                    value=str(rdata.exchange).rstrip("."),
                    priority=rdata.preference,
                )
                records.append(record)
            logger.debug(f"Found {len(records)} MX records for {domain}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            logger.debug(f"No MX records found for {domain}")
        except Exception as e:
            logger.warning(f"Error querying MX records for {domain}: {str(e)}")

        return records

    def _query_cname_records(self, domain: str) -> list[DnsRecord]:
        """Query CNAME (Canonical Name) records.

        Args:
            domain: Domain to query

        Returns:
            List of DnsRecord objects for CNAME entries
        """
        records: list[DnsRecord] = []
        try:
            answers = self.resolver.resolve(domain, "CNAME")
            for rdata in answers:
                record = DnsRecord(
                    record_type="CNAME",
                    value=str(rdata.target).rstrip("."),
                )
                records.append(record)
            logger.debug(f"Found {len(records)} CNAME records for {domain}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            logger.debug(f"No CNAME records found for {domain}")
        except Exception as e:
            logger.warning(f"Error querying CNAME records for {domain}: {str(e)}")

        return records

    def _query_soa_record(self, domain: str) -> str | None:
        """Query SOA (Start of Authority) record.

        Args:
            domain: Domain to query

        Returns:
            SOA record as string or None
        """
        try:
            answers = self.resolver.resolve(domain, "SOA")
            soa = str(answers[0])
            logger.debug(f"Found SOA record for {domain}")
            return soa
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            logger.debug(f"No SOA record found for {domain}")
        except Exception as e:
            logger.warning(f"Error querying SOA record for {domain}: {str(e)}")

        return None
