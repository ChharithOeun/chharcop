"""Web collectors for evidence gathering."""

from chharcop.web.collectors.base import BaseCollector
from chharcop.web.collectors.dns_collector import DnsCollector
from chharcop.web.collectors.metadata_collector import MetadataCollector
from chharcop.web.collectors.ssl_collector import SslCollector
from chharcop.web.collectors.whois_collector import WhoisCollector

__all__ = [
    "BaseCollector",
    "WhoisCollector",
    "DnsCollector",
    "SslCollector",
    "MetadataCollector",
]
