"""Agency report formatters for fraud and law enforcement reporting.

Provides pre-filled report generators for submitting evidence to:
- FTC (Federal Trade Commission)
- FBI IC3 (Internet Crime Complaint Center)
- Google Safe Browsing
- Gaming platforms (Steam, Discord, Xbox, PSN)
"""

from chharcop.report.agency.ftc import FtcReportFormatter
from chharcop.report.agency.ic3 import Ic3ReportFormatter
from chharcop.report.agency.google_sb import GoogleSafeBrowsingFormatter
from chharcop.report.agency.platform_reports import (
    SteamReportFormatter,
    DiscordReportFormatter,
    XboxReportFormatter,
    PsnReportFormatter,
)

__all__ = [
    "FtcReportFormatter",
    "Ic3ReportFormatter",
    "GoogleSafeBrowsingFormatter",
    "SteamReportFormatter",
    "DiscordReportFormatter",
    "XboxReportFormatter",
    "PsnReportFormatter",
]
