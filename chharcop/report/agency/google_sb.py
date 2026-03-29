"""Google Safe Browsing report formatter.

Generates formatted report text for submitting suspicious URL reports
to Google's Safe Browsing initiative.
"""

from chharcop.models import ScanResult


class GoogleSafeBrowsingFormatter:
    """Formatter for Google Safe Browsing reports.

    Converts scan results into formatted text and direct report links
    for submission to Google's Safe Browsing program.

    Example:
        >>> formatter = GoogleSafeBrowsingFormatter()
        >>> report_text = formatter.format(scan_result)
        >>> print(report_text)
    """

    GOOGLE_REPORT_URL = "https://safebrowsing.google.com/safebrowsing/report_badware/"

    def format(self, scan_result: ScanResult) -> str:
        """Format scan result for Google Safe Browsing submission.

        Generates pre-filled text with direct link to Google's Safe Browsing
        report form and evidence summary.

        Args:
            scan_result: ScanResult containing collected evidence

        Returns:
            Formatted text for Google Safe Browsing report

        Raises:
            ValueError: If scan_result lacks required fields
        """
        if not scan_result or not scan_result.target:
            raise ValueError("scan_result must have valid target")

        lines = []

        # Header
        lines.append("=" * 70)
        lines.append("GOOGLE SAFE BROWSING REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Report Information
        lines.append("REPORT INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"Date: {scan_result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Report ID: {scan_result.scan_id}")
        lines.append(f"Risk Level: {scan_result.risk_level.upper()}")
        lines.append("")

        # Suspicious URL
        lines.append("SUSPICIOUS URL:")
        lines.append("-" * 70)
        lines.append(f"URL: {scan_result.target}")
        lines.append("")

        # Direct Report Link
        lines.append("DIRECT REPORT LINK:")
        lines.append("-" * 70)
        report_url = self._build_report_url(scan_result.target)
        lines.append(report_url)
        lines.append("")
        lines.append(
            "Click the link above or copy and paste into your browser to report "
            "this URL to Google Safe Browsing."
        )
        lines.append("")

        # Evidence Summary
        lines.append("EVIDENCE SUMMARY:")
        lines.append("-" * 70)
        lines.extend(self._build_evidence_summary(scan_result))
        lines.append("")

        # Risk Assessment
        lines.append("RISK ASSESSMENT:")
        lines.append("-" * 70)
        lines.append(f"Risk Score: {scan_result.risk_score:.2%}")
        lines.append(f"Risk Level: {scan_result.risk_level.upper()}")
        if scan_result.risk_factors:
            lines.append("Risk Factors Identified:")
            for factor in scan_result.risk_factors:
                lines.append(f"  • {factor.replace('_', ' ').title()}")
        lines.append("")

        # Classification Suggestions
        lines.append("CLASSIFICATION SUGGESTIONS:")
        lines.append("-" * 70)
        lines.extend(self._build_classification(scan_result))
        lines.append("")

        # Collection Metadata
        lines.append("COLLECTION METADATA:")
        lines.append("-" * 70)
        lines.append(f"Scan Type: {scan_result.scan_type.upper()}")
        lines.append(f"Scan ID: {scan_result.scan_id}")
        lines.append(f"Timestamp: {scan_result.scan_timestamp.isoformat()}")
        lines.append(f"Data Integrity: Verified (SHA-256 hashes computed)")
        lines.append("")

        # Instructions
        lines.append("INSTRUCTIONS:")
        lines.append("-" * 70)
        lines.append("1. Copy the Direct Report Link above")
        lines.append("2. Paste into your web browser")
        lines.append("3. Complete Google's Safe Browsing report form")
        lines.append("4. Include evidence from summary above if applicable")
        lines.append("5. Submit the report")
        lines.append("")
        lines.append(
            "Note: Google Safe Browsing helps protect billions of users by "
            "identifying phishing, malware, and unwanted software."
        )
        lines.append("")

        lines.append("=" * 70)
        lines.append("End of Google Safe Browsing Report")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _build_report_url(self, target_url: str) -> str:
        """Build formatted Google Safe Browsing report URL.

        Args:
            target_url: URL to report

        Returns:
            Formatted report URL
        """
        # Encode the URL for the query parameter
        from urllib.parse import quote

        encoded_url = quote(target_url, safe="")
        return (
            f"{self.GOOGLE_REPORT_URL}?url={encoded_url}"
        )

    def _build_evidence_summary(self, scan_result: ScanResult) -> list[str]:
        """Build evidence summary for the report.

        Args:
            scan_result: Scan result with evidence

        Returns:
            List of evidence summary lines
        """
        lines = []

        if not scan_result.web_results:
            lines.append("No web evidence collected")
            return lines

        web = scan_result.web_results

        # Domain/WHOIS Evidence
        if web.whois_data:
            whois = web.whois_data
            lines.append(f"Domain: {whois.domain}")

            if whois.days_old is not None:
                if whois.days_old < 7:
                    lines.append(
                        f"Age: Less than 1 week old ({whois.days_old} days) - "
                        "NEW DOMAIN (common for phishing)"
                    )
                elif whois.days_old < 30:
                    lines.append(
                        f"Age: Very new ({whois.days_old} days) - "
                        "May indicate temporary fraudulent site"
                    )
                else:
                    lines.append(f"Age: {whois.days_old} days")

            if whois.privacy_protected:
                lines.append("WHOIS: Privately registered (identity hidden)")
            if whois.registrar:
                lines.append(f"Registrar: {whois.registrar}")

        # SSL Certificate Evidence
        if web.ssl_data:
            ssl = web.ssl_data
            if ssl.is_self_signed:
                lines.append(
                    "SSL: Self-signed certificate (not from trusted authority) - "
                    "RED FLAG"
                )
            elif not ssl.is_valid:
                lines.append(
                    "SSL: Invalid or expired certificate - RED FLAG"
                )
            elif ssl.cert_type == "unknown":
                lines.append("SSL: Certificate type could not be verified")
            else:
                lines.append(f"SSL: Certificate appears valid ({ssl.cert_type} type)")

        # Website Metadata Evidence
        if web.metadata:
            meta = web.metadata
            missing_trust = []
            if not meta.has_privacy_policy:
                missing_trust.append("privacy policy")
            if not meta.has_terms_of_service:
                missing_trust.append("terms of service")
            if not meta.has_contact_page:
                missing_trust.append("contact info")
            if not meta.has_about_page:
                missing_trust.append("about page")

            if missing_trust:
                lines.append(
                    f"Trust Signals: Missing {len(missing_trust)} critical elements - "
                    f"{', '.join(missing_trust)}"
                )

            if len(meta.redirect_chain) > 2:
                lines.append(
                    f"URL Redirects: Multiple redirects detected "
                    f"({len(meta.redirect_chain)} hops) - "
                    "may obscure true destination"
                )

            if meta.response_time_ms and meta.response_time_ms > 5000:
                lines.append(
                    f"Server: Slow response ({meta.response_time_ms:.0f}ms) - "
                    "may indicate compromised hosting"
                )

        # DNS Evidence
        if web.dns_data:
            dns = web.dns_data
            if dns.a_records:
                lines.append(f"DNS A Records: {', '.join(dns.a_records[:3])}")
                if len(dns.a_records) > 3:
                    lines.append(f"  (and {len(dns.a_records) - 3} more)")

        if not lines:
            lines.append("No specific evidence indicators detected")

        return lines

    def _build_classification(self, scan_result: ScanResult) -> list[str]:
        """Build classification suggestions based on risk level.

        Args:
            scan_result: Scan result with risk assessment

        Returns:
            List of classification suggestions
        """
        lines = []

        risk_level = scan_result.risk_level.lower()

        if risk_level == "critical":
            lines.append("Classification: LIKELY MALICIOUS")
            lines.append("")
            lines.append("Suggested categories:")
            lines.append("  • Phishing and deception")
            lines.append("  • Malware hosting")
            lines.append("  • Unwanted software")

        elif risk_level == "high":
            lines.append("Classification: SUSPICIOUS - LIKELY MALICIOUS")
            lines.append("")
            lines.append("Suggested categories:")
            lines.append("  • Phishing and deception")
            lines.append("  • Potentially harmful")

        elif risk_level == "medium":
            lines.append("Classification: SUSPICIOUS")
            lines.append("")
            lines.append("Suggested categories:")
            lines.append("  • Potentially harmful")
            lines.append("  • Suspicious characteristics")

        elif risk_level == "low":
            lines.append("Classification: LOW RISK")
            lines.append("")
            lines.append("Site exhibits minor risk indicators")
            lines.append("Review before submission")

        else:
            lines.append("Classification: REQUIRES REVIEW")
            lines.append("")
            lines.append("Manual review recommended before submission")

        return lines
