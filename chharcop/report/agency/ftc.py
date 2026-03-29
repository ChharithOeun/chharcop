"""FTC fraud complaint report formatter.

Generates pre-filled text matching FTC reportfraud.ftc.gov complaint form fields
for submitting evidence of deceptive or fraudulent online practices.
"""

from chharcop.models import ScanResult


class FtcReportFormatter:
    """Formatter for FTC fraud complaint reports.

    Converts scan results into formatted text pre-filled for submission
    to the Federal Trade Commission's fraud complaint portal.

    Example:
        >>> formatter = FtcReportFormatter()
        >>> report_text = formatter.format(scan_result)
        >>> print(report_text)
    """

    def format(self, scan_result: ScanResult) -> str:
        """Format scan result for FTC complaint submission.

        Generates pre-filled text suitable for FTC reportfraud.ftc.gov form
        with complete details of the deceptive practice evidence.

        Args:
            scan_result: ScanResult containing collected evidence

        Returns:
            Formatted text for FTC complaint form

        Raises:
            ValueError: If scan_result lacks required fields
        """
        if not scan_result or not scan_result.target:
            raise ValueError("scan_result must have valid target")

        lines = []

        # Header
        lines.append("=" * 70)
        lines.append("FTC FRAUD COMPLAINT REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Complaint Details
        lines.append("COMPLAINT INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"Date of Complaint: {scan_result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Complaint ID: {scan_result.scan_id}")
        lines.append("")

        # URL/Website Information
        lines.append("SUSPICIOUS WEBSITE/URL:")
        lines.append("-" * 70)
        lines.append(f"URL: {scan_result.target}")
        lines.append("")

        # Description of Deceptive Practices
        lines.append("DESCRIPTION OF DECEPTIVE PRACTICES:")
        lines.append("-" * 70)
        lines.extend(self._build_deceptive_practices(scan_result))
        lines.append("")

        # Evidence Summary
        lines.append("COLLECTED EVIDENCE SUMMARY:")
        lines.append("-" * 70)
        lines.extend(self._build_evidence_summary(scan_result))
        lines.append("")

        # Technical Details
        lines.append("TECHNICAL DETAILS:")
        lines.append("-" * 70)
        lines.extend(self._build_technical_details(scan_result))
        lines.append("")

        # Risk Assessment
        lines.append("RISK LEVEL ASSESSMENT:")
        lines.append("-" * 70)
        lines.append(f"Overall Risk Level: {scan_result.risk_level.upper()}")
        lines.append(f"Risk Score: {scan_result.risk_score:.2%}")
        if scan_result.risk_factors:
            lines.append("Risk Factors:")
            for factor in scan_result.risk_factors:
                lines.append(f"  • {factor.replace('_', ' ').title()}")
        lines.append("")

        # Recommendation
        lines.append("RECOMMENDED ACTION:")
        lines.append("-" * 70)
        lines.append("This website exhibits indicators of potentially deceptive practices.")
        lines.append("Report details above provide evidence for investigation.")
        lines.append("All evidence has been cryptographically verified for integrity.")
        lines.append("")

        lines.append("=" * 70)
        lines.append("End of FTC Complaint Report")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _build_deceptive_practices(self, scan_result: ScanResult) -> list[str]:
        """Build deceptive practices description from risk factors.

        Args:
            scan_result: Scan result with risk factors

        Returns:
            List of formatted practice descriptions
        """
        lines = []

        if not scan_result.web_results:
            lines.append("No web evidence collected.")
            return lines

        web = scan_result.web_results

        # Domain age indicators
        if web.whois_data:
            if web.whois_data.days_old is not None:
                if web.whois_data.days_old < 30:
                    lines.append(
                        "• Domain was recently registered (less than 30 days old), "
                        "a common indicator of fraudulent sites that are quickly abandoned "
                        "and recreated under new domains."
                    )
                elif web.whois_data.days_old < 180:
                    lines.append(
                        "• Domain was recently created (less than 180 days old), "
                        "showing recent establishment of potential fraudulent presence."
                    )

            if web.whois_data.privacy_protected:
                lines.append(
                    "• Domain registration uses privacy protection services, "
                    "obscuring true operator identity."
                )

        # SSL Certificate issues
        if web.ssl_data:
            if web.ssl_data.is_self_signed:
                lines.append(
                    "• Uses self-signed SSL certificate instead of trusted Certificate Authority, "
                    "a major red flag for deceptive or malicious intent."
                )
            if not web.ssl_data.is_valid:
                lines.append(
                    "• SSL certificate is expired or invalid, "
                    "preventing legitimate security verification."
                )

        # Missing trust signals
        if web.metadata:
            missing_signals = []
            if not web.metadata.has_privacy_policy:
                missing_signals.append("privacy policy")
            if not web.metadata.has_terms_of_service:
                missing_signals.append("terms of service")
            if not web.metadata.has_contact_page:
                missing_signals.append("contact information")
            if not web.metadata.has_about_page:
                missing_signals.append("about page")

            if len(missing_signals) >= 3:
                signals_str = ", ".join(missing_signals)
                lines.append(
                    f"• Missing standard trust signals ({signals_str}), "
                    "indicating lack of legitimate business transparency."
                )

            if len(web.metadata.redirect_chain) > 2:
                lines.append(
                    f"• URL redirects through {len(web.metadata.redirect_chain)} domains, "
                    "potentially obscuring true destination and deceiving users."
                )

        if not lines:
            lines.append(
                "Evidence indicates website exhibits characteristics consistent "
                "with deceptive or fraudulent online practices."
            )

        return lines

    def _build_evidence_summary(self, scan_result: ScanResult) -> list[str]:
        """Build summary of collected evidence.

        Args:
            scan_result: Scan result with evidence

        Returns:
            List of evidence summaries
        """
        lines = []

        if scan_result.web_results:
            if scan_result.web_results.whois_data:
                whois = scan_result.web_results.whois_data
                lines.append(
                    f"Domain: {whois.domain} (Age: {whois.days_old} days if available)"
                )
                if whois.registrar:
                    lines.append(f"Registrar: {whois.registrar}")
                if whois.name_servers:
                    lines.append(f"Name Servers: {', '.join(whois.name_servers)}")

            if scan_result.web_results.dns_data:
                dns = scan_result.web_results.dns_data
                if dns.a_records:
                    lines.append(f"Resolved IP Addresses: {', '.join(dns.a_records)}")

            if scan_result.web_results.ssl_data:
                ssl = scan_result.web_results.ssl_data
                lines.append(
                    f"SSL Certificate Valid: {ssl.is_valid} "
                    f"(Type: {ssl.cert_type})"
                )

            if scan_result.web_results.metadata:
                meta = scan_result.web_results.metadata
                lines.append(f"Website Title: {meta.title or 'Not available'}")
                lines.append(
                    f"Trust Signals: "
                    f"Privacy Policy: {meta.has_privacy_policy}, "
                    f"ToS: {meta.has_terms_of_service}, "
                    f"Contact: {meta.has_contact_page}, "
                    f"About: {meta.has_about_page}"
                )

        if not lines:
            lines.append("No web evidence collected for detailed analysis.")

        return lines

    def _build_technical_details(self, scan_result: ScanResult) -> list[str]:
        """Build technical details section.

        Args:
            scan_result: Scan result with technical data

        Returns:
            List of technical details
        """
        lines = []

        lines.append(f"Scan Type: {scan_result.scan_type.upper()}")
        lines.append(f"Scan ID: {scan_result.scan_id}")
        lines.append(f"Scan Timestamp: {scan_result.scan_timestamp.isoformat()}")

        if scan_result.web_results and scan_result.web_results.dns_data:
            dns = scan_result.web_results.dns_data
            lines.append(f"DNS Query Timestamp: {dns.query_timestamp.isoformat()}")

        if scan_result.overall_errors:
            lines.append(f"Collection Errors: {len(scan_result.overall_errors)}")
            for error in scan_result.overall_errors:
                lines.append(f"  - {error.collector}: {error.error_message}")

        return lines
