"""FBI IC3 (Internet Crime Complaint Center) report formatter.

Generates pre-filled text matching ic3.gov complaint form fields for
reporting cyber fraud and criminal activity to the FBI.
"""

from chharcop.models import ScanResult


class Ic3ReportFormatter:
    """Formatter for FBI IC3 crime complaint reports.

    Converts scan results into formatted text pre-filled for submission
    to the FBI's Internet Crime Complaint Center portal.

    Example:
        >>> formatter = Ic3ReportFormatter()
        >>> report_text = formatter.format(scan_result)
        >>> print(report_text)
    """

    def format(self, scan_result: ScanResult) -> str:
        """Format scan result for FBI IC3 complaint submission.

        Generates pre-filled text suitable for ic3.gov complaint form
        with complete incident details and technical forensics.

        Args:
            scan_result: ScanResult containing collected evidence

        Returns:
            Formatted text for FBI IC3 complaint form

        Raises:
            ValueError: If scan_result lacks required fields
        """
        if not scan_result or not scan_result.target:
            raise ValueError("scan_result must have valid target")

        lines = []

        # Header
        lines.append("=" * 70)
        lines.append("FBI IC3 INTERNET CRIME COMPLAINT")
        lines.append("Internet Crime Complaint Center (ic3.gov)")
        lines.append("=" * 70)
        lines.append("")

        # Complaint Metadata
        lines.append("COMPLAINT INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"Complaint Submitted: {scan_result.scan_timestamp.strftime('%Y-%m-%d')}")
        lines.append(f"Reference ID: {scan_result.scan_id}")
        lines.append(f"Incident Type: Suspicious Website / Cyber Fraud")
        lines.append("")

        # Incident Description
        lines.append("INCIDENT DESCRIPTION:")
        lines.append("-" * 70)
        lines.extend(self._build_incident_description(scan_result))
        lines.append("")

        # Targeted Website/Domain
        lines.append("TARGETED WEBSITE/DOMAIN:")
        lines.append("-" * 70)
        lines.append(f"URL: {scan_result.target}")
        lines.extend(self._build_domain_info(scan_result))
        lines.append("")

        # IP Address Information
        lines.append("IP ADDRESS INFORMATION:")
        lines.append("-" * 70)
        lines.extend(self._build_ip_info(scan_result))
        lines.append("")

        # Domain Registration Details
        lines.append("DOMAIN REGISTRATION DETAILS:")
        lines.append("-" * 70)
        lines.extend(self._build_registration_details(scan_result))
        lines.append("")

        # Technical Indicators
        lines.append("TECHNICAL INDICATORS OF COMPROMISE:")
        lines.append("-" * 70)
        lines.extend(self._build_technical_indicators(scan_result))
        lines.append("")

        # Malware/Security Indicators
        lines.append("SECURITY ASSESSMENT:")
        lines.append("-" * 70)
        lines.append(f"Risk Level: {scan_result.risk_level.upper()}")
        lines.append(f"Risk Score: {scan_result.risk_score:.2%}")
        if scan_result.risk_factors:
            lines.append("Identified Risk Factors:")
            for factor in scan_result.risk_factors:
                lines.append(f"  • {factor.replace('_', ' ').title()}")
        lines.append("")

        # Investigative Notes
        lines.append("INVESTIGATIVE NOTES:")
        lines.append("-" * 70)
        lines.append(
            "This complaint is based on automated forensic analysis of website "
            "properties, SSL certificates, domain registration details, and "
            "historical metadata. Evidence has been cryptographically hashed "
            "for integrity verification."
        )
        if scan_result.correlation_notes:
            lines.append("\nCorrelation Notes:")
            for note in scan_result.correlation_notes:
                lines.append(f"  • {note}")
        lines.append("")

        # Recommendation
        lines.append("RECOMMENDATION:")
        lines.append("-" * 70)
        lines.append(
            "Recommend investigation into domain operator identity, "
            "infrastructure hosting, and payment processing details. "
            "All technical evidence is documented and available for review."
        )
        lines.append("")

        lines.append("=" * 70)
        lines.append("End of FBI IC3 Complaint")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _build_incident_description(self, scan_result: ScanResult) -> list[str]:
        """Build incident description from risk factors.

        Args:
            scan_result: Scan result with risk assessment

        Returns:
            List of incident description lines
        """
        lines = []

        risk_level_text = {
            "critical": "Critical risk factors identified",
            "high": "High risk factors identified",
            "medium": "Medium risk factors identified",
            "low": "Low risk factors identified",
            "unknown": "Risk assessment inconclusive",
        }

        lines.append(
            f"Website at {scan_result.target} exhibits characteristics "
            f"consistent with fraudulent or malicious activity."
        )
        lines.append(
            risk_level_text.get(
                scan_result.risk_level.lower(),
                "Risk factors identified"
            )
        )

        if scan_result.web_results and scan_result.web_results.whois_data:
            whois = scan_result.web_results.whois_data
            if whois.days_old is not None and whois.days_old < 30:
                lines.append(
                    "Domain was registered within the last 30 days, "
                    "suggesting potential rapid deployment of fraudulent infrastructure."
                )

        if scan_result.gaming_results:
            lines.append(
                "Connected gaming account profiles show indicators of "
                "account farming, trade ban history, or scam flags."
            )

        return lines

    def _build_domain_info(self, scan_result: ScanResult) -> list[str]:
        """Build domain information section.

        Args:
            scan_result: Scan result with web data

        Returns:
            List of domain information lines
        """
        lines = []

        if not scan_result.web_results or not scan_result.web_results.whois_data:
            lines.append("Domain: No WHOIS data available")
            return lines

        whois = scan_result.web_results.whois_data
        lines.append(f"Domain Name: {whois.domain}")
        lines.append(f"Registrar: {whois.registrar or 'Unknown'}")

        if whois.creation_date:
            lines.append(
                f"Domain Creation Date: {whois.creation_date.strftime('%Y-%m-%d')}"
            )
        if whois.expiration_date:
            lines.append(
                f"Domain Expiration Date: {whois.expiration_date.strftime('%Y-%m-%d')}"
            )

        lines.append(
            f"Privacy Protection: "
            f"{'Yes - WHOIS privately registered' if whois.privacy_protected else 'No'}"
        )

        return lines

    def _build_ip_info(self, scan_result: ScanResult) -> list[str]:
        """Build IP address information section.

        Args:
            scan_result: Scan result with DNS data

        Returns:
            List of IP information lines
        """
        lines = []

        if not scan_result.web_results or not scan_result.web_results.dns_data:
            lines.append("No DNS resolution data available")
            return lines

        dns = scan_result.web_results.dns_data

        if dns.a_records:
            lines.append(f"IPv4 Addresses (A Records):")
            for ip in dns.a_records:
                lines.append(f"  • {ip}")

        if dns.aaaa_records:
            lines.append(f"IPv6 Addresses (AAAA Records):")
            for ip in dns.aaaa_records:
                lines.append(f"  • {ip}")

        if dns.ns_records:
            lines.append(f"Authoritative Nameservers:")
            for ns in dns.ns_records:
                lines.append(f"  • {ns}")

        return lines

    def _build_registration_details(self, scan_result: ScanResult) -> list[str]:
        """Build domain registration details section.

        Args:
            scan_result: Scan result with WHOIS data

        Returns:
            List of registration detail lines
        """
        lines = []

        if not scan_result.web_results or not scan_result.web_results.whois_data:
            lines.append("No registration data available")
            return lines

        whois = scan_result.web_results.whois_data

        if whois.registrant_org:
            lines.append(f"Registrant Organization: {whois.registrant_org}")
        elif whois.registrant_name:
            lines.append(f"Registrant Name: {whois.registrant_name}")
        else:
            lines.append("Registrant: Information Unavailable (Privacy Protection)")

        if whois.name_servers:
            lines.append(f"Nameservers ({len(whois.name_servers)}):")
            for ns in whois.name_servers[:5]:  # Limit to first 5
                lines.append(f"  • {ns}")

        if whois.days_old is not None:
            lines.append(f"Domain Age: {whois.days_old} days")

        return lines

    def _build_technical_indicators(self, scan_result: ScanResult) -> list[str]:
        """Build technical indicators section.

        Args:
            scan_result: Scan result with technical data

        Returns:
            List of technical indicator lines
        """
        lines = []

        indicators = []

        # SSL Certificate indicators
        if scan_result.web_results and scan_result.web_results.ssl_data:
            ssl = scan_result.web_results.ssl_data
            if ssl.is_self_signed:
                indicators.append(
                    "Self-signed SSL certificate (not from trusted CA)"
                )
            if not ssl.is_valid:
                indicators.append("SSL certificate expired or invalid")
            if ssl.cert_type == "unknown":
                indicators.append("Certificate type could not be verified")

        # Metadata indicators
        if scan_result.web_results and scan_result.web_results.metadata:
            meta = scan_result.web_results.metadata
            missing_trust = sum([
                not meta.has_privacy_policy,
                not meta.has_terms_of_service,
                not meta.has_contact_page,
                not meta.has_about_page,
            ])
            if missing_trust >= 3:
                indicators.append(
                    f"Missing {missing_trust} standard trust signals "
                    "(privacy policy, ToS, contact, about)"
                )

            if len(meta.redirect_chain) > 2:
                indicators.append(
                    f"Suspicious redirect chain ({len(meta.redirect_chain)} redirects)"
                )

        # Gaming indicators
        if scan_result.gaming_results:
            if scan_result.gaming_results.steam_profile:
                sp = scan_result.gaming_results.steam_profile
                if sp.vac_banned:
                    indicators.append("Associated Steam account with VAC bans")
                if sp.trade_ban:
                    indicators.append("Associated Steam account with trade ban")
                if sp.steamrep_status == "scammer":
                    indicators.append(
                        "Associated Steam account flagged as scammer on SteamRep"
                    )

        if indicators:
            for indicator in indicators:
                lines.append(f"  • {indicator}")
        else:
            lines.append("  • No major technical indicators detected")

        return lines
