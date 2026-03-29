"""Gaming platform report formatters.

Generates formatted reports for submitting evidence and complaints to
major gaming platforms (Steam, Discord, Xbox, PSN).
"""

from chharcop.models import ScanResult


class SteamReportFormatter:
    """Formatter for Steam user report submissions.

    Generates formatted text for reporting suspicious or fraudulent Steam
    accounts to Valve's Trust & Safety team.

    Example:
        >>> formatter = SteamReportFormatter()
        >>> report_text = formatter.format(scan_result)
        >>> print(report_text)
    """

    def format(self, scan_result: ScanResult) -> str:
        """Format scan result for Steam user report submission.

        Generates pre-filled text suitable for Steam user report form
        with complete evidence of fraudulent activity.

        Args:
            scan_result: ScanResult containing gaming evidence

        Returns:
            Formatted text for Steam report submission

        Raises:
            ValueError: If scan_result lacks gaming data or target
        """
        if not scan_result or not scan_result.target:
            raise ValueError("scan_result must have valid target")

        if not scan_result.gaming_results or not scan_result.gaming_results.steam_profile:
            raise ValueError("scan_result must contain Steam profile data")

        steam = scan_result.gaming_results.steam_profile
        lines = []

        # Header
        lines.append("=" * 70)
        lines.append("STEAM USER REPORT FORM")
        lines.append("=" * 70)
        lines.append("")

        # Report Details
        lines.append("REPORT INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"Date: {scan_result.scan_timestamp.strftime('%Y-%m-%d')}")
        lines.append(f"Report ID: {scan_result.scan_id}")
        lines.append("")

        # Account Information
        lines.append("ACCOUNT INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"Steam ID: {steam.steam_id}")
        lines.append(f"Username/Persona: {steam.persona_name}")
        lines.append(f"Profile URL: {steam.profile_url}")
        if steam.account_created:
            lines.append(f"Account Created: {steam.account_created.strftime('%Y-%m-%d')}")
        lines.append(f"Account Level: {steam.level}")
        lines.append("")

        # Risk Assessment
        lines.append("RISK ASSESSMENT:")
        lines.append("-" * 70)
        lines.append(f"Overall Risk Level: {scan_result.risk_level.upper()}")
        lines.append(f"Risk Score: {scan_result.risk_score:.2%}")
        lines.append("")

        # Ban/Restriction Status
        lines.append("BAN AND RESTRICTION STATUS:")
        lines.append("-" * 70)
        ban_flags = []
        if steam.vac_banned:
            ban_flags.append(
                f"VAC BANNED: Yes ({steam.vac_ban_count} ban(s), "
                f"{steam.days_since_last_ban} days since last ban if available)"
            )
        else:
            ban_flags.append("VAC BAN: No")

        if steam.trade_ban:
            ban_flags.append("TRADE BAN: Yes - Account restricted from trading")
        else:
            ban_flags.append("TRADE BAN: No")

        if steam.community_banned:
            ban_flags.append("COMMUNITY BAN: Yes - Account suspended from community")
        else:
            ban_flags.append("COMMUNITY BAN: No")

        if steam.economy_ban:
            ban_flags.append(f"ECONOMY BAN: {steam.economy_ban}")

        for flag in ban_flags:
            lines.append(f"  • {flag}")
        lines.append("")

        # Reputation
        lines.append("REPUTATION INDICATORS:")
        lines.append("-" * 70)
        if steam.steamrep_status == "scammer":
            lines.append("STEAMREP STATUS: FLAGGED AS SCAMMER")
        elif steam.steamrep_status == "trusted":
            lines.append("STEAMREP STATUS: Trusted trader")
        else:
            lines.append(f"STEAMREP STATUS: {steam.steamrep_status}")

        lines.append(f"Games Owned: {steam.game_count}")
        lines.append(f"Friend Count: {steam.friend_count}")
        lines.append(f"Profile Visibility: {steam.visibility}")
        lines.append("")

        # Reason for Report
        lines.append("REASON FOR REPORT:")
        lines.append("-" * 70)
        reasons = self._build_report_reasons(steam, scan_result)
        for reason in reasons:
            lines.append(f"  • {reason}")
        lines.append("")

        # Additional Evidence
        if scan_result.web_results:
            lines.append("ASSOCIATED WEBSITE EVIDENCE:")
            lines.append("-" * 70)
            lines.append(f"Website: {scan_result.target}")
            lines.append(f"Website Risk Level: {scan_result.risk_level.upper()}")
            lines.append("")

        # Instructions
        lines.append("INSTRUCTIONS:")
        lines.append("-" * 70)
        lines.append("1. Visit: https://support.steampowered.com/")
        lines.append("2. Click 'Report a Player'")
        lines.append("3. Enter Steam ID: " + steam.steam_id)
        lines.append("4. Select appropriate violation category")
        lines.append("5. Include evidence from this report")
        lines.append("6. Submit for review")
        lines.append("")

        lines.append("=" * 70)
        lines.append("End of Steam Report")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _build_report_reasons(self, steam, scan_result) -> list[str]:
        """Build list of reasons for the report.

        Args:
            steam: Steam profile data
            scan_result: Complete scan result

        Returns:
            List of report reasons
        """
        reasons = []

        if steam.steamrep_status == "scammer":
            reasons.append("Account flagged as scammer on SteamRep database")

        if steam.vac_banned:
            reasons.append(
                f"Account has {steam.vac_ban_count} VAC ban(s) "
                "indicating history of cheating"
            )

        if steam.trade_ban:
            reasons.append(
                "Account is trade banned, indicating history of suspicious "
                "trading activity"
            )

        if steam.community_banned:
            reasons.append(
                "Account is suspended from community, indicating violation "
                "of Steam Community Rules"
            )

        if steam.game_count < 5 and steam.account_created:
            age_days = (
                scan_result.scan_timestamp - steam.account_created
            ).days
            if age_days < 30:
                reasons.append(
                    f"New account ({age_days} days old) with very few games "
                    "- pattern of account farming or fraud"
                )

        if steam.visibility == "private":
            reasons.append(
                "Profile is completely private, limiting transparency "
                "and verification"
            )

        if not reasons:
            reasons.append("Account exhibits characteristics consistent with fraud")

        return reasons


class DiscordReportFormatter:
    """Formatter for Discord Trust & Safety reports.

    Generates formatted text for reporting suspicious or fraudulent Discord
    accounts to Discord's Trust & Safety team.

    Example:
        >>> formatter = DiscordReportFormatter()
        >>> report_text = formatter.format(scan_result)
        >>> print(report_text)
    """

    def format(self, scan_result: ScanResult) -> str:
        """Format scan result for Discord Trust & Safety report.

        Generates pre-filled text suitable for Discord report form
        with complete evidence of fraudulent activity.

        Args:
            scan_result: ScanResult containing Discord evidence

        Returns:
            Formatted text for Discord report submission

        Raises:
            ValueError: If scan_result lacks Discord data or target
        """
        if not scan_result or not scan_result.target:
            raise ValueError("scan_result must have valid target")

        if not scan_result.gaming_results or not scan_result.gaming_results.discord_user:
            raise ValueError("scan_result must contain Discord user data")

        discord = scan_result.gaming_results.discord_user
        lines = []

        # Header
        lines.append("=" * 70)
        lines.append("DISCORD TRUST & SAFETY REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Report Details
        lines.append("REPORT INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"Date: {scan_result.scan_timestamp.strftime('%Y-%m-%d')}")
        lines.append(f"Report ID: {scan_result.scan_id}")
        lines.append("")

        # User Information
        lines.append("USER INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"Discord ID: {discord.user_id}")
        lines.append(f"Username: {discord.username}")
        if discord.discriminator:
            lines.append(f"Discriminator: {discord.discriminator}")
        if discord.account_created:
            lines.append(f"Account Created: {discord.account_created.strftime('%Y-%m-%d')}")
        lines.append(f"Bot Account: {'Yes' if discord.bot else 'No'}")
        lines.append("")

        # Risk Assessment
        lines.append("RISK ASSESSMENT:")
        lines.append("-" * 70)
        lines.append(f"Overall Risk Level: {scan_result.risk_level.upper()}")
        lines.append(f"Risk Score: {scan_result.risk_score:.2%}")
        lines.append("")

        # Scam Indicators
        lines.append("DETECTED SCAM PATTERNS:")
        lines.append("-" * 70)
        if discord.known_scam_patterns:
            for pattern in discord.known_scam_patterns:
                lines.append(f"  • {pattern}")
        else:
            lines.append("  • No specific scam patterns detected")
        lines.append("")

        # Account Flags
        lines.append("ACCOUNT FLAGS:")
        lines.append("-" * 70)
        lines.append(f"Mutual Guilds: {discord.mutual_guilds_count}")
        lines.append(f"User Flags: {discord.flags}")
        lines.append(f"Public Flags: {discord.public_flags}")
        lines.append("")

        # Associated Website
        if scan_result.web_results:
            lines.append("ASSOCIATED WEBSITE:")
            lines.append("-" * 70)
            lines.append(f"URL: {scan_result.target}")
            lines.append(f"Website Risk Level: {scan_result.risk_level.upper()}")
            lines.append("")

        # Report Category
        lines.append("REPORT CATEGORY:")
        lines.append("-" * 70)
        lines.append("Violation Type: Scam / Fraud / Phishing")
        lines.append("")

        # Description
        lines.append("INCIDENT DESCRIPTION:")
        lines.append("-" * 70)
        lines.append(
            "This Discord user is suspected of fraudulent activity or scamming. "
            "Account exhibits indicators of potential account farming, "
            "social engineering, or marketplace fraud."
        )
        if discord.known_scam_patterns:
            lines.append(f"Detected patterns: {', '.join(discord.known_scam_patterns)}")
        lines.append("")

        # Instructions
        lines.append("HOW TO REPORT:")
        lines.append("-" * 70)
        lines.append("1. On the user's profile, click the three dots menu")
        lines.append("2. Select 'Report User'")
        lines.append("3. Enter Discord ID: " + discord.user_id)
        lines.append("4. Select reason: Scam/Fraud")
        lines.append("5. Include details from this report")
        lines.append("6. Optionally attach evidence")
        lines.append("")
        lines.append("OR")
        lines.append("")
        lines.append("1. Visit: https://dis.gd/report")
        lines.append("2. Fill out the report form")
        lines.append("3. Include user ID and evidence")
        lines.append("4. Submit for Discord Trust & Safety review")
        lines.append("")

        lines.append("=" * 70)
        lines.append("End of Discord Report")
        lines.append("=" * 70)

        return "\n".join(lines)


class XboxReportFormatter:
    """Formatter for Xbox Live enforcement reports.

    Generates formatted text for reporting suspicious Xbox Live
    accounts to Microsoft's Xbox Enforcement team.

    Example:
        >>> formatter = XboxReportFormatter()
        >>> report_text = formatter.format(scan_result)
        >>> print(report_text)
    """

    def format(self, scan_result: ScanResult) -> str:
        """Format scan result for Xbox enforcement report.

        Generates pre-filled text suitable for Xbox report form.

        Args:
            scan_result: ScanResult containing gaming evidence

        Returns:
            Formatted text for Xbox enforcement report

        Raises:
            ValueError: If scan_result lacks required data
        """
        if not scan_result or not scan_result.target:
            raise ValueError("scan_result must have valid target")

        lines = []

        # Header
        lines.append("=" * 70)
        lines.append("XBOX LIVE ENFORCEMENT REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Report Details
        lines.append("REPORT INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"Date: {scan_result.scan_timestamp.strftime('%Y-%m-%d')}")
        lines.append(f"Report ID: {scan_result.scan_id}")
        lines.append("")

        # Gamertag Information
        lines.append("GAMERTAG INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"Gamertag: {scan_result.target}")
        lines.append("")

        # Risk Assessment
        lines.append("RISK ASSESSMENT:")
        lines.append("-" * 70)
        lines.append(f"Risk Level: {scan_result.risk_level.upper()}")
        lines.append(f"Risk Score: {scan_result.risk_score:.2%}")
        if scan_result.risk_factors:
            lines.append("Risk Factors:")
            for factor in scan_result.risk_factors:
                lines.append(f"  • {factor.replace('_', ' ').title()}")
        lines.append("")

        # Associated Website
        if scan_result.web_results:
            lines.append("ASSOCIATED WEBSITE:")
            lines.append("-" * 70)
            lines.append(f"URL: {scan_result.target}")
            lines.append(f"Website Risk Level: {scan_result.risk_level.upper()}")
            lines.append("")

        # Report Category
        lines.append("VIOLATION CATEGORY:")
        lines.append("-" * 70)
        lines.append("Type: Fraud / Scam / Account Compromised")
        lines.append("")

        # Description
        lines.append("INCIDENT DESCRIPTION:")
        lines.append("-" * 70)
        lines.append(
            "Xbox Live account or associated website shows indicators of "
            "fraudulent activity, account farming, or scamming behavior."
        )
        lines.append("")

        # Instructions
        lines.append("HOW TO REPORT:")
        lines.append("-" * 70)
        lines.append("1. Visit: https://enforcement.xbox.com/")
        lines.append(f"2. Search for gamertag: {scan_result.target}")
        lines.append("3. Click 'Report'")
        lines.append("4. Select violation reason")
        lines.append("5. Provide evidence and context")
        lines.append("6. Submit report")
        lines.append("")
        lines.append("For website fraud reports:")
        lines.append("1. Include website URL in description")
        lines.append("2. Explain connection to Xbox account")
        lines.append("3. Provide evidence of fraudulent activity")
        lines.append("")

        lines.append("=" * 70)
        lines.append("End of Xbox Report")
        lines.append("=" * 70)

        return "\n".join(lines)


class PsnReportFormatter:
    """Formatter for PSN (PlayStation Network) reports.

    Generates formatted text for reporting suspicious PSN
    accounts to Sony's Trust & Safety team.

    Example:
        >>> formatter = PsnReportFormatter()
        >>> report_text = formatter.format(scan_result)
        >>> print(report_text)
    """

    def format(self, scan_result: ScanResult) -> str:
        """Format scan result for PSN report submission.

        Generates pre-filled text suitable for PSN report form.

        Args:
            scan_result: ScanResult containing gaming evidence

        Returns:
            Formatted text for PSN report

        Raises:
            ValueError: If scan_result lacks required data
        """
        if not scan_result or not scan_result.target:
            raise ValueError("scan_result must have valid target")

        lines = []

        # Header
        lines.append("=" * 70)
        lines.append("PLAYSTATION NETWORK REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Report Details
        lines.append("REPORT INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"Date: {scan_result.scan_timestamp.strftime('%Y-%m-%d')}")
        lines.append(f"Report ID: {scan_result.scan_id}")
        lines.append("")

        # Account Information
        lines.append("ACCOUNT INFORMATION:")
        lines.append("-" * 70)
        lines.append(f"PSN Username: {scan_result.target}")
        lines.append("")

        # Risk Assessment
        lines.append("RISK ASSESSMENT:")
        lines.append("-" * 70)
        lines.append(f"Risk Level: {scan_result.risk_level.upper()}")
        lines.append(f"Risk Score: {scan_result.risk_score:.2%}")
        if scan_result.risk_factors:
            lines.append("Risk Factors:")
            for factor in scan_result.risk_factors:
                lines.append(f"  • {factor.replace('_', ' ').title()}")
        lines.append("")

        # Associated Website
        if scan_result.web_results:
            lines.append("ASSOCIATED WEBSITE:")
            lines.append("-" * 70)
            lines.append(f"URL: {scan_result.target}")
            lines.append(f"Website Risk Level: {scan_result.risk_level.upper()}")
            lines.append("")

        # Violation Category
        lines.append("VIOLATION CATEGORY:")
        lines.append("-" * 70)
        lines.append("Type: Fraud / Scam / Suspicious Activity")
        lines.append("")

        # Description
        lines.append("INCIDENT DESCRIPTION:")
        lines.append("-" * 70)
        lines.append(
            "PSN account shows indicators of fraudulent activity or "
            "involvement in scamming. Associated website/infrastructure "
            "also exhibits suspicious characteristics."
        )
        lines.append("")

        # Instructions
        lines.append("HOW TO REPORT:")
        lines.append("-" * 70)
        lines.append("1. On the user's PSN profile, select options menu")
        lines.append(f"2. Select 'Report Player' or 'Report Account'")
        lines.append(f"3. Username: {scan_result.target}")
        lines.append("4. Select reason: Fraud / Scam")
        lines.append("5. Provide details from this report")
        lines.append("6. Submit to PlayStation Network Trust & Safety")
        lines.append("")
        lines.append("Or visit: https://www.playstation.com/en-us/support/")
        lines.append("")

        lines.append("=" * 70)
        lines.append("End of PSN Report")
        lines.append("=" * 70)

        return "\n".join(lines)
