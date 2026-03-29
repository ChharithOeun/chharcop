"""Professional PDF evidence report generation.

Generates chain-of-custody compliant evidence reports using ReportLab
with comprehensive scan results, risk assessment, and forensic data.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

from chharcop.evidence.hash_chain import EvidenceHasher
from chharcop.models import ScanResult


class ChharcpPDFReport:
    """Professional PDF evidence report generator.

    Generates comprehensive multi-page PDF reports with evidence data,
    risk assessment, and chain-of-custody information suitable for
    forensic documentation and agency reporting.

    Example:
        >>> reporter = ChharcpPDFReport()
        >>> report_path = reporter.generate(
        ...     scan_result=scan_result,
        ...     output_path=Path("/path/to/report.pdf")
        ... )
    """

    # Color scheme
    HEADER_COLOR = "#1a237e"  # Dark blue
    ACCENT_COLOR = "#0d47a1"  # Medium blue
    TABLE_BG_COLOR = "#f5f5f5"  # Light gray
    TEXT_COLOR = "#212121"  # Dark gray
    BORDER_COLOR = "#bdbdbd"  # Medium gray
    RISK_CRITICAL = "#c62828"  # Red
    RISK_HIGH = "#f57c00"  # Orange
    RISK_MEDIUM = "#fbc02d"  # Amber
    RISK_LOW = "#388e3c"  # Green

    def __init__(self):
        """Initialize PDF report generator."""
        self.hasher = EvidenceHasher()
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()

    def _add_custom_styles(self) -> None:
        """Add custom paragraph styles for report."""
        self.styles.add(
            ParagraphStyle(
                name="CustomHeading1",
                parent=self.styles["Heading1"],
                fontSize=24,
                textColor=self.HEADER_COLOR,
                spaceAfter=12,
                alignment=TA_CENTER,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="CustomHeading2",
                parent=self.styles["Heading2"],
                fontSize=14,
                textColor=self.ACCENT_COLOR,
                spaceAfter=10,
                spaceBefore=6,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="CustomBody",
                parent=self.styles["BodyText"],
                fontSize=10,
                textColor=self.TEXT_COLOR,
                leading=14,
            )
        )

    def generate(self, scan_result: ScanResult, output_path: Path) -> Path:
        """Generate comprehensive PDF evidence report.

        Creates a professional multi-page PDF with complete scan results,
        risk assessment, and chain-of-custody documentation.

        Args:
            scan_result: ScanResult containing all collected evidence
            output_path: Path where PDF should be written

        Returns:
            Path to generated PDF file

        Raises:
            ValueError: If scan_result is invalid or incomplete
            PermissionError: If output directory is not writable
            IOError: If PDF cannot be written
        """
        if not scan_result or not scan_result.scan_id:
            raise ValueError("scan_result must have valid scan_id")

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Create document
            doc = SimpleDocTemplate(
                str(output_path),
                pagesize=LETTER,
                rightMargin=0.75 * inch,
                leftMargin=0.75 * inch,
                topMargin=0.75 * inch,
                bottomMargin=0.75 * inch,
            )

            # Build story (content)
            story = []
            story.extend(self._build_cover_page(scan_result))
            story.append(PageBreak())
            story.extend(self._build_executive_summary(scan_result))
            story.append(PageBreak())

            if scan_result.web_results:
                if scan_result.web_results.whois_data:
                    story.extend(self._build_whois_section(scan_result.web_results))
                    story.append(PageBreak())

                if scan_result.web_results.dns_data:
                    story.extend(self._build_dns_section(scan_result.web_results))
                    story.append(PageBreak())

                if scan_result.web_results.ssl_data:
                    story.extend(self._build_ssl_section(scan_result.web_results))
                    story.append(PageBreak())

                if scan_result.web_results.metadata:
                    story.extend(self._build_metadata_section(scan_result.web_results))
                    story.append(PageBreak())

            if scan_result.gaming_results:
                story.extend(self._build_gaming_section(scan_result))
                story.append(PageBreak())

            story.extend(self._build_risk_section(scan_result))
            story.append(PageBreak())
            story.extend(self._build_coc_section(scan_result))

            # Build PDF
            doc.build(story, onFirstPage=self._add_footer, onLaterPages=self._add_footer)

            return output_path

        except PermissionError as e:
            raise PermissionError(f"Cannot write to {output_path}: {e}") from e
        except IOError as e:
            raise IOError(f"Failed to generate PDF: {e}") from e

    def _add_footer(self, canvas, doc):
        """Add footer to every page with generation info and page number.

        Args:
            canvas: ReportLab canvas
            doc: Document object
        """
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)

        footer_text = (
            f"Generated by Chharcop v0.1.0 | "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | "
            f"Page {doc.page} of {doc.page}"
        )

        canvas.drawString(0.75 * inch, 0.5 * inch, footer_text)
        canvas.restoreState()

    def _build_cover_page(self, scan_result: ScanResult) -> list:
        """Build report cover page.

        Args:
            scan_result: Scan results

        Returns:
            List of Platypus elements for cover page
        """
        elements = []

        elements.append(Spacer(1, 1.5 * inch))

        # Title
        title = Paragraph("CHHARCOP EVIDENCE REPORT", self.styles["CustomHeading1"])
        elements.append(title)

        elements.append(Spacer(1, 0.3 * inch))

        # Scan ID
        scan_info = [
            [
                Paragraph("<b>Scan ID:</b>", self.styles["CustomBody"]),
                Paragraph(scan_result.scan_id, self.styles["CustomBody"]),
            ],
            [
                Paragraph("<b>Target:</b>", self.styles["CustomBody"]),
                Paragraph(scan_result.target, self.styles["CustomBody"]),
            ],
            [
                Paragraph("<b>Scan Type:</b>", self.styles["CustomBody"]),
                Paragraph(scan_result.scan_type.upper(), self.styles["CustomBody"]),
            ],
            [
                Paragraph("<b>Date:</b>", self.styles["CustomBody"]),
                Paragraph(
                    scan_result.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    self.styles["CustomBody"],
                ),
            ],
        ]

        scan_table = Table(scan_info, colWidths=[2 * inch, 4 * inch])
        scan_table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LINEABOVE", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.grey),
                ]
            )
        )

        elements.append(scan_table)
        elements.append(Spacer(1, 0.4 * inch))

        # Risk badge
        risk_colors = {
            "critical": self.RISK_CRITICAL,
            "high": self.RISK_HIGH,
            "medium": self.RISK_MEDIUM,
            "low": self.RISK_LOW,
            "unknown": self.BORDER_COLOR,
        }

        risk_color = risk_colors.get(
            scan_result.risk_level.lower(), self.BORDER_COLOR
        )

        risk_text = f"RISK LEVEL: {scan_result.risk_level.upper()}"
        risk_para = Paragraph(risk_text, self.styles["CustomHeading1"])

        elements.append(risk_para)

        return elements

    def _build_executive_summary(self, scan_result: ScanResult) -> list:
        """Build executive summary section.

        Args:
            scan_result: Scan results

        Returns:
            List of Platypus elements
        """
        elements = []

        elements.append(
            Paragraph("EXECUTIVE SUMMARY", self.styles["CustomHeading2"])
        )
        elements.append(Spacer(1, 0.15 * inch))

        # Summary info
        summary = [
            [
                Paragraph("<b>Risk Score:</b>", self.styles["CustomBody"]),
                Paragraph(f"{scan_result.risk_score:.2%}", self.styles["CustomBody"]),
            ],
            [
                Paragraph("<b>Risk Level:</b>", self.styles["CustomBody"]),
                Paragraph(
                    scan_result.risk_level.upper(), self.styles["CustomBody"]
                ),
            ],
        ]

        summary_table = Table(summary, colWidths=[2 * inch, 4 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("BACKGROUND", (0, 0), (-1, -1), self.TABLE_BG_COLOR),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                ]
            )
        )

        elements.append(summary_table)
        elements.append(Spacer(1, 0.2 * inch))

        # Key findings
        if scan_result.risk_factors:
            elements.append(
                Paragraph("<b>Key Risk Factors:</b>", self.styles["CustomBody"])
            )
            for factor in scan_result.risk_factors:
                factor_text = f"• {factor.replace('_', ' ').title()}"
                elements.append(
                    Paragraph(factor_text, self.styles["CustomBody"])
                )
                elements.append(Spacer(1, 0.1 * inch))

        return elements

    def _build_whois_section(self, web_results) -> list:
        """Build WHOIS data section.

        Args:
            web_results: Web scan results

        Returns:
            List of Platypus elements
        """
        elements = []
        elements.append(Paragraph("SECTION 1 - WHOIS DATA", self.styles["CustomHeading2"]))
        elements.append(Spacer(1, 0.15 * inch))

        whois = web_results.whois_data
        if not whois:
            elements.append(
                Paragraph("No WHOIS data available.", self.styles["CustomBody"])
            )
            return elements

        whois_data = [
            ["Field", "Value"],
            ["Domain", whois.domain or "N/A"],
            ["Registrar", whois.registrar or "N/A"],
            ["Registrar URL", whois.registrar_url or "N/A"],
            [
                "Creation Date",
                whois.creation_date.isoformat() if whois.creation_date else "N/A",
            ],
            [
                "Expiration Date",
                whois.expiration_date.isoformat()
                if whois.expiration_date
                else "N/A",
            ],
            ["Days Old", str(whois.days_old) if whois.days_old else "N/A"],
            ["Days Until Expiry", str(whois.days_until_expiry) if whois.days_until_expiry else "N/A"],
            ["Name Servers", ", ".join(whois.name_servers) if whois.name_servers else "N/A"],
            ["Privacy Protected", "Yes" if whois.privacy_protected else "No"],
            ["Registrant Name", whois.registrant_name or "N/A"],
            ["Registrant Organization", whois.registrant_org or "N/A"],
        ]

        whois_table = Table(whois_data, colWidths=[2.5 * inch, 3.5 * inch])
        whois_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), self.HEADER_COLOR),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.TABLE_BG_COLOR]),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                ]
            )
        )

        elements.append(whois_table)
        return elements

    def _build_dns_section(self, web_results) -> list:
        """Build DNS records section.

        Args:
            web_results: Web scan results

        Returns:
            List of Platypus elements
        """
        elements = []
        elements.append(Paragraph("SECTION 2 - DNS RECORDS", self.styles["CustomHeading2"]))
        elements.append(Spacer(1, 0.15 * inch))

        dns = web_results.dns_data
        if not dns:
            elements.append(
                Paragraph("No DNS data available.", self.styles["CustomBody"])
            )
            return elements

        # A Records
        if dns.a_records:
            elements.append(
                Paragraph("<b>A Records (IPv4):</b>", self.styles["CustomBody"])
            )
            a_table_data = [["Address"]] + [[addr] for addr in dns.a_records]
            a_table = Table(a_table_data, colWidths=[6 * inch])
            a_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), self.HEADER_COLOR),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.TABLE_BG_COLOR]),
                        ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                    ]
                )
            )
            elements.append(a_table)
            elements.append(Spacer(1, 0.15 * inch))

        # MX Records
        if dns.mx_records:
            elements.append(
                Paragraph("<b>MX Records (Mail):</b>", self.styles["CustomBody"])
            )
            mx_table_data = [["Priority", "Value"]] + [
                [str(rec.priority or "N/A"), rec.value] for rec in dns.mx_records
            ]
            mx_table = Table(mx_table_data, colWidths=[1.5 * inch, 4.5 * inch])
            mx_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), self.HEADER_COLOR),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.TABLE_BG_COLOR]),
                        ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                    ]
                )
            )
            elements.append(mx_table)
            elements.append(Spacer(1, 0.15 * inch))

        # NS Records
        if dns.ns_records:
            elements.append(
                Paragraph("<b>NS Records (Nameservers):</b>", self.styles["CustomBody"])
            )
            ns_table_data = [["Nameserver"]] + [[ns] for ns in dns.ns_records]
            ns_table = Table(ns_table_data, colWidths=[6 * inch])
            ns_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), self.HEADER_COLOR),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.TABLE_BG_COLOR]),
                        ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                    ]
                )
            )
            elements.append(ns_table)

        return elements

    def _build_ssl_section(self, web_results) -> list:
        """Build SSL certificate section.

        Args:
            web_results: Web scan results

        Returns:
            List of Platypus elements
        """
        elements = []
        elements.append(
            Paragraph("SECTION 3 - SSL CERTIFICATE", self.styles["CustomHeading2"])
        )
        elements.append(Spacer(1, 0.15 * inch))

        ssl = web_results.ssl_data
        if not ssl:
            elements.append(
                Paragraph("No SSL data available.", self.styles["CustomBody"])
            )
            return elements

        ssl_data = [
            ["Field", "Value"],
            ["Domain", ssl.domain or "N/A"],
            ["Valid", "Yes" if ssl.is_valid else "No"],
            ["Certificate Type", ssl.cert_type or "Unknown"],
            ["Self-Signed", "Yes" if ssl.is_self_signed else "No"],
            [
                "Valid From",
                ssl.not_valid_before.isoformat() if ssl.not_valid_before else "N/A",
            ],
            [
                "Valid Until",
                ssl.not_valid_after.isoformat() if ssl.not_valid_after else "N/A",
            ],
            ["Days Until Expiry", str(ssl.days_until_expiry) if ssl.days_until_expiry else "N/A"],
            ["Signature Algorithm", ssl.signature_algorithm or "N/A"],
            ["Serial Number", ssl.serial_number or "N/A"],
            ["Issuer", str(ssl.issuer) if ssl.issuer else "N/A"],
        ]

        ssl_table = Table(ssl_data, colWidths=[2.5 * inch, 3.5 * inch])
        ssl_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), self.HEADER_COLOR),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.TABLE_BG_COLOR]),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                ]
            )
        )

        elements.append(ssl_table)
        return elements

    def _build_metadata_section(self, web_results) -> list:
        """Build site metadata section.

        Args:
            web_results: Web scan results

        Returns:
            List of Platypus elements
        """
        elements = []
        elements.append(
            Paragraph("SECTION 4 - SITE METADATA", self.styles["CustomHeading2"])
        )
        elements.append(Spacer(1, 0.15 * inch))

        meta = web_results.metadata
        if not meta:
            elements.append(
                Paragraph("No metadata available.", self.styles["CustomBody"])
            )
            return elements

        metadata = [
            ["Field", "Value"],
            ["URL", meta.url or "N/A"],
            ["Title", meta.title or "N/A"],
            ["Description", meta.description or "N/A"],
            ["Status Code", str(meta.status_code) if meta.status_code else "N/A"],
            ["Server", meta.server_header or "N/A"],
            ["Response Time (ms)", str(meta.response_time_ms) if meta.response_time_ms else "N/A"],
            ["Has Privacy Policy", "Yes" if meta.has_privacy_policy else "No"],
            ["Has Terms of Service", "Yes" if meta.has_terms_of_service else "No"],
            ["Has Contact Page", "Yes" if meta.has_contact_page else "No"],
            ["Has About Page", "Yes" if meta.has_about_page else "No"],
            ["External Links", str(meta.external_links_count) if meta.external_links_count else "0"],
            ["Technologies", ", ".join(meta.technologies) if meta.technologies else "N/A"],
        ]

        meta_table = Table(metadata, colWidths=[2.5 * inch, 3.5 * inch])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), self.HEADER_COLOR),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.TABLE_BG_COLOR]),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                ]
            )
        )

        elements.append(meta_table)
        return elements

    def _build_gaming_section(self, scan_result: ScanResult) -> list:
        """Build gaming profile section.

        Args:
            scan_result: Scan results

        Returns:
            List of Platypus elements
        """
        elements = []
        elements.append(
            Paragraph(
                "SECTION 5 - GAMING PROFILE INVESTIGATION",
                self.styles["CustomHeading2"],
            )
        )
        elements.append(Spacer(1, 0.15 * inch))

        gaming = scan_result.gaming_results
        if not gaming:
            elements.append(
                Paragraph("No gaming data collected.", self.styles["CustomBody"])
            )
            return elements

        # Steam
        if gaming.steam_profile:
            sp = gaming.steam_profile
            elements.append(
                Paragraph("<b>Steam Profile:</b>", self.styles["CustomBody"])
            )
            steam_data = [
                ["Field", "Value"],
                ["Steam ID", sp.steam_id or "N/A"],
                ["Username", sp.persona_name or "N/A"],
                ["Profile URL", sp.profile_url or "N/A"],
                ["Account Created", sp.account_created.isoformat() if sp.account_created else "N/A"],
                ["Last Logoff", sp.last_logoff.isoformat() if sp.last_logoff else "N/A"],
                ["VAC Banned", "Yes" if sp.vac_banned else "No"],
                ["Trade Banned", "Yes" if sp.trade_banned else "No"],
                ["Community Banned", "Yes" if sp.community_banned else "No"],
                ["SteamRep Status", sp.steamrep_status or "Unknown"],
                ["Game Count", str(sp.game_count) if sp.game_count else "0"],
                ["Friend Count", str(sp.friend_count) if sp.friend_count else "0"],
                ["Account Level", str(sp.level) if sp.level else "0"],
            ]

            steam_table = Table(steam_data, colWidths=[2.5 * inch, 3.5 * inch])
            steam_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), self.HEADER_COLOR),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.TABLE_BG_COLOR]),
                        ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                    ]
                )
            )
            elements.append(steam_table)
            elements.append(Spacer(1, 0.15 * inch))

        # Discord
        if gaming.discord_user:
            du = gaming.discord_user
            elements.append(
                Paragraph("<b>Discord User:</b>", self.styles["CustomBody"])
            )
            discord_data = [
                ["Field", "Value"],
                ["Discord ID", du.user_id or "N/A"],
                ["Username", du.username or "N/A"],
                ["Account Created", du.account_created.isoformat() if du.account_created else "N/A"],
                ["Bot Account", "Yes" if du.bot else "No"],
                ["Scam Patterns", ", ".join(du.known_scam_patterns) if du.known_scam_patterns else "None detected"],
            ]

            discord_table = Table(discord_data, colWidths=[2.5 * inch, 3.5 * inch])
            discord_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), self.HEADER_COLOR),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.TABLE_BG_COLOR]),
                        ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                    ]
                )
            )
            elements.append(discord_table)

        return elements

    def _build_risk_section(self, scan_result: ScanResult) -> list:
        """Build risk assessment section.

        Args:
            scan_result: Scan results

        Returns:
            List of Platypus elements
        """
        elements = []
        elements.append(
            Paragraph("SECTION 6 - RISK ASSESSMENT", self.styles["CustomHeading2"])
        )
        elements.append(Spacer(1, 0.15 * inch))

        risk_data = [
            ["Risk Factor", "Description"],
        ]

        risk_descriptions = {
            "new_domain": "Domain registered less than 30 days ago",
            "recently_created": "Domain registered less than 180 days ago",
            "self_signed_cert": "Uses self-signed SSL certificate instead of trusted CA",
            "invalid_cert": "SSL certificate is expired or invalid",
            "unknown_cert_type": "Certificate type could not be verified",
            "missing_trust_signals": "Missing 3+ trust signals (privacy policy, ToS, contact, about)",
            "suspicious_redirects": "More than 2 redirects in URL chain",
            "vac_banned": "Steam account has VAC (anti-cheat) bans",
            "trade_banned": "Steam account is trade banned",
            "community_banned": "Steam account is community banned",
            "steamrep_flagged": "Flagged as scammer on SteamRep",
            "new_account_few_games": "New account with fewer than 5 games",
            "private_profile": "Private Steam profile limits visibility",
            "discord_scam_patterns": "Known scam patterns detected on Discord",
        }

        for factor in scan_result.risk_factors:
            description = risk_descriptions.get(
                factor, "Risk factor identified"
            )
            risk_data.append([factor.replace("_", " ").title(), description])

        if len(risk_data) == 1:
            risk_data.append(["None", "No risk factors identified"])

        risk_table = Table(risk_data, colWidths=[2 * inch, 4 * inch])
        risk_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), self.HEADER_COLOR),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.TABLE_BG_COLOR]),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                ]
            )
        )

        elements.append(risk_table)
        return elements

    def _build_coc_section(self, scan_result: ScanResult) -> list:
        """Build chain-of-custody section with integrity hashes.

        Args:
            scan_result: Scan results

        Returns:
            List of Platypus elements
        """
        elements = []
        elements.append(
            Paragraph("SECTION 7 - CHAIN OF CUSTODY", self.styles["CustomHeading2"])
        )
        elements.append(Spacer(1, 0.15 * inch))

        coc_data = [["Evidence Item", "SHA-256 Hash", "Timestamp"]]

        # Add scan result hash
        scan_hash = self.hasher.hash_string(scan_result.json())
        coc_data.append([
            "Scan Result",
            scan_hash[:32] + "...",
            scan_result.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        ])

        # Add evidence hashes if present
        for name, evidence_hash in scan_result.evidence_hashes.items():
            coc_data.append([
                name,
                evidence_hash.value[:32] + "...",
                scan_result.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            ])

        coc_table = Table(coc_data, colWidths=[1.5 * inch, 3 * inch, 1.5 * inch])
        coc_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), self.HEADER_COLOR),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 9),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.TABLE_BG_COLOR]),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.BORDER_COLOR),
                ]
            )
        )

        elements.append(coc_table)
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(
            Paragraph(
                "<b>Full SHA-256 Hash:</b>",
                self.styles["CustomBody"],
            )
        )
        elements.append(Spacer(1, 0.08 * inch))
        elements.append(
            Paragraph(
                scan_hash,
                ParagraphStyle(
                    name="HashCode",
                    parent=self.styles["BodyText"],
                    fontName="Courier",
                    fontSize=8,
                    textColor=self.TEXT_COLOR,
                ),
            )
        )

        return elements
