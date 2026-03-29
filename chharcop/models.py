"""
Pydantic models for Chharcop.

Central data structures for evidence collection, scanning results, and reporting.
Includes models for web (WHOIS, DNS, SSL) and gaming (Steam, Discord) data.
"""

from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import Any, Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk assessment levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class CollectorError(BaseModel):
    """Error details from a collector."""

    collector: str = Field(..., description="Name of the collector that failed")
    error_type: str = Field(..., description="Type of error (e.g., 'ConnectionError')")
    error_message: str = Field(..., description="Human-readable error message")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True


class EvidenceHash(BaseModel):
    """Hash of evidence data for integrity verification."""

    algorithm: str = Field(default="sha256", description="Hash algorithm used")
    value: str = Field(..., description="Hash value in hexadecimal")

    @staticmethod
    def compute_sha256(data: str) -> str:
        """Compute SHA256 hash of data.

        Args:
            data: String data to hash

        Returns:
            Hexadecimal hash value
        """
        return sha256(data.encode()).hexdigest()


class WhoisData(BaseModel):
    """WHOIS domain registration data."""

    domain: str = Field(..., description="Domain name")
    registrar: Optional[str] = Field(None, description="Domain registrar")
    registrar_url: Optional[str] = Field(None, description="Registrar website")
    creation_date: Optional[datetime] = Field(None, description="Domain creation date")
    expiration_date: Optional[datetime] = Field(None, description="Domain expiration date")
    updated_date: Optional[datetime] = Field(None, description="Last update date")
    name_servers: list[str] = Field(default_factory=list, description="Authoritative name servers")
    registrant_name: Optional[str] = Field(None, description="Registrant name (may be private)")
    registrant_email: Optional[str] = Field(None, description="Registrant email (may be private)")
    registrant_org: Optional[str] = Field(None, description="Registrant organization")
    privacy_protected: bool = Field(
        default=False, description="Whether domain uses privacy protection"
    )
    days_old: Optional[int] = Field(None, description="Age of domain in days")
    days_until_expiry: Optional[int] = Field(None, description="Days until expiration")


class DnsRecord(BaseModel):
    """Single DNS record entry."""

    record_type: str = Field(..., description="DNS record type (A, AAAA, MX, etc.)")
    value: str = Field(..., description="Record value/target")
    priority: Optional[int] = Field(None, description="Priority (for MX records)")
    ttl: Optional[int] = Field(None, description="Time to live in seconds")


class DnsData(BaseModel):
    """DNS resolution and records data."""

    domain: str = Field(..., description="Domain queried")
    a_records: list[str] = Field(default_factory=list, description="IPv4 addresses")
    aaaa_records: list[str] = Field(default_factory=list, description="IPv6 addresses")
    mx_records: list[DnsRecord] = Field(default_factory=list, description="Mail exchange records")
    ns_records: list[str] = Field(default_factory=list, description="Nameserver records")
    txt_records: list[str] = Field(default_factory=list, description="Text records (SPF, DKIM, etc.)")
    cname_records: list[DnsRecord] = Field(default_factory=list, description="CNAME records")
    soa_record: Optional[str] = Field(None, description="SOA record")
    query_timestamp: datetime = Field(default_factory=datetime.utcnow)


class SslData(BaseModel):
    """SSL/TLS certificate data."""

    domain: str = Field(..., description="Domain for certificate")
    subject: dict[str, str] = Field(default_factory=dict, description="Certificate subject")
    issuer: dict[str, str] = Field(default_factory=dict, description="Certificate issuer")
    not_valid_before: Optional[datetime] = Field(None, description="Certificate valid from date")
    not_valid_after: Optional[datetime] = Field(None, description="Certificate valid to date")
    serial_number: Optional[str] = Field(None, description="Certificate serial number")
    version: Optional[int] = Field(None, description="X.509 certificate version")
    signature_algorithm: Optional[str] = Field(None, description="Signature algorithm")
    is_self_signed: bool = Field(default=False, description="Whether certificate is self-signed")
    cert_type: str = Field(
        default="unknown", description="Certificate type (DV, OV, EV, unknown)"
    )
    is_valid: bool = Field(default=False, description="Whether certificate is currently valid")
    days_until_expiry: Optional[int] = Field(None, description="Days until expiration")
    certificate_pem: Optional[str] = Field(None, description="PEM-encoded certificate")


class SiteMetadata(BaseModel):
    """Website metadata and analysis."""

    url: str = Field(..., description="Website URL analyzed")
    title: Optional[str] = Field(None, description="Page title")
    description: Optional[str] = Field(None, description="Meta description")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    redirect_chain: list[str] = Field(default_factory=list, description="Redirect URLs")
    technologies: list[str] = Field(default_factory=list, description="Detected technologies")
    has_privacy_policy: bool = Field(default=False, description="Has privacy policy link")
    has_terms_of_service: bool = Field(default=False, description="Has ToS link")
    has_contact_page: bool = Field(default=False, description="Has contact information")
    has_about_page: bool = Field(default=False, description="Has about page")
    external_links_count: int = Field(default=0, description="Number of external links")
    response_time_ms: Optional[float] = Field(None, description="Response time in milliseconds")
    server_header: Optional[str] = Field(None, description="Server header value")
    query_timestamp: datetime = Field(default_factory=datetime.utcnow)


class SteamProfile(BaseModel):
    """Steam gaming profile data."""

    steam_id: str = Field(..., description="Steam ID (64-bit)")
    persona_name: str = Field(..., description="Display name")
    profile_url: str = Field(..., description="Profile URL")
    avatar_url: Optional[str] = Field(None, description="Avatar image URL")
    account_created: Optional[datetime] = Field(None, description="Account creation date")
    last_logoff: Optional[datetime] = Field(None, description="Last logoff timestamp")
    visibility: str = Field(default="private", description="Profile visibility setting")
    vac_banned: bool = Field(default=False, description="VAC ban status")
    vac_ban_count: int = Field(default=0, description="Number of VAC bans")
    days_since_last_ban: Optional[int] = Field(None, description="Days since last VAC ban")
    trade_ban: bool = Field(default=False, description="Trade ban status")
    community_banned: bool = Field(default=False, description="Community ban status")
    economy_ban: Optional[str] = Field(None, description="Economy ban type if any")
    steamrep_status: str = Field(
        default="unknown", description="SteamRep status (scammer, trusted, unknown)"
    )
    game_count: int = Field(default=0, description="Number of owned games")
    friend_count: int = Field(default=0, description="Number of friends")
    level: int = Field(default=0, description="Steam account level")
    primary_group: Optional[str] = Field(None, description="Primary group name")
    custom_url: Optional[str] = Field(None, description="Custom profile URL")


class DiscordUser(BaseModel):
    """Discord user account data."""

    user_id: str = Field(..., description="Discord user ID")
    username: str = Field(..., description="Username")
    discriminator: Optional[str] = Field(None, description="User discriminator (#0000)")
    avatar_url: Optional[str] = Field(None, description="Avatar image URL")
    account_created: Optional[datetime] = Field(None, description="Account creation date")
    flags: int = Field(default=0, description="User flags bitmask")
    public_flags: int = Field(default=0, description="Public flags bitmask")
    bot: bool = Field(default=False, description="Whether account is a bot")
    system: bool = Field(default=False, description="Whether account is a system account")
    mutual_guilds_count: int = Field(default=0, description="Number of shared servers")
    known_scam_patterns: list[str] = Field(
        default_factory=list, description="Detected scam patterns"
    )


class GamertagResult(BaseModel):
    """Cross-platform gamertag search result."""

    gamertag: str = Field(..., description="Searched gamertag/username")
    platform: str = Field(..., description="Platform found on")
    found: bool = Field(default=False, description="Whether gamertag exists")
    profile_url: Optional[str] = Field(None, description="Profile URL")
    verified: bool = Field(default=False, description="Whether profile verified")


class PsnProfile(BaseModel):
    """PlayStation Network profile data."""

    psn_id: str = Field(..., description="PSN account ID")
    username: str = Field(..., description="Display name")
    avatar_url: Optional[str] = Field(None, description="Avatar URL")
    profile_url: str = Field(..., description="Profile URL")
    account_created: Optional[datetime] = Field(None, description="Account creation date")


class XboxProfile(BaseModel):
    """Xbox Live profile data."""

    xbox_id: str = Field(..., description="Xbox account ID")
    gamertag: str = Field(..., description="Gamertag")
    avatar_url: Optional[str] = Field(None, description="Avatar URL")
    profile_url: str = Field(..., description="Profile URL")
    account_created: Optional[datetime] = Field(None, description="Account creation date")


class EpicProfile(BaseModel):
    """Epic Games profile data."""

    epic_id: str = Field(..., description="Epic account ID")
    display_name: str = Field(..., description="Display name")
    avatar_url: Optional[str] = Field(None, description="Avatar URL")
    profile_url: str = Field(..., description="Profile URL")


class CrossPlatformMatch(BaseModel):
    """Cross-platform identity correlation."""

    primary_identifier: str = Field(..., description="Primary identifier (e.g., Steam ID)")
    matched_platforms: list[str] = Field(default_factory=list, description="Platforms with matches")
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Match confidence score"
    )
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class WebScanResult(BaseModel):
    """Results from website-based evidence collection."""

    url: str = Field(..., description="URL scanned")
    whois_data: Optional[WhoisData] = Field(None, description="WHOIS results")
    dns_data: Optional[DnsData] = Field(None, description="DNS results")
    ssl_data: Optional[SslData] = Field(None, description="SSL certificate results")
    metadata: Optional[SiteMetadata] = Field(None, description="Website metadata")
    errors: list[CollectorError] = Field(default_factory=list, description="Collection errors")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)


class GamingScanResult(BaseModel):
    """Results from gaming platform evidence collection."""

    target_identifier: str = Field(..., description="Gaming account identifier")
    platform: str = Field(..., description="Gaming platform (steam, discord, etc.)")
    steam_profile: Optional[SteamProfile] = Field(None, description="Steam profile data")
    discord_user: Optional[DiscordUser] = Field(None, description="Discord user data")
    cross_platform_matches: list[GamertagResult] = Field(
        default_factory=list, description="Matches on other platforms"
    )
    errors: list[CollectorError] = Field(default_factory=list, description="Collection errors")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanResult(BaseModel):
    """Complete scan result combining web and gaming evidence."""

    scan_id: str = Field(..., description="Unique scan identifier")
    target: str = Field(..., description="Primary target (URL, Steam ID, Discord ID, etc.)")
    scan_type: str = Field(..., description="Type of scan (website, steam, discord, gamertag, full)")
    risk_level: RiskLevel = Field(default=RiskLevel.UNKNOWN, description="Overall risk assessment")
    risk_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Numerical risk score"
    )
    risk_factors: list[str] = Field(default_factory=list, description="Identified risk factors")
    web_results: Optional[WebScanResult] = Field(None, description="Website scan results")
    gaming_results: Optional[GamingScanResult] = Field(None, description="Gaming scan results")
    correlation_notes: list[str] = Field(
        default_factory=list, description="Notes on cross-platform correlations"
    )
    overall_errors: list[CollectorError] = Field(default_factory=list, description="Overall errors")
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    evidence_hashes: dict[str, EvidenceHash] = Field(
        default_factory=dict, description="Integrity hashes of evidence"
    )

    class Config:
        use_enum_values = True

    def calculate_risk_score(self) -> None:
        """Calculate overall risk score and level based on collected data."""
        factors: dict[str, float] = {}

        if self.web_results:
            # Domain age risk
            if self.web_results.whois_data:
                if self.web_results.whois_data.days_old is not None:
                    if self.web_results.whois_data.days_old < 30:
                        factors["new_domain"] = 0.3
                    elif self.web_results.whois_data.days_old < 180:
                        factors["recently_created"] = 0.15

            # SSL certificate risks
            if self.web_results.ssl_data:
                if self.web_results.ssl_data.is_self_signed:
                    factors["self_signed_cert"] = 0.35
                if not self.web_results.ssl_data.is_valid:
                    factors["invalid_cert"] = 0.4
                if self.web_results.ssl_data.cert_type == "unknown":
                    factors["unknown_cert_type"] = 0.2

            # Metadata risks
            if self.web_results.metadata:
                missing_trust_signals = 0
                if not self.web_results.metadata.has_privacy_policy:
                    missing_trust_signals += 1
                if not self.web_results.metadata.has_terms_of_service:
                    missing_trust_signals += 1
                if not self.web_results.metadata.has_contact_page:
                    missing_trust_signals += 1
                if not self.web_results.metadata.has_about_page:
                    missing_trust_signals += 1

                if missing_trust_signals >= 3:
                    factors["missing_trust_signals"] = 0.25

                if len(self.web_results.metadata.redirect_chain) > 2:
                    factors["suspicious_redirects"] = 0.2

        if self.gaming_results:
            if self.gaming_results.steam_profile:
                sp = self.gaming_results.steam_profile
                if sp.vac_banned:
                    factors["vac_banned"] = 0.4
                if sp.trade_ban:
                    factors["trade_banned"] = 0.35
                if sp.community_banned:
                    factors["community_banned"] = 0.3
                if sp.steamrep_status == "scammer":
                    factors["steamrep_flagged"] = 0.5
                if sp.game_count < 5 and sp.account_created:
                    age = (datetime.utcnow() - sp.account_created).days
                    if age < 30:
                        factors["new_account_few_games"] = 0.25
                if sp.visibility == "private":
                    factors["private_profile"] = 0.1

            if self.gaming_results.discord_user:
                if len(self.gaming_results.discord_user.known_scam_patterns) > 0:
                    factors["discord_scam_patterns"] = 0.3

        # Combine risk factors (using maximum to prevent saturation)
        if factors:
            self.risk_score = max(factors.values())
            self.risk_factors = list(factors.keys())

            if self.risk_score >= 0.4:
                self.risk_level = RiskLevel.CRITICAL
            elif self.risk_score >= 0.3:
                self.risk_level = RiskLevel.HIGH
            elif self.risk_score >= 0.15:
                self.risk_level = RiskLevel.MEDIUM
            elif self.risk_score > 0:
                self.risk_level = RiskLevel.LOW
