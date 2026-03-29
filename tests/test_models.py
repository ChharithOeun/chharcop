"""Tests for Chharcop data models."""

from datetime import datetime, timedelta

import pytest

from chharcop.models import (
    DnsData,
    DnsRecord,
    DiscordUser,
    RiskLevel,
    ScanResult,
    SiteMetadata,
    SslData,
    SteamProfile,
    WhoisData,
)


class TestRiskLevel:
    """Test risk level enumeration."""

    def test_risk_levels_exist(self) -> None:
        """Test that all risk levels are defined."""
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.UNKNOWN.value == "unknown"


class TestWhoisData:
    """Test WHOIS data model."""

    def test_whois_data_creation(self) -> None:
        """Test creating WHOIS data."""
        now = datetime.utcnow()
        whois = WhoisData(
            domain="example.com",
            registrar="Example Registrar",
            creation_date=now - timedelta(days=365),
            days_old=365,
        )

        assert whois.domain == "example.com"
        assert whois.registrar == "Example Registrar"
        assert whois.days_old == 365
        assert whois.privacy_protected is False

    def test_whois_privacy_protection(self) -> None:
        """Test privacy protection detection."""
        whois = WhoisData(
            domain="private.com",
            registrant_name="Privacy Protection Service",
        )

        assert whois.privacy_protected is True


class TestDnsData:
    """Test DNS data model."""

    def test_dns_data_creation(self) -> None:
        """Test creating DNS data."""
        dns = DnsData(
            domain="example.com",
            a_records=["192.0.2.1"],
            aaaa_records=["2001:db8::1"],
        )

        assert dns.domain == "example.com"
        assert len(dns.a_records) == 1
        assert len(dns.aaaa_records) == 1

    def test_dns_record_with_priority(self) -> None:
        """Test DNS record with priority (MX)."""
        record = DnsRecord(
            record_type="MX",
            value="mail.example.com",
            priority=10,
        )

        assert record.record_type == "MX"
        assert record.priority == 10


class TestSslData:
    """Test SSL certificate data model."""

    def test_ssl_data_creation(self) -> None:
        """Test creating SSL data."""
        now = datetime.utcnow()
        ssl = SslData(
            domain="example.com",
            subject={"CN": "example.com"},
            issuer={"CN": "Let's Encrypt"},
            not_valid_before=now - timedelta(days=30),
            not_valid_after=now + timedelta(days=365),
            is_self_signed=False,
            is_valid=True,
        )

        assert ssl.domain == "example.com"
        assert ssl.is_self_signed is False
        assert ssl.is_valid is True

    def test_ssl_self_signed_detection(self) -> None:
        """Test self-signed certificate detection."""
        ssl = SslData(
            domain="suspicious.com",
            subject={"CN": "suspicious.com"},
            issuer={"CN": "suspicious.com"},
            is_self_signed=True,
        )

        assert ssl.is_self_signed is True


class TestSiteMetadata:
    """Test website metadata model."""

    def test_site_metadata_creation(self) -> None:
        """Test creating site metadata."""
        metadata = SiteMetadata(
            url="https://example.com",
            title="Example Website",
            status_code=200,
            has_privacy_policy=True,
            has_terms_of_service=True,
        )

        assert metadata.url == "https://example.com"
        assert metadata.title == "Example Website"
        assert metadata.status_code == 200

    def test_site_metadata_trust_signals(self) -> None:
        """Test trust signal detection."""
        metadata = SiteMetadata(
            url="https://suspicious.com",
            has_privacy_policy=False,
            has_terms_of_service=False,
            has_contact_page=False,
            has_about_page=False,
        )

        trust_signals = sum([
            metadata.has_privacy_policy,
            metadata.has_terms_of_service,
            metadata.has_contact_page,
            metadata.has_about_page,
        ])

        assert trust_signals == 0


class TestSteamProfile:
    """Test Steam profile model."""

    def test_steam_profile_creation(self) -> None:
        """Test creating Steam profile."""
        profile = SteamProfile(
            steam_id="76561198012345678",
            persona_name="TestPlayer",
            profile_url="https://steamcommunity.com/id/testplayer",
            vac_banned=False,
            vac_ban_count=0,
        )

        assert profile.steam_id == "76561198012345678"
        assert profile.persona_name == "TestPlayer"
        assert profile.vac_banned is False

    def test_steam_profile_bans(self) -> None:
        """Test Steam profile with bans."""
        profile = SteamProfile(
            steam_id="76561198012345678",
            persona_name="SuspiciousPlayer",
            profile_url="https://steamcommunity.com/id/suspicious",
            vac_banned=True,
            vac_ban_count=2,
            trade_ban=True,
            steamrep_status="scammer",
        )

        assert profile.vac_banned is True
        assert profile.vac_ban_count == 2
        assert profile.trade_ban is True
        assert profile.steamrep_status == "scammer"


class TestDiscordUser:
    """Test Discord user model."""

    def test_discord_user_creation(self) -> None:
        """Test creating Discord user."""
        user = DiscordUser(
            user_id="123456789012345678",
            username="testuser",
            bot=False,
        )

        assert user.user_id == "123456789012345678"
        assert user.username == "testuser"
        assert user.bot is False

    def test_discord_user_scam_patterns(self) -> None:
        """Test Discord user with scam patterns."""
        user = DiscordUser(
            user_id="123456789012345678",
            username="steam-support",
            known_scam_patterns=["steam.support", "phishing"],
        )

        assert len(user.known_scam_patterns) == 2
        assert "steam.support" in user.known_scam_patterns


class TestScanResult:
    """Test scan result model."""

    def test_scan_result_creation(self) -> None:
        """Test creating scan result."""
        result = ScanResult(
            scan_id="test-scan-123",
            target="example.com",
            scan_type="website",
        )

        assert result.scan_id == "test-scan-123"
        assert result.target == "example.com"
        assert result.scan_type == "website"

    def test_risk_score_calculation_empty(self) -> None:
        """Test risk score calculation with no data."""
        result = ScanResult(
            scan_id="test-scan",
            target="example.com",
            scan_type="website",
        )

        result.calculate_risk_score()

        assert result.risk_score == 0.0
        assert result.risk_level == RiskLevel.UNKNOWN

    def test_risk_score_calculation_with_factors(self) -> None:
        """Test risk score calculation with self-signed cert (35 pts → MEDIUM)."""
        ssl = SslData(
            domain="example.com",
            is_self_signed=True,  # +35
        )

        from chharcop.models import WebScanResult
        web_result = WebScanResult(
            url="https://example.com",
            ssl_data=ssl,
        )

        result = ScanResult(
            scan_id="test-scan",
            target="example.com",
            scan_type="website",
            web_results=web_result,
        )

        result.calculate_risk_score()

        assert result.risk_score >= 35
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]

    def test_multiple_risk_factors(self) -> None:
        """Test multiple risk factors combined (additive, capped at 100)."""
        steam_profile = SteamProfile(
            steam_id="76561198012345678",
            persona_name="BadPlayer",
            profile_url="https://steamcommunity.com/id/bad",
            vac_banned=True,        # +40
            trade_ban=True,         # +35
            steamrep_status="scammer",  # +50 → total 125, capped at 100
        )

        from chharcop.models import GamingScanResult
        gaming_result = GamingScanResult(
            target_identifier="76561198012345678",
            platform="steam",
            steam_profile=steam_profile,
        )

        result = ScanResult(
            scan_id="test-scan",
            target="76561198012345678",
            scan_type="steam",
            gaming_results=gaming_result,
        )

        result.calculate_risk_score()

        assert result.risk_score >= 40  # At minimum the VAC ban weight
        assert result.risk_level == RiskLevel.CRITICAL


class TestEvidenceHash:
    """Test evidence hash model."""

    def test_sha256_computation(self) -> None:
        """Test SHA256 hash computation."""
        from chharcop.models import EvidenceHash

        test_data = "test_evidence_data"
        hash_value = EvidenceHash.compute_sha256(test_data)

        # Should produce consistent hash
        assert len(hash_value) == 64  # SHA256 hex length
        assert EvidenceHash.compute_sha256(test_data) == hash_value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
