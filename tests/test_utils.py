"""Tests for Chharcop utilities."""

import pytest

from chharcop.utils.url_validator import (
    extract_domain,
    is_valid_domain,
    normalize_url,
    validate_url,
)


class TestUrlValidator:
    """Test URL validation utilities."""

    def test_validate_url_with_scheme(self) -> None:
        """Test validation of URL with scheme."""
        assert validate_url("https://example.com") is True
        assert validate_url("http://example.com") is True

    def test_validate_url_without_scheme(self) -> None:
        """Test validation of URL without scheme."""
        assert validate_url("example.com") is True
        assert validate_url("sub.example.com") is True

    def test_validate_url_invalid(self) -> None:
        """Test validation of invalid URLs."""
        assert validate_url("") is False
        assert validate_url("not a url") is False
        assert validate_url("http://") is False

    def test_extract_domain_from_url(self) -> None:
        """Test domain extraction from full URL."""
        assert extract_domain("https://example.com/path") == "example.com"
        assert extract_domain("http://www.example.com") == "example.com"
        assert extract_domain("https://sub.example.com:8080") == "sub.example.com"

    def test_extract_domain_removes_www(self) -> None:
        """Test that www is removed from domain."""
        assert extract_domain("www.example.com") == "example.com"
        assert extract_domain("https://www.test.com") == "test.com"

    def test_extract_domain_invalid(self) -> None:
        """Test domain extraction from invalid input."""
        assert extract_domain("") is None
        assert extract_domain("not a url") is None

    def test_is_valid_domain_simple(self) -> None:
        """Test simple domain validation."""
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("test.org") is True
        assert is_valid_domain("sub.example.co.uk") is True

    def test_is_valid_domain_localhost(self) -> None:
        """Test localhost validation."""
        assert is_valid_domain("localhost") is True

    def test_is_valid_domain_invalid(self) -> None:
        """Test invalid domains."""
        assert is_valid_domain("") is False
        assert is_valid_domain("-invalid.com") is False
        assert is_valid_domain("invalid-.com") is False
        assert is_valid_domain("invalid..com") is False

    def test_is_valid_domain_with_port(self) -> None:
        """Test domain validation with port."""
        assert is_valid_domain("example.com:8080") is True
        assert is_valid_domain("example.com:443") is True

    def test_normalize_url_adds_scheme(self) -> None:
        """Test URL normalization adds scheme."""
        assert normalize_url("example.com").startswith("https://")
        assert normalize_url("www.example.com").startswith("https://")

    def test_normalize_url_preserves_scheme(self) -> None:
        """Test URL normalization preserves original scheme."""
        assert normalize_url("http://example.com").startswith("http://")
        assert normalize_url("https://example.com").startswith("https://")

    def test_normalize_url_lowercases_domain(self) -> None:
        """Test URL normalization lowercases domain."""
        normalized = normalize_url("https://EXAMPLE.COM/Path")
        assert "example.com" in normalized

    def test_normalize_url_invalid(self) -> None:
        """Test normalize_url with invalid input."""
        assert normalize_url("") == ""
        assert normalize_url("not a url") == "https://not a url"


class TestConfig:
    """Test configuration utilities."""

    def test_config_creation(self) -> None:
        """Test creating config object."""
        from chharcop.utils.config import Config

        config = Config()
        assert config is not None
        # Keys may or may not be set depending on environment
        assert hasattr(config, "steam_api_key")
        assert hasattr(config, "discord_bot_token")

    def test_config_cache_dir(self) -> None:
        """Test cache directory handling."""
        from chharcop.utils.config import Config

        config = Config()
        cache_dir = config.ensure_cache_dir()
        assert cache_dir.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
