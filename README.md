# Chharcop

**Cross-platform scam evidence collection and reporting toolkit for websites and gaming platforms**

Chharcop is an open-source Python toolkit designed to collect comprehensive evidence of scams across websites and gaming platforms. It performs automated OSINT (Open Source Intelligence), risk assessment, and generates professional reports for reporting suspicious accounts and domains.

## Features

### Web Evidence Collection
- **WHOIS Data**: Domain registration details, registrant info, privacy protection status
- **DNS Records**: A, AAAA, MX, NS, TXT, CNAME, SOA records
- **SSL/TLS Certificates**: Certificate validation, expiration, type classification (DV/OV/EV)
- **Website Metadata**: Page structure, technology detection, trust signals, redirect tracking

### Gaming Platform OSINT
- **Steam Profiles**: Account info, VAC/trade/community bans, game library, reputation status
- **Discord Users**: Account age, scam pattern detection, account flags
- **Cross-Platform Gamertag Search**: Find matching accounts across Steam, Xbox, PSN, Epic Games

### Risk Assessment
- Intelligent risk scoring based on multiple factors
- Risk levels: LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
- Detailed risk factor identification

### Cross-Platform
- Works on Windows, macOS, and Linux
- No platform-specific dependencies
- Async/await for concurrent operations

## Installation

### From Source

```bash
git clone https://github.com/chharbot/chharcop.git
cd chharcop
pip install -e .
```

### With Optional Dependencies

```bash
# For API server support
pip install -e ".[api]"

# For screenshot capabilities
pip install -e ".[screenshots]"

# For development
pip install -e ".[dev]"
```

## Configuration

### API Keys

Chharcop requires API keys for accessing external services. Set these as environment variables:

```bash
# Steam Web API Key
export STEAM_API_KEY="your_steam_api_key"

# Discord Bot Token
export DISCORD_BOT_TOKEN="your_discord_bot_token"

# VirusTotal API Key (optional)
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
```

#### Getting API Keys

**Steam API Key**: https://steamcommunity.com/dev/apikey

**Discord Bot Token**: Create a bot at https://discord.com/developers/applications

**VirusTotal API Key**: https://www.virustotal.com/gui/home/upload (free account)

## Usage

### Python API

```python
import asyncio
from chharcop import Chharcop

async def main():
    chharcop = Chharcop()

    # Scan a website
    website_result = await chharcop.scan_website("example.com")
    print(f"Risk Level: {website_result.risk_level}")
    print(f"Risk Score: {website_result.risk_score}")

    # Scan a Steam profile
    steam_result = await chharcop.scan_steam("76561198012345678")

    # Scan a Discord user
    discord_result = await chharcop.scan_discord("123456789012345678")

    # Search gamertag across platforms
    gamertag_result = await chharcop.scan_gamertag("suspicious_user")

    # Auto-detect and scan
    results = await chharcop.full_scan("suspicious_site.com")

asyncio.run(main())
```

### Command Line

```bash
# Scan a website
chharcop website example.com
chharcop website example.com --json

# Scan Steam profile
chharcop steam 76561198012345678

# Scan Discord user
chharcop discord 123456789012345678

# Search gamertag
chharcop gamertag suspicious_user

# Auto-detect and scan
chharcop scan example.com
```

## Architecture

### Module Structure

```
chharcop/
├── models.py           # Pydantic data models
├── core.py            # Main Chharcop orchestrator
├── web/               # Website evidence collectors
│   └── collectors/
│       ├── whois_collector.py
│       ├── dns_collector.py
│       ├── ssl_collector.py
│       └── metadata_collector.py
├── gaming/            # Gaming platform collectors
│   └── collectors/
│       ├── steam_collector.py
│       ├── discord_collector.py
│       └── gamertag_osint.py
├── utils/             # Utilities
│   ├── url_validator.py
│   └── config.py
├── evidence/          # Evidence storage (extensible)
├── report/            # Report generation (extensible)
└── cli/               # Command-line interface
```

### Collector Architecture

All collectors inherit from a base class and follow a consistent pattern:

- **BaseCollector**: Base for web collectors
- **BaseGamingCollector**: Base for gaming platform collectors

Collectors are fully async and include:
- Error handling and recovery
- Logging via loguru
- Type hints throughout
- Proper docstrings

## Data Models

### Risk Levels

- `LOW`: Minor concerns
- `MEDIUM`: Notable indicators of scam activity
- `HIGH`: Strong indicators of scam activity
- `CRITICAL`: Clear evidence of scam activity
- `UNKNOWN`: Insufficient data

### Risk Scoring

Risk scores (0.0 to 1.0) are calculated based on:

**Web Evidence**:
- New domains (< 30 days): +0.3
- Self-signed SSL certificates: +0.35
- Invalid SSL certificates: +0.4
- Missing trust signals (privacy policy, ToS, contact, about): +0.25
- Suspicious redirect chains: +0.2

**Gaming Evidence**:
- VAC bans: +0.4
- Trade bans: +0.35
- Community bans: +0.3
- SteamRep "scammer" status: +0.5
- New accounts with few games: +0.25
- Discord scam patterns: +0.3

## Examples

### Example 1: Website Analysis

```python
async def analyze_suspicious_site():
    chharcop = Chharcop()
    result = await chharcop.scan_website("suspicious-gaming-site.com")

    if result.web_results:
        whois = result.web_results.whois_data
        if whois and whois.days_old < 30:
            print(f"Warning: Domain is only {whois.days_old} days old!")

        ssl = result.web_results.ssl_data
        if ssl and ssl.is_self_signed:
            print("Warning: Self-signed certificate detected!")

    print(f"Overall Risk: {result.risk_level}")
```

### Example 2: Gaming Account Investigation

```python
async def investigate_gaming_account():
    chharcop = Chharcop()

    # Check Steam profile
    steam_result = await chharcop.scan_steam("76561198012345678")
    if steam_result.gaming_results and steam_result.gaming_results.steam_profile:
        profile = steam_result.gaming_results.steam_profile
        if profile.vac_banned:
            print("Alert: Account has VAC bans!")
        if profile.steamrep_status == "scammer":
            print("Alert: Account flagged as scammer on SteamRep!")

    # Search for matching accounts
    gamertag_result = await chharcop.scan_gamertag("suspicious_user")
    print(f"Found on {len(gamertag_result.gaming_results.cross_platform_matches)} platforms")
```

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests with coverage
pytest

# Run specific test
pytest tests/test_models.py -v
```

### Code Quality

```bash
# Format code
ruff format chharcop tests

# Lint code
ruff check chharcop tests

# Type checking
mypy chharcop

# Pre-commit hooks
pre-commit install
pre-commit run --all-files
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Testing Philosophy

All changes must include:
- Unit tests for new collectors/utilities
- Integration tests for orchestrator
- Type hints throughout
- Comprehensive docstrings
- Error handling examples

## Security

- Never commit API keys or credentials
- Use environment variables for sensitive data
- All API communications use HTTPS
- Certificate validation enabled by default
- Input validation on all user-provided data

## License

MIT License - see LICENSE file for details

## Support

- Issues: https://github.com/chharbot/chharcop/issues
- Discussions: https://github.com/chharbot/chharcop/discussions
- Email: chharith@gmail.com

## Roadmap

### Planned Features
- [ ] Report generation (PDF, HTML)
- [ ] Evidence storage and caching
- [ ] Integration with fraud databases
- [ ] Phone number validation and carrier info
- [ ] Email address reputation checking
- [ ] IP geolocation and ASN lookup
- [ ] Web UI for easy access
- [ ] API server (FastAPI)
- [ ] Database support for evidence history

### Collector Expansion
- [ ] More gaming platforms (Roblox, Minecraft, etc.)
- [ ] Payment processor checks (PayPal, Stripe)
- [ ] Social media analysis
- [ ] Email header analysis

## Disclaimer

Chharcop is provided for authorized security research and evidence collection. Users are responsible for:
- Obtaining proper authorization before scanning
- Complying with applicable laws
- Respecting terms of service of scanned platforms
- Proper data handling and privacy

Unauthorized access to computer systems is illegal.

## Author

**Chharbot Contributors**
Email: chharith@gmail.com
