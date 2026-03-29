# Changelog

All notable changes to Chharcop will be documented in this file.

## [0.2.1] - 2026-03-29

### First Real Scan
- Completed first production scan against lookups.io (scan ID: 0136ef96)
- Generated evidence report PDF with WHOIS, DNS, SSL, and metadata — all 4 collectors succeeded
- Risk score: 0.0 / UNKNOWN (no red flags detected — domain 567 days old, valid Google-issued DV cert, full trust signals present)
- Fixed WHOIS collector timezone bug (offset-naive vs offset-aware datetime arithmetic)
- Evidence artifacts saved to `evidence/lookups_io_0136ef96.{json,pdf}`

## [0.2.0] - 2026-03-29

### Added — Auto-Training Module (`chharcop/training/`)
- `training/dataset.py`: SQLite-backed training dataset manager seeded with lookups.io and known-scam/legit sites; supports bulk ingestion from JSON, VirusTotal, and ScamAdviser
- `training/metrics.py`: Full classification metrics — confusion matrix, precision, recall, F1, false-positive rate, per-module breakdown, risk-score calibration bucketing, trend series export
- `training/trainer.py`: Async training loop that runs Chharcop's scanner against all labelled sites with configurable concurrency (MAX_CONCURRENT=3), writes results to `training_results.db`, exports to `chharcop-status.json`

### Added — Autonomous Reporting Module (`chharcop/report/`)
- `report/auto_submit.py`: Full submission lifecycle (draft → awaiting_approval → submitted → acknowledged) for FTC, FBI IC3, Google Safe Browsing, APWG eCX; Playwright pre-fill + screenshot for form agencies; programmatic API submission for APWG eCX; human confirmation gate before final submit; versioned template storage
- `report/form_checker.py`: Periodic form-structure checker that scrapes agency pages, diffs field names against stored templates, persists change history to DB, and alerts when forms drift

### Added — VPN Integration (`chharcop/vpn/`)
- `vpn/wireguard.py`: WireGuard client — config file generation/parsing, `wg-quick` lifecycle management, installation detection with per-platform install instructions, public-IP verification after connect
- `vpn/tor_integration.py`: Tor SOCKS5 proxy client — port reachability check, `stem` controller integration for NEWNYM circuit rotation, optional in-process daemon launch, httpx proxy helper
- `vpn/manager.py`: Unified VPN mode selector (none / wireguard / tor); speed-test comparison across all modes; per-investigation VPN choice; connection status tracking

### Added — Email Intake (`chharcop/intake/email_intake.py`)
- IMAP inbox monitor (ProtonMail Bridge compatible, configurable host/port via env vars)
- RFC 822 email parser: extracts URLs, phone numbers, sender domains from body
- Auto-creates one investigation case per URL, phone, and suspicious domain
- Auto-reply acknowledgement to forwarder with assigned case IDs
- SQLite persistence for messages and cases

### Added — Phone / Voicemail Intake (`chharcop/intake/phone_intake.py`)
- Parses forwarded SMS texts for phone numbers and scam keyword indicators (30+ keywords: IRS, warrant, gift card, crypto, etc.)
- Transcribes voicemail audio (MP3/WAV/M4A/OGG/FLAC/WebM) via local OpenAI Whisper library or Whisper API fallback
- Reverse phone lookup via AbstractAPI (configurable via `CHHARCOP_PHONE_API_KEY`)
- Extracts scam indicators from transcription text
- SQLite persistence for all phone cases

### Added — Status Dashboard Schema
- `chharcop-status.json` created with full v0.2.0 schema: `training_metrics`, `active_investigations`, `reporting_queue`, `vpn_status`, `inbox`, `email_intake`, `phone_intake`
- Training metrics module auto-updates this file after each training run

### Changed
- `pyproject.toml`: Added optional dependency groups for `training` (no new deps — uses stdlib sqlite3), `vpn` (stem), `intake` (openai-whisper), `reporting` (playwright already in screenshots extra)

## [0.1.0] - 2026-03-29

### Security & Legal
- Added comprehensive legal framework (LEGAL.md, Terms of Use, Privacy Policy)
- Added license disclaimer addendum restricting to lawful use
- Added CFAA/GDPR/CCPA compliance documentation
- Added AI agent usage liability disclaimers
- Added binding arbitration and class action waiver

### Added
- Initial project scaffolding and architecture
- Web investigation module (WHOIS, DNS, SSL, metadata collectors)
- Gaming platform module (Steam profile + VAC ban detection, Discord user lookup + scam bot patterns, cross-platform gamertag OSINT)
- Evidence packaging module (PDF report generator with chain-of-custody SHA-256 hashing)
- Report templates for FTC, FBI IC3, Google Safe Browsing, Steam, Discord, Xbox, PSN
- CLI interface: `chharcop website`, `chharcop steam`, `chharcop gamertag`
- Comprehensive research report covering APIs, legal framework, and gap analysis
- Build tree architecture document
