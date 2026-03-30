# Changelog

All notable changes to Chharcop will be documented in this file.

## [0.2.3] - 2026-03-29

### Docs — Risk Scoring Transparency
- Added `docs/RISK_SCORING.md`: full public explanation of the additive scoring model
  - Lists every risk signal, its point value, and a plain-English explanation of what it means
  - Documents all 4 score thresholds (LOW/MEDIUM/HIGH/CRITICAL)
  - Includes complete calibration results table for all 10 tested sites
  - Covers known limitations (bot-blocked sites, DV cert false positives, privacy WHOIS on legitimate sites)
  - Links source code location (`chharcop/models.py → ScanResult.calculate_risk_score()`)
- Updated `README.md`: added Risk Scoring section with summary calibration table and link to `docs/RISK_SCORING.md`

### Fix — FUNDING.yml Buy Me a Coffee
- Fixed `.github/FUNDING.yml`: replaced `custom: ["https://buymeacoffee.com/chharcop"]` with
  the correct native GitHub format `buy_me_a_coffee: chharcop`
- The previous `custom` URL format caused a 404 on GitHub's sponsor button
- GitHub Sponsors entry (`github: ChharithOeun`) was already correct

### Risk Calibration — Round 2 (5 new sites)
Added calibration runs against 2 additional legitimate controls and 3 people-search sites.
All evidence saved to `evidence/calibration/`.

**New results:**

| Site | Score | Level | Type |
|------|-------|-------|------|
| facebook.com | 5 | LOW | Control (legit) |
| paypal.com | 0 | UNKNOWN | Control (EV cert — cleanest possible profile) |
| peoplelooker.com | 53 | MEDIUM | People-search |
| truthfinder.com | 38 | MEDIUM | People-search |
| fastpeoplesearch.com | 68 | HIGH | People-search (more sketchy) |

**Key observations:**
- paypal.com scores 0/UNKNOWN — the only tested site with an EV cert; confirms EV cert correctly suppresses `dv_cert_only` signal
- facebook.com scores 5/LOW despite being one of the world's largest sites — DV cert is now standard even for major companies using short-lived auto-renewed certs
- fastpeoplesearch.com ties lookups.io at 68 HIGH: cert_expiring_soon (+15) fires due to 38-day expiry (under 45-day threshold), which is unusual for a Let's Encrypt site with auto-renewal available — signals poor operational hygiene
- truthfinder.com scores 38 vs peoplelooker.com's 53 because it doesn't use Magento — no platform_mismatch fires

**Cumulative calibration dataset (10 sites):**

| Site | Score | Level |
|------|-------|-------|
| paypal.com | 0 | UNKNOWN |
| google.com | 5 | LOW |
| amazon.com | 5 | LOW |
| facebook.com | 5 | LOW |
| spokeo.com | 5 | LOW (bot-blocked) |
| truthfinder.com | 38 | MEDIUM |
| beenverified.com | 40 | MEDIUM |
| peoplelooker.com | 53 | MEDIUM |
| lookups.io | 68 | HIGH |
| fastpeoplesearch.com | 68 | HIGH |

## [0.2.2] - 2026-03-29

### Risk Scoring Calibration

Complete rewrite of the `calculate_risk_score()` algorithm based on multi-site calibration
runs against 5 targets: lookups.io, spokeo.com, beenverified.com (people-search), and
google.com / amazon.com (legitimate controls).

**Root cause of 0.0 score on lookups.io:**  The old algorithm used `max(factors.values())`
so only the single worst signal counted — and no single trigger fired.  Privacy-protected
WHOIS ("Private by Design, LLC") was missed because the keyword check only looked for
"privacy" not "private".  The 33-day cert expiry window was never evaluated.

**Algorithm changes (chharcop/models.py):**
- Switched from `max()` to **additive scoring**, capped at 100
- Score scale changed from 0.0–1.0 to **0–100** with new thresholds:
  - 0–30 → LOW, 31–60 → MEDIUM, 61–80 → HIGH, 81–100 → CRITICAL
- `risk_score` Pydantic field updated to `le=100.0`
- Added `WhoisData.model_validator` that auto-detects privacy registration from
  registrant name keywords ("privacy", "private", "whoisguard", "domains by proxy", …)

**New risk signals and weights:**
| Signal | Weight | Trigger |
|---|---|---|
| `new_domain` | +40 | Domain < 30 days old |
| `recently_created` | +20 | Domain < 180 days old |
| `self_signed_cert` | +35 | Self-signed SSL |
| `invalid_cert` | +40 | Expired / invalid SSL |
| `cert_expiring_soon` | +15 | SSL expiry < 45 days |
| `dv_cert_only` | +5 | DV certificate (not OV/EV) |
| `people_search_site` | +20 | Title/description matches people-search keywords |
| `platform_mismatch` | +10 | Magento on a people-search / non-commerce site |
| `cloudflare_proxy` | +5 | Cloudflare in tech stack, server header, or NS records |
| `missing_all_trust_signals` | +20 | ALL 4 trust signals absent on HTTP 200 page |
| `suspicious_redirects` | +15 | Redirect chain > 2 hops |
| `privacy_registrar` | +8 | Privacy-protected WHOIS registration |
| `discount_registrar` | +5 | Porkbun / Namecheap / Namesilo |

**Removed signals:** `unknown_cert_type` (folded into `dv_cert_only`), old
`missing_trust_signals` threshold of 3 (now requires ALL 4 to avoid false positives
on large sites like amazon.com).

**Bug fixes (chharcop/web/collectors/whois_collector.py):**
- Fixed `ValidationError` crash when `registrar_url` is returned as a `list` by the
  `python-whois` library (seen on spokeo.com, beenverified.com) — now takes `[0]`
- Improved privacy detection in collector to use the same keyword set as the model validator

**Re-scored lookups.io with v0.2.2 algorithm:**
- Previous: 0.0 / UNKNOWN
- New: **68 / HIGH**
- Factors: `privacy_registrar`(+8) + `discount_registrar`(+5) + `dv_cert_only`(+5) +
  `cert_expiring_soon`(+15) + `cloudflare_proxy`(+5) + `people_search_site`(+20) +
  `platform_mismatch`(+10)

**Calibration run results (evidence/calibration_*.json):**
| Site | Pre-v0.2.2 | Post-v0.2.2 | Expected |
|---|---|---|---|
| lookups.io | 0.0 UNKNOWN | 68 HIGH | MEDIUM–HIGH |
| google.com | 0.0 UNKNOWN | 5 LOW | LOW ✓ |
| amazon.com | 25 MEDIUM (**false positive**) | 5 LOW | LOW ✓ |
| beenverified.com | 0.0 UNKNOWN | 40 MEDIUM | MEDIUM ✓ |
| spokeo.com | 25 MEDIUM (403 artefact) | 5 LOW | varies (bot-blocked) |

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

### Operations
- First production scan against lookups.io completed successfully
- Generated evidence report (PDF + JSON) with WHOIS, DNS, SSL, metadata
- Fixed WHOIS collector timezone bug (offset-naive vs offset-aware)
- Risk scoring algorithm calibration started

### Business
- Added monetization strategy document (docs/MONETIZATION_STRATEGY.md)
- Identified top 5 revenue streams and top 3 scaling strategies
- Documented legal implications of each monetization path

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
