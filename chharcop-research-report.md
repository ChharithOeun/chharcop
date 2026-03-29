# Chharcop Research Report

## Landscape Analysis: Scam Reporting, Gaming OSINT, and Digital Evidence Collection

**Date:** March 29, 2026
**Project:** Chharcop - Open-source tool for collecting evidence from scam websites and gaming platforms, and reporting scammers to authorities
**Vision:** Scammers hiding behind gamer tags is a blind spot nobody is addressing with proper tooling

---

## Table of Contents

1. [Threat Intelligence APIs](#1-threat-intelligence-apis)
2. [Law Enforcement Reporting Portals](#2-law-enforcement-reporting-portals)
3. [Gaming Platform APIs and OSINT](#3-gaming-platform-apis-and-osint)
4. [Gaming Scam Patterns](#4-gaming-scam-patterns)
5. [Platform-Specific Reporting (Gaming)](#5-platform-specific-reporting-gaming)
6. [Existing Open-Source Tools](#6-existing-open-source-tools)
7. [Legal Considerations](#7-legal-considerations)
8. [Gap Analysis and Chharcop Opportunity](#8-gap-analysis-and-chharcop-opportunity)

---

## 1. Threat Intelligence APIs

### 1.1 VirusTotal API v3

- **Docs:** https://docs.virustotal.com/reference/overview
- **Base endpoint:** `https://www.virustotal.com/api/v3`
- **Auth:** API key (header `x-apikey`)
- **Free tier:** 500 requests/day, 4 requests/minute
- **Key data:** URL scan results from 70+ AV engines, domain info, IP reports, file hashes, WHOIS, DNS, subdomains, SSL certificates
- **Key endpoints:**
  - `GET /urls/{id}` - URL analysis report
  - `POST /urls` - Submit URL for scanning
  - `GET /domains/{domain}` - Domain report
  - `GET /ip_addresses/{ip}` - IP address report
- **Python:** `pip install vt-py` (official client)
- **Status:** Active, production-ready. Best single API for scam URL analysis.

### 1.2 Google Safe Browsing / Web Risk API

- **Docs:** https://cloud.google.com/web-risk/docs
- **Important:** Safe Browsing API v4 is DEPRECATED. Migrate to Web Risk API.
- **Base endpoint:** `https://webrisk.googleapis.com/v1`
- **Auth:** Google Cloud API key or service account
- **Free tier:** Web Risk has commercial pricing; Safe Browsing v4 Lookup API was free (10,000 requests/day) but deprecated
- **Key data:** URL threat classification (malware, social engineering, unwanted software)
- **Key endpoints:**
  - `GET /uris:search` - Check single URL
  - `POST /submissions:create` - Submit malicious URL
- **Python:** `pip install google-cloud-webrisk`
- **Status:** Active but commercial. Consider PhishTank or VirusTotal as free alternatives for URL reputation.

### 1.3 WHOIS Lookup Options

**python-whois (Free, no API key)**

- **Install:** `pip install python-whois`
- **Usage:** `whois.whois("example.com")` - Direct WHOIS server queries
- **Data:** Registrar, creation/expiration dates, name servers, registrant info (when not privacy-protected)
- **Rate limits:** Dependent on WHOIS server (typically ~50-100/hour before throttling)
- **Status:** Active, best free option

**WhoisXML API (Commercial with trial)**

- **Docs:** https://whoisxmlapi.com/
- **Free tier:** 500 queries on signup (trial credits)
- **Auth:** API key
- **Data:** Enriched WHOIS + reverse WHOIS, DNS history, IP geolocation
- **Python:** `pip install whoisxmlapi`

### 1.4 URLScan.io API

- **Docs:** https://urlscan.io/docs/api/
- **Base endpoint:** `https://urlscan.io/api/v1`
- **Auth:** API key (header `API-Key`)
- **Free tier:** 1,000 searches/day, 100 scans/day, 2 requests/second
- **Key data:** Full page screenshots, DOM snapshots, HTTP transactions, JavaScript behavior, linked resources, IP/ASN info, technology stack detection
- **Key endpoints:**
  - `POST /scan/` - Submit URL for scanning
  - `GET /result/{uuid}/` - Get scan results
  - `GET /search/` - Search existing scans
- **Python:** Direct HTTP requests (no official SDK)
- **Status:** Active, production-ready. Excellent for visual evidence (automated screenshots).

### 1.5 Shodan API

- **Docs:** https://developer.shodan.io/api
- **Base endpoint:** `https://api.shodan.io`
- **Auth:** API key (query parameter)
- **Free tier:** Limited search (no filters), 1 scan credit/month. Academic accounts get more.
- **Paid:** Starting at $59/month for full search filters
- **Key data:** Open ports, services, SSL certs, hosting provider, organization, geolocation, vulnerabilities
- **Key endpoints:**
  - `GET /shodan/host/{ip}` - Host information
  - `GET /dns/resolve` - DNS resolution
  - `GET /dns/reverse` - Reverse DNS
- **Python:** `pip install shodan`
- **Status:** Active. Useful for scam infrastructure analysis but paid tier needed for serious use.

### 1.6 PhishTank API

- **Docs:** https://phishtank.org/api_info.php
- **Endpoint:** `http://checkurl.phishtank.com/checkurl/`
- **Auth:** Optional API key (app_key for higher limits)
- **Free tier:** Unlimited with key; HTTP 509 when rate-limited without key
- **Key data:** Known phishing URL verification, community verification status
- **Parameters:** `url` (urlencoded or base64), `format` (xml/json), `app_key`
- **Python:** Direct HTTP POST
- **Operator:** Cisco Talos Intelligence Group
- **Status:** Active, production-ready. Good complement to VirusTotal for phishing-specific checks.

### 1.7 AbuseIPDB API

- **Docs:** https://docs.abuseipdb.com/
- **Base endpoint:** `https://api.abuseipdb.com/api/v2`
- **Auth:** API key (header `Key`)
- **Free tier:** 1,000 checks/day, 500 reports/day
- **Key data:** IP abuse reports, confidence score, ISP, usage type, country, report categories
- **Key endpoints:**
  - `GET /check` - Check IP reputation
  - `POST /report` - Report abusive IP
  - `GET /check-block` - Check CIDR block
- **Python:** Direct HTTP requests
- **Status:** Active, production-ready. Essential for IP reputation checks on scam infrastructure.

### 1.8 AlienVault OTX (Open Threat Exchange)

- **Docs:** https://otx.alienvault.com/api
- **Base endpoint:** `https://otx.alienvault.com/api/v1`
- **Auth:** API key (header `X-OTX-API-KEY`)
- **Free tier:** Community-powered, free for all registered users
- **Key data:** Pulses (threat indicators), IP/domain/URL/file hash reputation, related malware, geo data
- **Python:** `pip install OTXv2`
- **Status:** Active. Good for community-sourced threat intelligence.

### 1.9 OpenPhish

- **URL:** https://openphish.com/
- **Free tier:** Community feed updated every 5 minutes (list of active phishing URLs)
- **Premium:** Full feed with additional metadata
- **Auth:** None for community feed
- **Data:** Active phishing URL list
- **Status:** Active. Useful as a passive feed for known phishing URLs.

### 1.10 ScamAdviser

- **URL:** https://www.scamadviser.com/
- **API:** B2B API available (commercial, contact for pricing)
- **Data:** Trust scores (0-100), domain age, hosting info, reviews
- **Free access:** Web lookup only (no free API tier)
- **Status:** Active but API is commercial-only. Web scraping may be an option but check ToS.

### API Priority for Chharcop Implementation

| Priority | API | Why |
|----------|-----|-----|
| P0 (Must have) | VirusTotal | Best single source, 70+ engines, free tier sufficient |
| P0 | python-whois | Free, no key needed, domain registration intelligence |
| P0 | URLScan.io | Automated screenshots + full page analysis |
| P1 (Should have) | PhishTank | Phishing-specific database, free |
| P1 | AbuseIPDB | IP reputation, free tier generous |
| P2 (Nice to have) | AlienVault OTX | Community threat intel, free |
| P2 | OpenPhish | Passive phishing feed |
| P3 (Future) | Shodan | Infrastructure analysis, needs paid tier |
| P3 | Google Web Risk | Commercial, consider if budget allows |

---

## 2. Law Enforcement Reporting Portals

### 2.1 FTC ReportFraud

- **URL:** https://reportfraud.ftc.gov/
- **Required fields:** Victim info (name, address, phone, email), fraud type, what happened, financial transaction info, perpetrator/company info
- **API:** No public API. Community Advocate Program available for organizations (bulk submission via custom links at reportfraud.ftc.gov/community)
- **File attachments:** Not explicitly documented
- **Tracking:** Confirmation on submission, no public tracking number
- **Notes:** Reports feed into FTC Consumer Sentinel database used for enforcement

### 2.2 FBI IC3

- **URL:** https://complaint.ic3.gov/
- **Required fields:** Complainant info (name, address, phone, email), transaction amount, transaction date, whether money was sent, subject/perpetrator info, incident details, crime type
- **Recommended extras:** Perpetrator IP addresses, domain registration details, screenshots, email headers, transaction receipts
- **API:** No public API, web form only
- **File attachments:** Can include supporting documents; must save/print copy before navigating away (no email copies sent)
- **Tracking:** Must save case number immediately on completion
- **Critical note:** IC3 does NOT directly collect evidence attachments. Users submit complaints via form, keep original evidence locally. If investigation opens, law enforcement requests evidence separately.

### 2.3 State Attorney General Offices

- **No centralized portal.** Each state maintains independent systems.
- **Examples:**
  - New York: ag.ny.gov/file-complaint
  - Texas: texasattorneygeneral.gov/consumer-protection/file-consumer-complaint
  - Michigan: michigan.gov/ag
  - Washington: atg.wa.gov/scam-alerts
- **API:** None identified for any state
- **Recommendation:** Use federal FTC ReportFraud as primary; state AG as supplemental

### 2.4 BBB Scam Tracker

- **URL:** https://www.bbb.org/scamtracker/reportscam
- **Required fields:** Scam type, business/company info, amount lost, personal info, description, contact method
- **API:** No public API
- **File attachments:** Supported
- **Tracking:** Published report after review, no private tracking number

### 2.5 APWG (Anti-Phishing Working Group)

- **Email:** reportphishing@apwg.org (forward full phishing email with headers)
- **eCrime eXchange (eCX):** https://apwg.org/ecx (members only)
  - REST API with GET/POST/PATCH methods
  - Requires Data Sharing Agreement
  - API token authentication
  - Supports programmatic bulk submissions
  - Sandbox: https://sandbox.ecrimex.net
- **Status:** Best option for organizations. Individual users can email reports.

### 2.6 econsumer.gov

- **URL:** https://www.econsumer.gov/
- **Required fields:** Complaint type, personal info, company/perpetrator info, financial loss
- **API:** No public API
- **Important:** Do NOT provide sensitive data (bank/card info, ID numbers, health history)
- **Reach:** Partnership of 35+ consumer protection authorities worldwide. Best for international scams.

### 2.7 Google Safe Browsing Report

- **Phishing report:** https://safebrowsing.google.com/safebrowsing/report_phish/
- **Incorrect listing:** https://safebrowsing.google.com/safebrowsing/report_error/
- **Programmatic:** Web Risk Submission API (`POST projects.uris.submit`) - requires Google Cloud credentials
- **Notes:** One URL per API request. Manual web form also available.

### 2.8 Microsoft SmartScreen

- **URL:** https://feedback.smartscreen.microsoft.com/
- **Report unsafe site:** https://feedback.smartscreen.microsoft.com/feedback.aspx
- **API:** No public API
- **Fields:** URL, issue type, description

### 2.9 PhishTank Submission

- **Email:** submissions@phishtank.com (requires free registration)
- **Web form:** Submit via phishtank.com after registration
- **API:** HTTP POST to `http://checkurl.phishtank.com/checkurl/` (checking, not submission)
- **Bulk:** Supported via API loops

### 2.10 CISA

- **URL:** https://cisa.services/report/
- **Fields:** Incident type, details, technical indicators (IPs, URLs, hashes), timeframe, impact, contact info
- **Features:** Save/update reports after submission, third-party reporting, search/filter, collaboration with CISA analysts
- **Auth:** Login.gov integration
- **API:** No public programmatic API

### Reporting Portal Summary

| Portal | API? | Bulk? | Tracking? | Best For |
|--------|------|-------|-----------|----------|
| FTC ReportFraud | Orgs only | Orgs only | Confirmation | Primary US consumer fraud |
| FBI IC3 | No | No | Save on submit | Internet crime (financial loss) |
| BBB Scam Tracker | No | No | No | Consumer scam visibility |
| APWG eCX | Members | Members | Yes | Phishing (organizations) |
| econsumer.gov | No | No | No | International scams |
| Google Safe Browsing | Web Risk API | Yes | Yes (API) | URL blacklisting |
| PhishTank | Check only | Via API | Yes | Phishing URL database |
| CISA | No | No | Yes | Infrastructure/cyber incidents |

---

## 3. Gaming Platform APIs and OSINT

### 3.1 Steam Web API

- **Docs:** https://steamcommunity.com/dev/ and https://partner.steamgames.com/doc/webapi_overview
- **Base endpoint:** `https://api.steampowered.com`
- **Auth:** API key from https://steamcommunity.com/dev/apikey
- **Rate limits:** Not officially documented; community reports ~100,000 requests/day
- **Status:** PRODUCTION READY

**Key endpoints:**

| Endpoint | Data Returned |
|----------|---------------|
| `ISteamUser/GetPlayerSummaries/v2` | Profile info, avatar, status, visibility, last logoff |
| `ISteamUser/GetPlayerBans/v1` | VAC bans, community bans, trade bans, game bans (ONLY platform with public ban data) |
| `ISteamUser/GetFriendList/v1` | Friends list with relationship timestamps |
| `IPlayerService/GetOwnedGames/v1` | Game library, playtime per game |
| `IPlayerService/GetRecentlyPlayedGames/v1` | Recent activity |
| `ISteamApps/GetAppList/v2` | Complete Steam app catalog |

**Python libraries:**
- `steam` - Community library for Steam API interactions
- `steampy` - Trading-focused library

**Investigation value:** Ban detection is the killer feature. `GetPlayerBans` returns VAC bans, trade bans, community bans, and days since last ban. No other platform exposes this data publicly.

### 3.2 SteamRep

- **URL:** https://steamrep.com/ (was)
- **CRITICAL:** SteamRep went OFFLINE at end of 2024. API sunset June 15, 2025.
- **Archive:** 53,925 scammer records archived at https://github.com/woctezuma/steamrep
- **No replacement exists.** This is a major gap Chharcop can fill.
- **Backpack.tf** (https://next.backpack.tf/) is the most-visited remaining alternative for trading reputation

### 3.3 PSN (PlayStation Network)

- **Official API:** None available to public
- **Reverse-engineered library:** `psnawp` (Python) - https://pypi.org/project/psnawp/
  - Requires NPSSO token from PlayStation login
  - Profile lookup, trophies, online status, friends list
  - **WARNING:** Use a dedicated/burner PSN account. Main account ban risk is real.
- **Third-party sites:** psnprofiles.com (web scraping only, no API)
- **Status:** BETA-quality. Fragile, can break with Sony updates.

### 3.4 Xbox Live / OpenXBL

- **Official:** Xbox services require Microsoft Partner Center registration (enterprise)
- **Third-party API:** OpenXBL - https://xbl.io/
  - Free tier available
  - Profile lookup, achievements, friends, presence, game clips
  - API key authentication
- **Python:** Direct HTTP requests to OpenXBL endpoints
- **Status:** PRODUCTION READY via OpenXBL

### 3.5 Discord API

- **Docs:** https://discord.com/developers/docs
- **Base endpoint:** `https://discord.com/api/v10`
- **Auth:** Bot token or OAuth2
- **Rate limits:** 50 requests/second global
- **Key data:** User profiles (ID, username, avatar, creation date from snowflake ID), guild (server) info, messages, member lists
- **Python:** `discord.py` - mature, well-maintained library
- **Investigation value:**
  - User creation date derivable from Discord snowflake ID (no API call needed)
  - Rich Presence reveals Steam/Xbox/PSN activity (cross-platform correlation)
  - Bot vs human detection via user flags
  - Server membership overlaps
- **Status:** PRODUCTION READY

### 3.6 Epic Games

- **Official API:** No public API
- **Third-party:** FortniteAPI.io was shutting down March 31, 2026
- **Alternative:** fortnite-api.com (community-maintained, fragile)
- **Status:** NOT RECOMMENDED. APIs are unstable/deprecated. Epic actively discourages third-party API usage.

### 3.7 Cross-Platform Correlation Tools

The strongest signal for linking accounts across platforms is **username reuse.**

| Tool | Platforms | GitHub Stars |
|------|-----------|-------------|
| Sherlock | 400+ sites including gaming | 74K+ |
| Maigret | 3,000+ sites (superset of Sherlock) | 19K+ |
| Blackbird | Multiple platforms | Growing |

**Correlation method:** Search the same username/gamertag across Steam, Discord, PSN, Xbox, Twitch, Reddit, Twitter, etc. Scammers frequently reuse names or variations.

**Discord Rich Presence** is particularly valuable: it shows what game a user is playing on Steam/Xbox/PSN, linking their Discord identity to gaming platform identities without needing those platforms' APIs.

---

## 4. Gaming Scam Patterns

### 4.1 Fake Game Item Traders / CS2 Skin Scams

**How they work:** Scammers use API key theft to intercept and redirect legitimate trades. They obtain the victim's Steam API key, cancel real trade offers, then send duplicate offers from fake bot accounts that look identical.

**Detectable signals:**
- Unauthorized API keys on victim's Steam API key page
- Trade offers missing "decoy" items (legitimate sites add low-value items as verification)
- Bot account details don't match the trading site's dashboard
- Account age and level mismatches between real and impersonator bots
- Phishing URLs that mimic official trading sites

**Detection approach for Chharcop:** Check `steamcommunity.com/dev/apikey` for unauthorized keys, validate trade partner account age/level against known legitimate bots, URL analysis on trade links.

### 4.2 Discord Phishing

**Common patterns:** Fake Nitro gift offers, fake game giveaway bots, QR code scams, fake moderation messages ("I accidentally reported you").

**Detectable signals:**
- URLs not pointing to discord.com or discord.gift
- URL shorteners (is.gd, bit.ly) in DMs
- Domains with slight character variations from official ones
- Bots contacting users unprompted (official Discord bots never do this for Nitro)
- Grammar inconsistencies in scam messages

**Detection approach for Chharcop:** URL pattern matching, domain similarity scoring (Levenshtein distance from legitimate domains), bot account age analysis via snowflake ID.

### 4.3 Fake Gift Card Scams (PSN, Xbox, Steam)

**Distribution:** Discord DMs, social media, email phishing, marketplace posts, "friend" impersonation with urgent requests.

**Detectable signals:**
- URL redirects to non-official domains
- Formatting errors ("Steam gift 50$" vs correct "$50")
- Urgency language ("limited time", "act now")
- Requests for credentials or personal info beyond what's needed
- Poor-quality card images

### 4.4 Account Selling/Boosting Scams

**Platforms:** PlayerAuctions (largest), EpicNPC, game-specific subreddits, private Discord servers.

**Red flags:**
- 70-90% below market value pricing
- New/unverified sellers
- Requests for off-platform payment
- Account reclamation after sale (seller uses game recovery to take back the account)

### 4.5 Fake Tournament Scams

**How they work:** Professional-looking fake websites, social media promotion, Discord/Telegram announcements. Charge registration fees for non-existent tournaments.

**Detection signals:**
- Registration not through official game developer sites
- Communication via WhatsApp/Telegram instead of official platforms
- No verifiable tournament history
- Payment via gift cards, crypto, or untraceable methods
- No tournament rules or prize breakdown published

**Current trend (2026):** Free Fire and CS2 tournaments most commonly faked. Mobile game tournaments most vulnerable.

### 4.6 Romance Scams Targeting Gamers

**How they differ:** Start in-game via voice chat or DMs, leverage shared gaming interests for trust-building, often target younger players. Grooming timeline is typically 6-8 months of daily communication before financial requests.

**Detectable signals:**
- Newly created gaming account with rapid login frequency
- Inconsistent location data (SIM card location vs IP address)
- Early declarations of love/commitment
- Requests to move communication off-platform
- Pressure to keep relationship secret

**Emerging pattern (2025-2026):** "Pig butchering" hybrid where romance scammers funnel gaming victims to fake crypto/gambling platforms.

### 4.7 NFT/Crypto Gaming Scams

**How rug pulls work:** Developers create fake play-to-earn games, collect investment, then drain funds and disappear.

**Detection signals:**
- No third-party smart contract audits
- Unlocked liquidity pools
- Anonymous development team
- Promises of "guaranteed" returns
- Low trading volume
- Suspicious whale wallet patterns

---

## 5. Platform-Specific Reporting (Gaming)

### 5.1 Steam

- **Support:** https://help.steampowered.com/
- **Scam FAQ:** https://help.steampowered.com/en/faqs/view/70E6-991B-233B-A37B
- **Report scammer:** Profile > "More" menu > "Report violation" OR support ticket
- **Evidence needed:** Full unedited screenshots of chat, scammer profile link, trade history, phishing links, timestamps
- **API for reporting:** No
- **Response time:** 1 day to several months
- **Note:** No item rollback for scammed items

### 5.2 PlayStation/PSN

- **URL:** https://www.playstation.com/en-us/support/account/ps5-report-behaviour/
- **Methods:** In-app reporting (Messages: highlight > OPTIONS > Report; Voice chat: PS button > More > Report; Profile: select Report)
- **Evidence:** Automatic in-app capture, screenshots
- **Response time:** Variable; notifications at each stage (submitted, reviewed, action taken)

### 5.3 Xbox Live

- **Complaint URL:** https://support.xbox.com/en-US/help/family-online-safety/enforcement/file-a-complaint
- **Enforcement:** https://enforcement.xbox.com/en-us/home/reputation
- **Methods:** Player profile > "Report or block" > choose violation type
- **Evidence:** Gamertag, description, screenshots/clips, timestamps
- **Response time:** 24-72 hours initial review

### 5.4 Discord Trust & Safety

- **Report form:** https://dis.gd/request
- **Scam/phishing bots:** https://support.discord.com/hc/en-us/articles/360037660611
- **Methods:** Right-click username > Apps > Report User; OR web form for phishing/bots
- **Evidence:** Screenshots, links, user IDs, message timestamps, malicious links
- **Response time:** 24-72 hours for critical phishing; longer for other violations

### 5.5 Epic Games / Fortnite

- **Report URL:** https://safety.epicgames.com/en-US/policies/reporting-misconduct/submit-report
- **In-game:** Report player directly, report creator (click name > scroll > Report Creator), report island
- **Evidence:** Gamertag/player ID, description, screenshots/clips, timestamps, chat logs
- **Check status:** Epic Games Safety Center > "My Reports"
- **Response time:** 5-10 business days

### 5.6 Twitch

- **Safety Center:** https://safety.twitch.tv/s/article/Filing-a-Report
- **Methods:** Stream > "More" > "Report"; Chat > click username > "Report"; VOD > "More" > "Report"
- **Evidence:** Timestamps, stream/VOD links, clips, chat logs, descriptions
- **Email for complex cases:** safety@twitch.tv
- **Reporting is anonymous**
- **Response time:** 5-15 business days

### Gaming Reporting Summary

| Platform | Report URL | API? | Response Time | Anonymous? |
|----------|-----------|------|---------------|------------|
| Steam | help.steampowered.com | No | 1 day - months | No |
| PSN | playstation.com/support | No | Variable | Yes |
| Xbox | enforcement.xbox.com | No | 24-72 hours | Yes |
| Discord | dis.gd/request | No | 24-72 hours | N/A |
| Epic Games | safety.epicgames.com | No | 5-10 days | Yes |
| Twitch | safety.twitch.tv | No | 5-15 days | Yes |

**Key finding:** ALL gaming platforms require manual reporting. No platform offers programmatic/API-based scam reporting. This is a major gap.

---

## 6. Existing Open-Source Tools

### 6.1 OSINT Frameworks

| Tool | GitHub Stars | Language | What It Does | Last Active |
|------|-------------|----------|--------------|-------------|
| Sherlock | 74K+ | Python | Username search across 400+ sites | Active 2026 |
| Maigret | 19K+ | Python | Username search across 3,000+ sites | Active 2026 |
| SpiderFoot | 13K+ | Python | Automated OSINT collection (100+ modules) | Active |
| theHarvester | 15.9K+ | Python | Domain/email/name intelligence gathering | Active |
| Recon-ng | 11K+ | Python | Web reconnaissance framework | Active |
| PhoneInfoGa | 16K+ | Python/Go | Phone number OSINT | Active |

### 6.2 Evidence Preservation Tools

| Tool | Stars | What It Does |
|------|-------|--------------|
| ArchiveBox | 27K+ | Self-hosted web archiving (WARC, screenshots, PDFs, full page capture) |
| HTTrack | Established | Offline website copy |
| wget (WARC mode) | Built-in | `wget --warc-file=output URL` for WARC capture |

### 6.3 Steam-Specific Tools

| Tool | URL | What It Does |
|------|-----|--------------|
| SteamDB | steamdb.info | App/game database, pricing history, player counts |
| SteamID.io | steamid.io | Steam ID resolution (Steam64, Steam32, profile URL) |
| CSFloat | csfloat.com | CS2 skin float value analysis |
| Backpack.tf | next.backpack.tf | TF2/CS2 trading reputation and pricing |
| SteamRep Archive | github.com/woctezuma/steamrep | 53,925 archived scammer records (SteamRep is offline) |

### 6.4 Discord OSINT Tools

| Tool | URL | What It Does |
|------|-----|--------------|
| Discord-AntiScam/scam-links | github.com/Discord-AntiScam/scam-links | 24,000+ known phishing/scam URLs |
| Discord-Phishing-URLs | GitHub | Community-maintained phishing URL database |
| Darvester | GitHub | Discord user data harvesting (for research) |
| OSINTCord | Discord server | Community for Discord OSINT practitioners |

### 6.5 Cross-Platform Gaming Tools

| Tool | URL | What It Does |
|------|-----|--------------|
| Tracker.gg | tracker.gg | Multi-game stats tracking (Valorant, Fortnite, Apex, etc.) |
| UserSearch | usersearch.org | Cross-platform username search |
| Blackbird | GitHub | OSINT username search |

### 6.6 Notable Gap: No Unified Tool Exists

After surveying 150+ tools, the landscape has these characteristics:

- Steam tools work on Steam only (12+ tools)
- Discord tools work on Discord only (10+ tools)
- Trading reputation tools cover TF2 only (Backpack.tf)
- OSINT frameworks are general-purpose (not gaming-specific)
- Evidence preservation tools don't connect to reporting workflows
- **No single tool combines cross-platform gamertag intelligence with scam reporting**

---

## 7. Legal Considerations

### 7.1 Legality of Evidence Collection

**Public data collection is generally legal.** The Ninth Circuit established in hiQ Labs v. LinkedIn (2022) that scraping publicly available data does not violate the CFAA. The Supreme Court's Van Buren v. United States (2021) narrowed the CFAA's definition of "exceeds authorized access."

**Safe activities (strong legal protection):**
- Viewing publicly available web pages
- Taking screenshots of visible content
- Archiving publicly visible pages (WARC format)
- Collecting visible URLs and page content
- Documenting collection methodology

**Higher risk activities:**
- Using fake accounts to access restricted areas (breach of contract risk per hiQ)
- Bypassing authentication systems (CFAA violation)
- Circumventing technological access barriers (CFAA violation)
- Collecting EU personal data without legal basis (GDPR risk)
- Violating explicit clickwrap Terms of Service (contract liability)

**Chharcop approach:** Default to passive collection of publicly visible data only. Warn users against fake accounts or authentication circumvention.

### 7.2 Digital Evidence Preservation

**WARC format is the gold standard.** Recommended by the Sedona Conference, adopted by NARA and the Library of Congress. Captures complete website snapshots including HTTP headers, content, resources, and metadata.

**SHA-256 hashing is legally accepted.** Federal Rules of Evidence amendments 902(13) and 902(14) allow digitally stored information authenticated by hash to be admitted without witness testimony. Case law supporting: United States v. Cartier (8th Circuit 2008), United States v. Wellman (4th Circuit 2011), United States v. Grant (2022).

**Screenshot requirements for court admissibility (Federal Rules of Evidence 901):**
- Include web address/URL bar
- Include visible date/timestamp
- Full-page captures (entire page including scroll content)
- No cropping, editing, or filtering
- Forensic-grade tools that embed qualified timestamps and digital signatures are preferred

### 7.3 Chain of Custody

Chain of custody is a detailed chronological record documenting where evidence was, when it was collected, who accessed it, and how it was stored. If broken at any stage, digital evidence may be ruled inadmissible.

**Documentation requirements:**
- Permanent records of how evidence was obtained
- Every handler documented with date/time
- Reason for each transfer recorded
- Storage location and security measures logged
- Hash verification at every stage

**Chharcop should auto-generate chain of custody forms:**

```
Evidence Collection Report
==========================
Evidence ID:       [unique identifier]
Date Collected:    [date with timezone]
URL:               [complete URL]
Collection Method: [screenshot/WARC/other]
Tool Used:         Chharcop v[version]
Collected By:      [user name/organization]
SHA-256 Hash:      [hash value]
Storage Location:  [where stored]
```

### 7.4 Relevant Laws

| Law | Relevance to Chharcop |
|-----|----------------------|
| CFAA (18 U.S.C. 1030) | Public data collection is legal; don't bypass authentication |
| Wire Fraud (18 U.S.C. 1343) | Scammers violate this; evidence of wire communications supports prosecution |
| CAN-SPAM Act | Scam emails violating this can be reported to FTC |
| GDPR | If collecting from EU-hosted sites, minimize personal data collection |
| State computer crime laws | All 50 states have them; ToS violations alone generally not criminal |

### 7.5 NIST Standards

Follow NIST SP 800-86 four-step forensic process: Identify, Process, Analyze, Report. Follow NIST IR 8387 for digital evidence preservation: write-blocking, hash verification, secure storage, documented chain of custody.

---

## 8. Gap Analysis and Chharcop Opportunity

### 8.1 What Exists vs. What's Missing

| Capability | Current State | Chharcop Opportunity |
|-----------|--------------|---------------------|
| Cross-platform gamertag correlation | No unified tool (Sherlock/Maigret are generic) | Gaming-specific identity linker across Steam/Discord/PSN/Xbox |
| SteamRep replacement | Offline since 2024, 53K records archived | Import archive + build successor with multi-platform data |
| Evidence collection + reporting pipeline | Completely fragmented (different tools for each step) | Single workflow: collect evidence, generate package, submit to authorities |
| Gaming-specific scam detection | No purpose-built tool | Pattern detection for CS2 scams, Discord phishing, fake tournaments |
| Legally defensible evidence packages | WARC tools exist but disconnected from reporting | Auto-generate court-ready evidence with hashes, timestamps, chain of custody |
| Multi-platform scam reporting | Every platform is manual-only | Pre-fill forms, generate evidence packages formatted per platform requirements |
| Non-technical user accessibility | 95%+ tools are CLI-only | Wizard-style UI, 2-3 minute process for victims |

### 8.2 The Blind Spot Chharcop Addresses

Scammers frequently operate across gaming platforms simultaneously. A CS2 skin scammer on Steam also runs phishing Discord servers and sells stolen accounts on secondary marketplaces. Current tools can only see one platform at a time. Nobody is connecting the dots.

**Market data:**
- US fraud attempts up 261.9% year-over-year
- Global fraud attempts up 393% year-over-year
- 1.7 billion gamers targeted worldwide
- Fewer than 30% of victims report successfully
- 60% abandon the reporting process (too complex)
- SteamRep shutdown left a vacuum with no replacement

### 8.3 Recommended Chharcop Architecture

**Core modules:**

1. **Identity Resolver** - Input a gamertag, get linked accounts across Steam, Discord, PSN, Xbox, Twitch, Epic. Use Maigret/Sherlock engine + gaming-specific platform APIs.

2. **Intelligence Gatherer** - For each linked account, pull: Steam bans (VAC, trade, community), account age, game library, trading history patterns, Discord account age (snowflake), server memberships.

3. **Threat Scorer** - Run URLs through VirusTotal, PhishTank, URLScan.io. Run IPs through AbuseIPDB. Check against OpenPhish feed and Discord-AntiScam scam-links database. Generate composite risk score.

4. **Evidence Packager** - WARC archive of scam pages, SHA-256 hashed screenshots with visible URL bars and timestamps, auto-generated chain of custody documentation, exportable PDF evidence package.

5. **Report Router** - Pre-formatted submissions for: FBI IC3, FTC ReportFraud, Google Safe Browsing, platform-specific reports (Steam, Discord, PSN, Xbox, Epic, Twitch), PhishTank submission. Guide user through each portal with pre-filled data.

6. **Community Database** - Successor to SteamRep. Cross-platform scammer records. Import SteamRep archive (53K records). Community verification system.

### 8.4 Technical Stack Recommendation

- **Language:** Python (ecosystem alignment with OSINT tools, API libraries)
- **Web framework:** FastAPI (for API backend) + React (for web UI)
- **CLI:** Click or Typer for power users
- **Evidence:** warcio library for WARC files, Playwright for screenshots
- **Hashing:** hashlib (SHA-256, built into Python)
- **Database:** PostgreSQL + Redis (for caching API responses within rate limits)
- **Cross-platform username search:** Integrate Maigret as a library

### 8.5 API Rate Limit Budget per Investigation

Assuming free tiers only, a single scam investigation can query:

| API | Calls Needed | Daily Budget | Investigations/Day |
|-----|-------------|-------------|-------------------|
| VirusTotal | 3-5 per URL | 500/day | ~100 |
| URLScan.io | 1-2 scans | 100 scans/day | ~50 |
| python-whois | 1 per domain | ~50-100/hour | ~500 |
| PhishTank | 1 check | Unlimited (with key) | Unlimited |
| AbuseIPDB | 1-2 per IP | 1,000/day | ~500 |
| Steam Web API | 3-5 per user | ~100,000/day | ~20,000 |
| Discord API | 2-3 per user | Generous (50 req/sec) | Thousands |

**Bottleneck:** URLScan.io scan submissions (100/day free) and VirusTotal (500/day). Caching and deduplication are essential.

---

## Sources and References

### Threat Intelligence API Documentation
- VirusTotal API v3: https://docs.virustotal.com/reference/overview
- Google Web Risk: https://cloud.google.com/web-risk/docs
- URLScan.io: https://urlscan.io/docs/api/
- Shodan: https://developer.shodan.io/api
- PhishTank: https://phishtank.org/api_info.php
- AbuseIPDB: https://docs.abuseipdb.com/
- AlienVault OTX: https://otx.alienvault.com/api

### Law Enforcement Portals
- FTC ReportFraud: https://reportfraud.ftc.gov/
- FBI IC3: https://complaint.ic3.gov/
- APWG: https://apwg.org/ecx
- econsumer.gov: https://www.econsumer.gov/
- CISA: https://cisa.services/report/
- BBB Scam Tracker: https://www.bbb.org/scamtracker/reportscam

### Gaming Platform APIs
- Steam Web API: https://steamcommunity.com/dev/
- Steamworks: https://partner.steamgames.com/doc/webapi_overview
- Discord Developers: https://discord.com/developers/docs
- OpenXBL: https://xbl.io/
- psnawp: https://pypi.org/project/psnawp/

### Gaming Reporting
- Steam Support: https://help.steampowered.com/en/faqs/view/70E6-991B-233B-A37B
- PlayStation: https://www.playstation.com/en-us/support/account/ps5-report-behaviour/
- Xbox: https://support.xbox.com/en-US/help/family-online-safety/enforcement/file-a-complaint
- Discord Trust & Safety: https://dis.gd/request
- Epic Games Safety: https://safety.epicgames.com/en-US/policies/reporting-misconduct
- Twitch Safety: https://safety.twitch.tv/s/article/Filing-a-Report

### OSINT Tools
- Sherlock: https://github.com/sherlock-project/sherlock
- Maigret: https://github.com/soxoj/maigret
- SpiderFoot: https://github.com/smicallef/spiderfoot
- theHarvester: https://github.com/laramies/theHarvester
- ArchiveBox: https://github.com/ArchiveBox/ArchiveBox
- Discord-AntiScam scam-links: https://github.com/Discord-AntiScam/scam-links
- SteamRep Archive: https://github.com/woctezuma/steamrep

### Legal References
- hiQ Labs v. LinkedIn (9th Cir. 2022): https://cdn.ca9.uscourts.gov/datastore/opinions/2022/04/18/17-16783.pdf
- Van Buren v. United States (2021): Supreme Court, narrow CFAA interpretation
- CFAA: https://www.law.cornell.edu/uscode/text/18/1030
- NIST SP 800-86: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf
- NIST IR 8387: https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8387.pdf
- Federal Rules of Evidence 901, 902(13), 902(14)
- NCSL Computer Crime Statutes: https://www.ncsl.org/technology-and-communication/computer-crime-statutes
