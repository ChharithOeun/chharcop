# Chharcop Risk Scoring Model

> **Version:** v0.2.2
> **Algorithm:** Additive weighted scoring, capped at 100

This document explains exactly how Chharcop grades risk for websites it investigates. The model is fully transparent — no black-box ML, no hidden weights. Every point added to a scan result is traceable to a specific observable signal.

---

## Overview

Chharcop uses an **additive weighted scoring model** on a **0–100 scale**. Each risk signal that fires contributes a fixed number of points to the total. Points accumulate — a site with 3 suspicious signals scores higher than a site with just 1. The total is capped at 100.

This replaced the previous `max(factors)` approach (used before v0.2.2), which only counted the single worst signal and systematically under-scored sites with multiple moderate signals like lookups.io.

---

## Score Thresholds

| Score Range | Risk Level | What It Means |
|-------------|------------|---------------|
| 0           | UNKNOWN    | No signals fired — scanner ran but found nothing suspicious |
| 1–30        | LOW        | Minor concerns, likely legitimate (e.g. short-lived cert on a real company site) |
| 31–60       | MEDIUM     | Meaningful risk indicators — worth caution; may be a data broker, new site, or poor security hygiene |
| 61–80       | HIGH       | Multiple strong signals — treat as suspicious until proven otherwise |
| 81–100      | CRITICAL   | Severe risk profile — likely fraudulent, scam infrastructure, or compromised |

---

## Risk Signals & Weights

All signal detection happens in `chharcop/models.py` → `ScanResult.calculate_risk_score()`.

### Domain Age Signals

| Signal | Points | Trigger Condition |
|--------|--------|-------------------|
| `new_domain` | **+40** | Domain is less than 30 days old |
| `recently_created` | **+20** | Domain is 30–179 days old |

**Why this matters:** Scam infrastructure is almost always newly registered. Legitimate businesses rarely need domains younger than 30 days. This is the single highest-weight signal in the model.

*Note: `new_domain` and `recently_created` are mutually exclusive — only one fires per scan.*

---

### SSL Certificate Signals

| Signal | Points | Trigger Condition |
|--------|--------|-------------------|
| `invalid_cert` | **+40** | Certificate is expired or otherwise invalid |
| `self_signed_cert` | **+35** | Certificate is self-signed (not issued by a trusted CA) |
| `cert_expiring_soon` | **+15** | Certificate expires within 45 days |
| `dv_cert_only` | **+5** | Certificate is Domain Validation (DV) — not OV or EV |

**Why this matters:** Legitimate services maintain valid certificates. An invalid or self-signed cert on a site asking for your money or personal information is a major red flag. DV certs alone are weak evidence (most real sites use them), but they add minor signal weight when other factors are present.

*Note: `invalid_cert` and `self_signed_cert` can both fire if a self-signed cert is also expired.*

---

### Registration / Registrar Signals

| Signal | Points | Trigger Condition |
|--------|--------|-------------------|
| `privacy_registrar` | **+8** | WHOIS registration is privacy-protected (registrant name contains keywords: "privacy", "private", "whoisguard", "domains by proxy", etc.) |
| `discount_registrar` | **+5** | Domain registered with Porkbun, Namecheap, or Namesilo |

**Why this matters:** Privacy WHOIS isn't inherently suspicious — many legitimate developers use it — but it removes accountability and is nearly universal in scam domains. Discount registrars have high abuse rates compared to enterprise registrars like MarkMonitor or CSC Global.

---

### Content & Technology Signals

| Signal | Points | Trigger Condition |
|--------|--------|-------------------|
| `missing_all_trust_signals` | **+20** | All 4 trust signals (Privacy Policy, Terms of Service, Contact page, About page) are absent on a live HTTP 200 page |
| `people_search_site` | **+20** | Page title or meta description matches people-search keywords: "find people", "people search", "background check", "reverse phone", "phone lookup", "public records", etc. |
| `platform_mismatch` | **+10** | Magento (e-commerce platform) detected on a site that also triggered `people_search_site` |
| `suspicious_redirects` | **+15** | Redirect chain has more than 2 hops |
| `cloudflare_proxy` | **+5** | Cloudflare detected in tech stack, server header, or DNS nameservers |

**Why this matters:**

- **Missing trust signals:** Any real website serving the public should have at least a privacy policy. Sites with zero accountability signals are highly suspicious. The threshold is deliberately strict (all 4 must be absent) to avoid penalizing large sites like amazon.com that might omit one.
- **People-search sites:** Data broker / people-search sites traffic in personal information scraped without consent. They score independently of whether they are actively scamming — their business model itself is the signal.
- **Platform mismatch:** Magento is a shopping cart platform. If it appears on a people-search site, the site was likely set up using a purchased or cloned CMS template rather than purpose-built infrastructure — a signal of low-effort scam setup.
- **Suspicious redirects:** Legitimate sites rarely chain more than 2 redirects (e.g. `http://` → `https://` → final URL). Longer chains suggest cloaking, link farms, or affiliate fraud.
- **Cloudflare:** Low-weight signal only. Cloudflare is widely used by legitimate sites. It scores minimally because it also hides the real hosting provider, which slightly reduces accountability.

---

### Gaming Platform Signals (Steam / Discord)

| Signal | Points | Trigger Condition |
|--------|--------|-------------------|
| `steamrep_flagged` | **+50** | SteamRep lists the account as a confirmed scammer |
| `vac_banned` | **+40** | Account has one or more VAC (Valve Anti-Cheat) bans |
| `trade_banned` | **+35** | Account has a trade ban |
| `community_banned` | **+30** | Account has a Steam community ban |
| `discord_scam_patterns` | **+30** | Discord account exhibits known scam bot patterns |
| `new_account_few_games` | **+25** | Steam account is < 30 days old and owns fewer than 5 games |
| `private_profile` | **+10** | Steam profile is set to private |

---

## Calibration Results

These are real scan results used to validate and tune the algorithm. All evidence files are in `evidence/`.

### Round 1 — Initial Calibration (v0.2.2, 2026-03-29)

| Site | Score | Level | Expected | Status | Evidence File |
|------|-------|-------|----------|--------|---------------|
| lookups.io | **68** | HIGH | MEDIUM–HIGH | ✓ Pass | `calibration_lookups_io.json` |
| google.com | **5** | LOW | LOW | ✓ Pass | `calibration_google_com.json` |
| amazon.com | **5** | LOW | LOW | ✓ Pass (was false positive before v0.2.2) | `calibration_amazon_com.json` |
| beenverified.com | **40** | MEDIUM | MEDIUM | ✓ Pass | `calibration_beenverified_com.json` |
| spokeo.com | **5** | LOW | varies | ⚠ Bot-blocked (403) — minimal data collected | `calibration_spokeo_com.json` |

**lookups.io breakdown (68 pts):**
`privacy_registrar`(+8) + `discount_registrar`(+5) + `dv_cert_only`(+5) + `cert_expiring_soon`(+15) + `cloudflare_proxy`(+5) + `people_search_site`(+20) + `platform_mismatch`(+10) = **68**

**beenverified.com breakdown (40 pts):**
`dv_cert_only`(+5) + `cloudflare_proxy`(+5) + `people_search_site`(+20) + `platform_mismatch`(+10) = **40**

---

### Round 2 — Expanded Calibration (v0.2.2, 2026-03-29)

| Site | Score | Level | Expected | Status | Evidence File |
|------|-------|-------|----------|--------|---------------|
| facebook.com | **5** | LOW | LOW | ✓ Pass | `calibration/calibration_facebook_com.json` |
| paypal.com | **0** | UNKNOWN | LOW | ✓ Pass (EV cert, clean record) | `calibration/calibration_paypal_com.json` |
| peoplelooker.com | **53** | MEDIUM | MEDIUM+ | ✓ Pass | `calibration/calibration_peoplelooker_com.json` |
| truthfinder.com | **38** | MEDIUM | MEDIUM+ | ✓ Pass | `calibration/calibration_truthfinder_com.json` |
| fastpeoplesearch.com | **68** | HIGH | MEDIUM–HIGH | ✓ Pass | `calibration/calibration_fastpeoplesearch_com.json` |

**fastpeoplesearch.com breakdown (68 pts):**
`people_search_site`(+20) + `privacy_registrar`(+8) + `discount_registrar`(+5) + `dv_cert_only`(+5) + `cloudflare_proxy`(+5) + `platform_mismatch`(+10) + `cert_expiring_soon`(+15) = **68**

**peoplelooker.com breakdown (53 pts):**
`people_search_site`(+20) + `privacy_registrar`(+8) + `discount_registrar`(+5) + `dv_cert_only`(+5) + `cloudflare_proxy`(+5) + `platform_mismatch`(+10) = **53**

**truthfinder.com breakdown (38 pts):**
`people_search_site`(+20) + `privacy_registrar`(+8) + `dv_cert_only`(+5) + `cloudflare_proxy`(+5) = **38**

---

## False Positive Analysis

| Site | Pre-v0.2.2 Score | Post-v0.2.2 Score | Root Cause |
|------|------------------|-------------------|------------|
| amazon.com | 25 MEDIUM | 5 LOW | Old algorithm counted `missing_trust_signals` when only 3 of 4 were present. Fixed by requiring all 4 to be absent. |
| lookups.io | 0 UNKNOWN | 68 HIGH | Privacy WHOIS keyword "private" not detected. `max()` scoring missed additive multi-signal pattern. |

---

## Known Limitations

- **Bot-blocked sites** (HTTP 403/429): If a site returns a non-200 status, metadata analysis is limited. This can produce artificially low scores (as seen with spokeo.com). The score will not misfire HIGH, but it may score LOW when the true risk is MEDIUM.
- **Cloudflare false positives:** Cloudflare is legitimately used by millions of sites. The +5 weight is intentionally low. It only materially affects the score when combined with other signals.
- **DV certificates:** Nearly all Let's Encrypt certs are DV. The +5 weight is intentionally low for the same reason.
- **Privacy WHOIS on legitimate sites:** Many privacy-conscious developers and small businesses use WHOIS privacy. The +8 weight is calibrated not to push clean sites above LOW on its own.
- **Gaming signals only apply to gaming scans:** The `vac_banned`, `steamrep_flagged` etc. signals do not apply to website scans. They are evaluated separately when running `chharcop gaming` commands.

---

## Source Code Reference

All scoring logic lives in a single method:

```
chharcop/models.py → ScanResult.calculate_risk_score()
```

The method is fully deterministic — given the same collected data, it always produces the same score. There is no ML, no randomness, and no external API calls in the scoring step.
