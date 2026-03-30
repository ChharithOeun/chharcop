# Security Audit — Chharcop

**Audit date:** 2026-03-29
**Auditor:** Automated multi-agent analysis + manual review
**Scope:** All Python source files under `chharcop/` (v0.3.0)
**Result:** 10 vulnerabilities fixed (2 Critical, 5 High, 3 Medium)

---

## Methodology

Seven parallel audit agents examined the codebase across these categories:

1. Classic injection vulnerabilities (SQLi, command injection, path traversal, SSRF)
2. Privacy / PII handling (logging, storage, file permissions)
3. Malicious code detection (eval/exec, obfuscation, unexpected network calls)
4. VPN weak points (WireGuard, Tor)
5. Dependency audit (CVEs, typosquatting, loose pins)
6. Input validation (CLI, intake, API responses)
7. Authentication & authorization

---

## Findings and Fixes

### CRITICAL

#### C-1 — SSRF via private IP addresses in URL validator
- **File:** `chharcop/utils/url_validator.py`
- **Severity:** CRITICAL
- **Description:** `validate_url()` accepted URLs pointing to `127.x.x.x`, `10.x.x.x`,
  `192.168.x.x`, `172.16-31.x.x`, `::1`, `fe80::/10`, and other private/loopback ranges.
  Any collector that called `validate_url()` before making an HTTP request could be redirected
  to internal infrastructure (SSRF).
- **Proof of concept:** `validate_url("http://127.0.0.1/admin")` returned `False` only
  because `is_valid_domain` rejected bare IPs, but `validate_url("http://192.168.1.1/")` with
  a resolvable-looking host could pass.  Protocol-relative URLs (`//evil.com`) were also
  silently prepended with `https://`.
- **Fix applied:**
  - Added `_is_private_host()` helper using `ipaddress.ip_address()` that rejects all
    private, loopback, link-local, and reserved addresses (IPv4 + IPv6).
  - `validate_url()` now calls `_is_private_host()` on the parsed hostname and returns
    `False` immediately if the check fails.
  - Protocol-relative URLs (`//...`) are now explicitly rejected by `validate_url()` and
    normalised to `https:` by `extract_domain()` / `normalize_url()`.

#### C-2 — SQL injection via dynamic column names in `_update()`
- **File:** `chharcop/report/auto_submit.py`, `_update()` method
- **Severity:** CRITICAL
- **Description:** `_update()` built an `UPDATE` SQL statement by joining kwargs keys
  directly into the query string with an f-string (`f"UPDATE submissions SET {cols} WHERE id=?"`).
  Although values were parameterised, column names were not.  An attacker who could influence
  the kwargs keys (e.g., via a crafted scan ID that propagated through the call chain) could
  inject arbitrary SQL.
- **Proof of concept:** Passing `_update(1, **{"status; DROP TABLE submissions; --": "x"})`
  would execute `UPDATE submissions SET status; DROP TABLE submissions; --=? WHERE id=?`.
- **Fix applied:** Added `_UPDATABLE_COLUMNS` class-level frozenset containing the seven
  legitimate column names.  `_update()` now filters kwargs against this whitelist before
  constructing the SQL; unknown keys are silently discarded.

---

### HIGH

#### H-1 — SSRF via unvalidated redirects in metadata collector
- **File:** `chharcop/web/collectors/metadata_collector.py`
- **Severity:** HIGH
- **Description:** `httpx.AsyncClient(follow_redirects=True)` without redirect validation
  would follow a chain of redirects from a public URL to an internal service
  (e.g., `http://attacker.com → http://169.254.169.254/latest/meta-data/`).
  No maximum redirect count was set (httpx default is 20).
- **Fix applied:**
  - Added `_is_safe_url()` static method using `ipaddress` to reject private/loopback hosts.
  - Each URL in the redirect history is now checked; an exception is raised immediately if
    any redirect destination (including the final URL) is a private address.
  - Explicit `max_redirects=10` added to the client constructor.

#### H-2 — Path traversal / interface name injection in WireGuard
- **File:** `chharcop/vpn/wireguard.py`
- **Severity:** HIGH
- **Description:** The `interface` parameter to `connect()`, `disconnect()`,
  `save_config()`, and `load_config()` was passed directly to `Path` and to
  `asyncio.create_subprocess_exec` via `wg-quick`.  A value such as
  `../../etc/cron.d/evil` could escape the config directory; and while
  `create_subprocess_exec` does not use a shell, a crafted name could still reference
  unexpected files.
- **Fix applied:** Added `_validate_interface_name()` which enforces the regex
  `[a-zA-Z0-9_\-]{1,15}` (matching Linux's 15-char interface name limit).
  `connect()` and `disconnect()` return an error status on validation failure;
  `save_config()` and `load_config()` raise `ValueError`.

#### H-3 — URL parameter injection in gamertag OSINT collector
- **File:** `chharcop/gaming/collectors/gamertag_osint.py`
- **Severity:** HIGH
- **Description:** Gamertag strings were interpolated directly into URLs without encoding.
  A gamertag of `../admin` or `test?key=injected` could produce malformed or unintended URLs,
  bypass URL-based access controls, or inject additional query parameters.
- **Fix applied:** Imported `urllib.parse.quote` and wrapped every gamertag interpolation with
  `quote(gamertag, safe="")` in `_search_steam()`, `_search_xbox()`, and `_search_psn()`.

#### H-4 — URL parameter injection in Steam API collector
- **File:** `chharcop/gaming/collectors/steam_collector.py`
- **Severity:** HIGH
- **Description:** Both `vanity_or_id` (user-supplied) and `steam_id` (resolved, but
  potentially tainted) were interpolated unencoded into query strings across five API
  call methods (`_resolve_vanity_url`, `_get_player_summary`, `_get_player_bans`,
  `_get_owned_games`, `_get_friend_list`, `_get_steamrep_status`).
- **Fix applied:** Imported `urllib.parse.quote`; all six URL constructions now use
  `quote(steam_id, safe="")` or `quote(vanity_or_id, safe="")`.

#### H-5 — Path traversal in voicemail file copy
- **File:** `chharcop/intake/phone_intake.py`, `process_voicemail()`
- **Severity:** HIGH
- **Description:** `audio_path.name` strips directory components, but `audio_path` itself
  could point anywhere on the filesystem.  A crafted path like
  `Path("/etc/passwd")` would copy `/etc/passwd` into the voicemails directory.
  More critically, if the voicemail filename itself contained `..` components (possible
  on some filesystems), the copy destination could escape `voicemail_dir`.
- **Fix applied:**
  - Extracted `safe_name = Path(audio_path.name)` and verified that `safe_name.name ==
    audio_path.name` (i.e., no path separators slipped in).
  - Added a `resolve().relative_to()` check to ensure the destination stays within
    `voicemail_dir` even if symlinks are involved.
  - Set `dest.chmod(0o600)` on newly copied files.

---

### MEDIUM

#### M-1 — PII (phone numbers) logged in plaintext
- **File:** `chharcop/intake/phone_intake.py`
- **Severity:** MEDIUM
- **Description:** Three `logger.info` / `logger.warning` calls printed full phone numbers
  (`phone`, `primary_phone`) directly.  Log files may be stored in plaintext, rotated to
  shared storage, or forwarded to log aggregators — leaking PII.
- **Fix applied:** All three call sites now log only the last four digits
  (`***{phone[-4:]}`), consistent with common PII-redaction standards.

#### M-2 — Cache directory created with default (world-readable) permissions
- **File:** `chharcop/utils/config.py`, `ensure_cache_dir()`
- **Severity:** MEDIUM
- **Description:** `Path.mkdir(parents=True, exist_ok=True)` uses the process umask, which
  commonly produces `0o755` (world-readable).  The cache directory stores API responses and
  scan artefacts that may contain sensitive target information.
- **Fix applied:** `ensure_cache_dir()` now calls `self.cache_dir.chmod(0o700)` immediately
  after `mkdir()`.  The call is wrapped in `try/except NotImplementedError` to gracefully
  handle Windows (which does not support POSIX permissions).

#### M-3 — Redirect loop / DoS in metadata collector
- **File:** `chharcop/web/collectors/metadata_collector.py`
- **Severity:** MEDIUM
- **Description:** No explicit redirect limit meant a site could return up to httpx's default
  of 20 consecutive redirects, wasting resources and potentially causing DoS against the
  scanner process.
- **Fix applied:** Resolved as part of H-1 fix — `max_redirects=10` is now set explicitly.

---

## Items Reviewed and Found Clean

| Area | Finding |
|------|---------|
| `subprocess` / shell usage | All calls use `asyncio.create_subprocess_exec` with list args — no `shell=True` anywhere |
| `eval` / `exec` | Not used in any production module |
| `pickle` / `yaml.load` | Not used; no insecure deserialization |
| Hardcoded secrets | No API keys, passwords, or tokens in source files; all loaded from env vars |
| Obfuscated code | None detected |
| Unexpected network calls | All external calls go to documented public APIs (Steam, Discord, Tor, FTC, IC3, etc.) |
| Data exfiltration patterns | None detected |
| Typosquatted dependencies | All 17 packages verified as legitimate |
| `random` for security | Not used for security purposes; `uuid.uuid4()` used for IDs |
| XML parsing / XXE | HTML parsed with `html.parser` (safe); no XML parsing present |
| Regex DoS | Patterns in `social/patterns.py` are simple non-backtracking literals |
| Dependency `beautifulsoup4` | Uses `html.parser` throughout — not vulnerable to XXE |
| WireGuard config file permissions | Already set to `0o600` before this audit |
| API keys in logs | Only presence (not value) is logged at DEBUG level |

---

## Residual / Won't-Fix

| Item | Reason |
|------|--------|
| WireGuard kill switch | OS-level firewall rules are out of scope for a Python library; users should configure a system kill switch (e.g., `wg-quick` `PostUp`/`PreDown` rules) |
| Tor circuit isolation per-scan | `new_identity()` exists and is documented; enforcing it at the library level would break valid multi-request workflows |
| PII encryption at rest (SQLite) | The tool is local-only with no network-exposed DB; SQLCipher integration is a future enhancement |
| reportlab version pin | No CVE affects the currently required `>=4.1.0` range; added to monitoring backlog |

---

## Dependency Summary

All dependencies pass typosquatting review.  No known CVEs for the minimum required
versions at the time of this audit (2026-03-29).  Packages to monitor for future
security advisories:

- `reportlab` — PDF generation; has had historical injection issues in older versions
- `cryptography` — version-sensitive; monitor PyCA security advisories
- `playwright` (optional) — browser automation; keep updated
