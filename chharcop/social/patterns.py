"""Scam behavior pattern detection for social media."""

import re

# ---------------------------------------------------------------------------
# Scam language patterns (regex, case-insensitive applied at call site)
# ---------------------------------------------------------------------------

SCAM_LANGUAGE_PATTERNS: list[str] = [
    # Urgency / pressure
    r"\blimited\s+time\b",
    r"\bact\s+now\b",
    r"\burgent\b",
    r"\bhurry\b",
    r"\blast\s+chance\b",
    r"\bexpires?\s+soon\b",
    r"\btoday\s+only\b",
    r"\bdon'?t\s+miss\s+out\b",
    # Off-platform contact requests
    r"\bdm\s+me\b",
    r"\bslide\s+into\b",
    r"\bmessage\s+me\b",
    r"\binbox\s+me\b",
    r"\bwhatsapp\b",
    r"\btelegram\b",
    r"\bkik\b",
    r"\bcontact\s+me\b",
    # Crypto / forex spam
    r"\bbitcoin\b",
    r"\bbtc\b",
    r"\bethereumm?\b",
    r"\bcrypto\s+(?:invest|earn|profit|signal)\b",
    r"\bforex\s+(?:trading|signal|profit)\b",
    r"\btrading\s+signals?\b",
    r"\binvestment\s+opp(?:ortunit)?\b",
    r"\bdouble\s+your\s+(?:money|bitcoin|btc)\b",
    r"\bpassive\s+income\b",
    r"\bget\s+rich\s+quick\b",
    r"\b100%\s+profit\b",
    r"\bguaranteed\s+returns?\b",
    r"\bnft\s+(?:drop|mint|giveaway)\b",
    # Payment / gift card schemes
    r"\bgift\s+card\b",
    r"\bitunes\s+card\b",
    r"\bgoogle\s+play\s+card\b",
    r"\bsteam\s+(?:gift\s+)?card\b",
    r"\bcash\s*app\b",
    r"\bvenmo\b",
    r"\bpaypal\s+(?:me|send|transfer)\b",
    r"\bzelle\b",
    # Giveaway / prize scams
    r"\bgiveaway\b",
    r"\bfree\s+(?:iphone|ps5|xbox|nintendo|gift|money|bitcoin)\b",
    r"\byou(?:'ve|\s+have)\s+won\b",
    r"\bcongratulations[,!\s]",
    r"\bselected\s+(?:as\s+)?(?:a\s+)?winner\b",
    # Romance / relationship scams
    r"\blooking\s+for\s+(?:love|relationship|partner)\b",
    r"\bsingle\s+(?:lady|woman|man|girl|guy|mom|dad)\b",
    r"\bwidow(?:er)?\b",
    r"\bmilitary\s+(?:officer|man|woman|deployed)\b",
    # Impersonation signals
    r"\bofficial\s+(?:account|page|support)\b",
    r"\bverified\s+(?:account|page)\b",
    r"\breal\s+\w+\s+(?:here|official)\b",
    r"\bthe\s+real\s+\w+\b",
]

# ---------------------------------------------------------------------------
# Bot detection thresholds
# ---------------------------------------------------------------------------

BOT_POSTING_INTERVAL_SECONDS = 120   # avg interval < 2 min → suspicious
BOT_24H_ACTIVE_HOURS = 20            # active in ≥ 20 distinct hours → suspicious

# ---------------------------------------------------------------------------
# Fake follower / follower-farming thresholds
# ---------------------------------------------------------------------------

FOLLOWER_FARMING_FOLLOW_RATIO = 0.1    # followers/following < 10% = farming
FOLLOWER_FARMING_MIN_FOLLOWING = 500   # only check when following ≥ 500
HIGH_FOLLOWER_LOW_ENGAGEMENT = 0.005   # engagement rate < 0.5% on high-follower accounts
HIGH_FOLLOWER_THRESHOLD = 10_000       # apply engagement check above this follower count

# ---------------------------------------------------------------------------
# Suspicious Reddit subreddits (scam-prone or high-abuse communities)
# ---------------------------------------------------------------------------

SUSPICIOUS_SUBREDDITS: frozenset[str] = frozenset({
    "r/cryptomoonshots",
    "r/satoshistreetbets",
    "r/wallstreetbetscrypto",
    "r/shitcoinstreet",
    "r/dogecoin",
    "r/forex",
    "r/giftcardexchange",
    "r/steamgameswap",
    "r/hardwareswap",
    "r/phishing",
    "r/scambait",          # not inherently bad, but watch for context
    "r/beermoneyglobal",
    "r/slavelabour",
})

# ---------------------------------------------------------------------------
# Account age clustering (organised scam indicator)
# ---------------------------------------------------------------------------

CLUSTER_AGE_DAYS = 30          # accounts < 30 days considered "fresh"
CLUSTER_MIN_PLATFORMS = 2      # need at least 2 fresh accounts to flag clustering


class SocialPatterns:
    """Pattern detection for social media scam behaviors."""

    # ------------------------------------------------------------------
    # Language checks
    # ------------------------------------------------------------------

    def has_scam_language(self, text: str) -> bool:
        """Return True if text contains any scam language pattern."""
        if not text:
            return False
        text_lower = text.lower()
        return any(re.search(p, text_lower) for p in SCAM_LANGUAGE_PATTERNS)

    def scam_language_matches(self, text: str) -> list[str]:
        """Return list of pattern strings that matched in text."""
        if not text:
            return []
        text_lower = text.lower()
        return [p for p in SCAM_LANGUAGE_PATTERNS if re.search(p, text_lower)]

    # ------------------------------------------------------------------
    # Bot behaviour checks
    # ------------------------------------------------------------------

    def is_bot_posting_interval(self, avg_interval_seconds: float | None) -> bool:
        """True if average post interval is suspiciously short."""
        if avg_interval_seconds is None:
            return False
        return avg_interval_seconds < BOT_POSTING_INTERVAL_SECONDS

    def is_24h_activity(self, active_hours: int) -> bool:
        """True if account is active across an inhuman spread of hours."""
        return active_hours >= BOT_24H_ACTIVE_HOURS

    # ------------------------------------------------------------------
    # Follower / engagement checks
    # ------------------------------------------------------------------

    def is_follower_farming(self, followers: int, following: int) -> bool:
        """True if follow ratio looks like a follow-farming bot account."""
        if following < FOLLOWER_FARMING_MIN_FOLLOWING:
            return False
        if following == 0:
            return False
        return (followers / following) < FOLLOWER_FARMING_FOLLOW_RATIO

    def is_high_follower_low_engagement(
        self, followers: int, likes: int, tweets_sampled: int
    ) -> bool:
        """True if high-follower account has suspiciously low engagement."""
        if followers < HIGH_FOLLOWER_THRESHOLD or tweets_sampled == 0:
            return False
        avg_likes = likes / tweets_sampled
        return (avg_likes / followers) < HIGH_FOLLOWER_LOW_ENGAGEMENT

    # ------------------------------------------------------------------
    # Account age clustering
    # ------------------------------------------------------------------

    def is_account_age_clustering(self, account_ages: list[int | None]) -> bool:
        """True if ≥ 2 platforms have accounts that are all newly created."""
        valid = [a for a in account_ages if a is not None]
        if len(valid) < CLUSTER_MIN_PLATFORMS:
            return False
        return all(a <= CLUSTER_AGE_DAYS for a in valid)

    # ------------------------------------------------------------------
    # Profile clone / impersonation
    # ------------------------------------------------------------------

    def is_likely_clone(self, username: str, display_name: str) -> bool:
        """True if the username/display name uses impersonation language."""
        text = f"{username} {display_name}".lower()
        clone_patterns = [
            r"\bofficial\b",
            r"\bthe[\s_\-]?real\b",
            r"\breal[\s_\-]?\w+\b",
            r"\bverified[\s_\-]\w+\b",
            r"\blegit[\s_\-]\w+\b",
            r"\boriginal[\s_\-]\w+\b",
        ]
        return any(re.search(p, text) for p in clone_patterns)

    # ------------------------------------------------------------------
    # Reddit-specific
    # ------------------------------------------------------------------

    def has_suspicious_subreddit_activity(self, subreddits: list[str]) -> bool:
        """True if account is active in known scam-prone subreddits."""
        normalized = {s.lower().lstrip("r/") for s in subreddits}
        return bool(normalized & {s.lstrip("r/") for s in SUSPICIOUS_SUBREDDITS})

    def is_low_karma_high_activity(
        self, total_karma: int, total_posts_comments: int
    ) -> bool:
        """True if account posts a lot but has almost no karma (likely bot/spam)."""
        if total_posts_comments < 20:
            return False
        return total_karma < 50
