"""Social behavior section generator for evidence reports."""

from chharcop.models import SocialScanResult

# Human-readable descriptions for each risk factor flag
_FLAG_DESCRIPTIONS: dict[str, str] = {
    "new_account": "Account created within the last 30 days",
    "very_new_account": "Account created within the last 7 days",
    "bot_posting_interval": "Posts at suspiciously regular sub-2-minute intervals",
    "24h_activity_pattern": "Active across 20+ distinct hours — inhuman posting schedule",
    "scam_language_in_bio": "Bio contains scam / urgency language",
    "scam_language_in_posts": "Posts or comments contain scam language",
    "profile_clone_indicator": "Username/display name suggests impersonation",
    "follower_farming": "Following many accounts relative to followers (bot farming)",
    "high_follower_low_engagement": "High follower count but extremely low engagement rate",
    "bot_like_ratio": "Follower-to-following ratio consistent with bot account",
    "low_karma_high_activity": "High post volume but near-zero Reddit karma (spam/bot)",
    "suspicious_subreddits": "Active in subreddits known for fraud or scam activity",
    "account_age_clustering": "Multiple newly-created accounts on different platforms",
    "username_on_5_plus_platforms": "Username registered on 5+ platforms simultaneously",
    "username_on_8_plus_platforms": "Username registered on 8+ platforms — unusual breadth",
}

_RISK_LEVEL_LABELS: dict[str, str] = {
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
    "unknown": "UNKNOWN",
}


def generate_social_section(result: SocialScanResult) -> str:
    """Generate a plain-text summary of the social behavior scan.

    Suitable for embedding in evidence PDF reports or CLI output.

    Args:
        result: Completed SocialScanResult from SocialScanner.scan()

    Returns:
        Multi-line string report section
    """
    risk_label = _RISK_LEVEL_LABELS.get(str(result.risk_level).lower(), "UNKNOWN")
    ts = result.collection_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = [
        "=" * 60,
        "SOCIAL MEDIA BEHAVIOR SCAN",
        "=" * 60,
        f"Username     : {result.username}",
        f"Scan Time    : {ts}",
        f"Risk Score   : {result.risk_score:.0f}/100 [{risk_label}]",
        f"Platforms    : {', '.join(result.platforms_found) if result.platforms_found else 'none found'}",
        "",
    ]

    # Risk indicators
    if result.risk_factors:
        lines.append("RISK INDICATORS")
        lines.append("-" * 40)
        for factor in result.risk_factors:
            desc = _FLAG_DESCRIPTIONS.get(factor, factor.replace("_", " ").capitalize())
            lines.append(f"  [{factor}]")
            lines.append(f"    {desc}")
        lines.append("")

    # Per-platform detail
    seen_platforms: set[str] = set()
    for profile in result.profiles:
        platform = profile.get("platform", "unknown")
        if platform in ("cross_platform",):
            continue  # synthetic entries — already covered by risk_factors
        if platform in seen_platforms:
            continue
        seen_platforms.add(platform)

        if not profile.get("found"):
            continue

        lines.append(f"[{platform.upper()}]")
        lines.append(f"  Username : {profile.get('username', result.username)}")

        age = profile.get("account_age_days")
        if age is not None:
            lines.append(f"  Account Age : {age} days")

        profile_flags = profile.get("flags", [])
        if profile_flags:
            lines.append(f"  Flags : {', '.join(profile_flags)}")

        raw = profile.get("raw_data", {})
        if isinstance(raw, dict):
            if "followers" in raw:
                lines.append(f"  Followers : {raw['followers']:,}")
            if "following" in raw:
                lines.append(f"  Following : {raw['following']:,}")
            if "tweet_count" in raw:
                lines.append(f"  Tweets : {raw['tweet_count']:,}")
            if "total_karma" in raw:
                lines.append(
                    f"  Karma : {raw['total_karma']:,} "
                    f"(link: {raw.get('link_karma', 0):,}, "
                    f"comment: {raw.get('comment_karma', 0):,})"
                )
            if raw.get("subreddit_activity"):
                top = sorted(
                    raw["subreddit_activity"].items(), key=lambda x: x[1], reverse=True
                )[:5]
                lines.append(
                    "  Top Subreddits : "
                    + ", ".join(f"{sr}({n})" for sr, n in top)
                )
            if raw.get("bio"):
                bio_preview = raw["bio"][:120]
                if len(raw["bio"]) > 120:
                    bio_preview += "…"
                lines.append(f"  Bio : {bio_preview}")
            if raw.get("suspicious_subreddits_found"):
                lines.append(
                    f"  Suspicious Subreddits : "
                    f"{', '.join(raw['suspicious_subreddits_found'])}"
                )
            if raw.get("avg_tweet_interval_seconds") is not None:
                lines.append(
                    f"  Avg Post Interval : "
                    f"{raw.get('avg_tweet_interval_seconds', raw.get('avg_post_interval_seconds', 0)):.0f}s"
                )
        lines.append("")

    # Collection errors
    if result.errors:
        lines.append("COLLECTION ERRORS")
        lines.append("-" * 40)
        for err in result.errors:
            lines.append(f"  {err.collector}: {err.error_type} — {err.error_message}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)
