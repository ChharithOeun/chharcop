"""Reddit platform collector using PRAW."""

import asyncio
from datetime import datetime, timezone
from typing import Any

from loguru import logger

from chharcop.social.collectors.base import BaseSocialCollector
from chharcop.social.patterns import SUSPICIOUS_SUBREDDITS, SocialPatterns
from chharcop.utils.config import Config


class RedditCollector(BaseSocialCollector):
    """Collector for Reddit profiles using PRAW (Python Reddit API Wrapper).

    Collects: account age, karma breakdown, subreddit activity, post/comment frequency.

    Flags: low-karma high-activity accounts, suspicious subreddit patterns,
    bot-like posting intervals, scam language in posts/comments.

    Requires REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET environment variables.
    """

    def __init__(self) -> None:
        """Initialize the Reddit collector."""
        super().__init__("RedditCollector")
        self.config = Config()
        self._patterns = SocialPatterns()

    @property
    def platform(self) -> str:
        """Get platform name."""
        return "reddit"

    async def _collect(self, target: str) -> dict[str, Any]:
        """Collect Reddit account data and behaviour signals.

        Args:
            target: Reddit username (with or without u/ prefix)

        Returns:
            Dict with account metrics, activity patterns, and flags
        """
        try:
            import praw  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "praw is required for Reddit collection: pip install praw"
            ) from exc

        client_id = self.config.reddit_client_id
        client_secret = self.config.reddit_client_secret
        if not client_id or not client_secret:
            raise ValueError(
                "REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET environment variables not set"
            )

        reddit = praw.Reddit(
            client_id=client_id,
            client_secret=client_secret,
            user_agent="chharcop:social-scanner:v0.3.0 (scam evidence collector)",
        )

        username = target.lstrip("u/").lstrip("/")
        loop = asyncio.get_event_loop()

        # Force profile load to catch 404 / suspended accounts early
        redditor = await loop.run_in_executor(None, lambda: reddit.redditor(username))
        try:
            await loop.run_in_executor(None, lambda: getattr(redditor, "id"))
        except Exception as exc:
            raise ValueError(f"Reddit user not found or suspended: u/{username}") from exc

        # -----------------------------------------------------------
        # Basic account data
        # -----------------------------------------------------------
        created_utc: float | None = getattr(redditor, "created_utc", None)
        created_at: str | None = None
        account_age_days: int | None = None
        if created_utc:
            created_dt = datetime.fromtimestamp(created_utc, tz=timezone.utc)
            created_at = created_dt.isoformat()
            account_age_days = (datetime.now(timezone.utc) - created_dt).days

        link_karma: int = getattr(redditor, "link_karma", 0)
        comment_karma: int = getattr(redditor, "comment_karma", 0)
        total_karma: int = link_karma + comment_karma
        is_verified_email: bool = bool(getattr(redditor, "has_verified_email", False))
        is_mod: bool = bool(getattr(redditor, "is_mod", False))

        # -----------------------------------------------------------
        # Recent posts and comments (run concurrently)
        # -----------------------------------------------------------
        posts, comments = await asyncio.gather(
            loop.run_in_executor(None, lambda: list(redditor.submissions.new(limit=50))),
            loop.run_in_executor(None, lambda: list(redditor.comments.new(limit=100))),
        )

        # -----------------------------------------------------------
        # Subreddit activity
        # -----------------------------------------------------------
        subreddit_activity: dict[str, int] = {}
        for post in posts:
            sr = f"r/{post.subreddit.display_name}"
            subreddit_activity[sr] = subreddit_activity.get(sr, 0) + 1
        for comment in comments:
            sr = f"r/{comment.subreddit.display_name}"
            subreddit_activity[sr] = subreddit_activity.get(sr, 0) + 1

        suspicious_found: list[str] = [
            sr for sr in subreddit_activity
            if sr.lower().lstrip("r/") in {s.lstrip("r/") for s in SUSPICIOUS_SUBREDDITS}
        ]

        # -----------------------------------------------------------
        # Posting frequency / timing
        # -----------------------------------------------------------
        all_timestamps: list[datetime] = []
        for item in list(posts) + list(comments):
            ts = getattr(item, "created_utc", None)
            if ts:
                all_timestamps.append(datetime.fromtimestamp(ts, tz=timezone.utc))

        post_intervals: list[float] = []
        if len(all_timestamps) > 1:
            sorted_ts = sorted(all_timestamps, reverse=True)
            for i in range(len(sorted_ts) - 1):
                delta = (sorted_ts[i] - sorted_ts[i + 1]).total_seconds()
                post_intervals.append(delta)

        avg_interval_seconds: float | None = (
            sum(post_intervals) / len(post_intervals) if post_intervals else None
        )

        hour_distribution: dict[int, int] = {}
        for ts in all_timestamps:
            h = ts.hour
            hour_distribution[h] = hour_distribution.get(h, 0) + 1
        active_hours = len(hour_distribution)

        # -----------------------------------------------------------
        # Scam language scan (first 20 comments + 10 posts)
        # -----------------------------------------------------------
        scam_language_in_posts = False
        for comment in list(comments)[:20]:
            body: str = getattr(comment, "body", "") or ""
            if self._patterns.has_scam_language(body):
                scam_language_in_posts = True
                break
        if not scam_language_in_posts:
            for post in list(posts)[:10]:
                title: str = getattr(post, "title", "") or ""
                selftext: str = getattr(post, "selftext", "") or ""
                if self._patterns.has_scam_language(title + " " + selftext):
                    scam_language_in_posts = True
                    break

        # -----------------------------------------------------------
        # Flag generation
        # -----------------------------------------------------------
        flags: list[str] = []
        total_items = len(posts) + len(comments)

        if account_age_days is not None and account_age_days < 30:
            flags.append("new_account")
        if account_age_days is not None and account_age_days < 7:
            flags.append("very_new_account")

        if self._patterns.is_low_karma_high_activity(total_karma, total_items):
            flags.append("low_karma_high_activity")

        if suspicious_found:
            flags.append("suspicious_subreddits")

        if self._patterns.is_bot_posting_interval(avg_interval_seconds):
            flags.append("bot_posting_interval")

        if self._patterns.is_24h_activity(active_hours):
            flags.append("24h_activity_pattern")

        if scam_language_in_posts:
            flags.append("scam_language_in_posts")

        logger.debug(
            f"Reddit collection complete for u/{username}: "
            f"{len(flags)} flags, karma={total_karma}, age={account_age_days}d"
        )

        return {
            "platform": "reddit",
            "username": username,
            "user_id": getattr(redditor, "id", None),
            "created_at": created_at,
            "account_age_days": account_age_days,
            "link_karma": link_karma,
            "comment_karma": comment_karma,
            "total_karma": total_karma,
            "is_verified_email": is_verified_email,
            "is_mod": is_mod,
            "post_count": len(posts),
            "comment_count": len(comments),
            "subreddit_activity": subreddit_activity,
            "suspicious_subreddits_found": suspicious_found,
            "avg_post_interval_seconds": avg_interval_seconds,
            "active_hours_count": active_hours,
            "flags": flags,
        }
