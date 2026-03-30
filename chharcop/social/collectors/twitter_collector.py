"""Twitter/X platform collector using API v2 (tweepy)."""

import asyncio
from datetime import datetime, timezone
from typing import Any

from loguru import logger

from chharcop.social.collectors.base import BaseSocialCollector
from chharcop.social.patterns import SocialPatterns
from chharcop.utils.config import Config


class TwitterCollector(BaseSocialCollector):
    """Collector for Twitter/X profiles using the v2 API via tweepy.

    Collects: account age, follower/following ratio, tweet frequency,
    bio analysis, and link patterns.

    Flags: bot-like intervals, follower farming, scam language in bio.

    Requires TWITTER_BEARER_TOKEN environment variable.
    """

    def __init__(self) -> None:
        """Initialize the Twitter collector."""
        super().__init__("TwitterCollector")
        self.config = Config()
        self._patterns = SocialPatterns()

    @property
    def platform(self) -> str:
        """Get platform name."""
        return "twitter"

    async def _collect(self, target: str) -> dict[str, Any]:
        """Collect Twitter profile and behaviour data.

        Args:
            target: Twitter username (with or without @)

        Returns:
            Dict with profile metrics, timing analysis, and flags
        """
        try:
            import tweepy  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "tweepy is required for Twitter collection: pip install tweepy"
            ) from exc

        bearer_token = self.config.twitter_bearer_token
        if not bearer_token:
            raise ValueError("TWITTER_BEARER_TOKEN environment variable not set")

        username = target.lstrip("@")
        client = tweepy.Client(bearer_token=bearer_token, wait_on_rate_limit=False)
        loop = asyncio.get_event_loop()

        # -----------------------------------------------------------
        # Fetch user profile
        # -----------------------------------------------------------
        user_response = await loop.run_in_executor(
            None,
            lambda: client.get_user(
                username=username,
                user_fields=[
                    "created_at",
                    "description",
                    "entities",
                    "public_metrics",
                    "verified",
                    "protected",
                    "url",
                    "profile_image_url",
                    "withheld",
                ],
            ),
        )

        if not user_response.data:
            raise ValueError(f"Twitter user not found: @{username}")

        user = user_response.data
        metrics: dict[str, Any] = user.public_metrics or {}

        # Account age
        created_at: datetime | None = user.created_at
        account_age_days: int | None = None
        if created_at:
            account_age_days = (datetime.now(timezone.utc) - created_at).days

        # Counts
        followers: int = metrics.get("followers_count", 0)
        following: int = metrics.get("following_count", 0)
        tweet_count: int = metrics.get("tweet_count", 0)
        listed_count: int = metrics.get("listed_count", 0)
        ff_ratio: float = followers / following if following > 0 else float("inf")

        # -----------------------------------------------------------
        # Fetch recent tweets for frequency / timing analysis
        # -----------------------------------------------------------
        tweets_response = await loop.run_in_executor(
            None,
            lambda: client.get_users_tweets(
                id=user.id,
                max_results=100,
                tweet_fields=["created_at", "public_metrics"],
                exclude=["retweets", "replies"],
            ),
        )

        tweets_data = tweets_response.data or []

        # Average posting interval
        tweet_intervals: list[float] = []
        if len(tweets_data) > 1:
            timestamps = sorted(
                [t.created_at for t in tweets_data if t.created_at],
                reverse=True,
            )
            for i in range(len(timestamps) - 1):
                delta = (timestamps[i] - timestamps[i + 1]).total_seconds()
                tweet_intervals.append(delta)

        avg_interval_seconds: float | None = (
            sum(tweet_intervals) / len(tweet_intervals) if tweet_intervals else None
        )

        # Hour distribution (bot indicator: active across many hours)
        hour_distribution: dict[int, int] = {}
        for tweet in tweets_data:
            if tweet.created_at:
                h = tweet.created_at.hour
                hour_distribution[h] = hour_distribution.get(h, 0) + 1
        active_hours = len(hour_distribution)

        # Average likes on sampled tweets
        total_likes = sum(
            (t.public_metrics or {}).get("like_count", 0) for t in tweets_data
        )

        # -----------------------------------------------------------
        # Bio / links
        # -----------------------------------------------------------
        bio: str = user.description or ""
        bio_links: list[str] = []
        if user.entities:
            desc_entities = getattr(user.entities, "description", None)
            if desc_entities:
                urls = getattr(desc_entities, "urls", None) or []
                for u in urls:
                    expanded = getattr(u, "expanded_url", None)
                    if expanded:
                        bio_links.append(expanded)

        # -----------------------------------------------------------
        # Flag generation
        # -----------------------------------------------------------
        flags: list[str] = []

        if account_age_days is not None and account_age_days < 30:
            flags.append("new_account")
        if account_age_days is not None and account_age_days < 7:
            flags.append("very_new_account")

        if self._patterns.is_bot_posting_interval(avg_interval_seconds):
            flags.append("bot_posting_interval")

        if self._patterns.is_24h_activity(active_hours):
            flags.append("24h_activity_pattern")

        if self._patterns.is_follower_farming(followers, following):
            flags.append("follower_farming")

        if self._patterns.is_high_follower_low_engagement(
            followers, total_likes, len(tweets_data)
        ):
            flags.append("high_follower_low_engagement")

        if self._patterns.has_scam_language(bio):
            flags.append("scam_language_in_bio")

        if self._patterns.is_likely_clone(username, user.name or ""):
            flags.append("profile_clone_indicator")

        # Protected accounts hide content — note but don't flag harshly
        protected: bool = bool(user.protected)

        logger.debug(
            f"Twitter collection complete for @{username}: "
            f"{len(flags)} flags, age={account_age_days}d"
        )

        return {
            "platform": "twitter",
            "username": user.username,
            "display_name": user.name,
            "user_id": str(user.id),
            "created_at": created_at.isoformat() if created_at else None,
            "account_age_days": account_age_days,
            "followers": followers,
            "following": following,
            "tweet_count": tweet_count,
            "listed_count": listed_count,
            "ff_ratio": ff_ratio,
            "verified": bool(user.verified),
            "protected": protected,
            "bio": bio,
            "bio_links": bio_links,
            "avg_tweet_interval_seconds": avg_interval_seconds,
            "active_hours_count": active_hours,
            "sampled_tweets": len(tweets_data),
            "avg_likes_per_tweet": total_likes / len(tweets_data) if tweets_data else 0,
            "flags": flags,
        }
