"""In-memory rate limiter middleware.

NOTE:
- Works per-process only. With multiple Uvicorn workers or multiple pods,
  limits will not be shared. Use Redis for production global limits.
"""
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple
from collections import defaultdict, deque
import threading
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    In-memory rate limiter using sliding window with per-minute and per-hour windows.
    Thread-safe. Per-process only.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # Structure: {key: deque[timestamps]}
        self._requests: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20000))
        # Structure: {key: (limit_per_minute, limit_per_hour)}
        self._limits: Dict[str, Tuple[int, int]] = {}

        self._default_limit_per_minute = 100
        self._default_limit_per_hour = 1000

        self._minute_window = timedelta(minutes=1)
        self._hour_window = timedelta(hours=1)

    def set_limit(self, key: str, per_minute: int, per_hour: Optional[int] = None):
        """Set rate limit for a specific key."""
        if per_hour is None:
            per_hour = per_minute * 60
        with self._lock:
            self._limits[key] = (int(per_minute), int(per_hour))

    def get_limit(self, key: str) -> Tuple[int, int]:
        """Get rate limit for a key."""
        return self._limits.get(
            key,
            (self._default_limit_per_minute, self._default_limit_per_hour)
        )

    def _cleanup(self, q: deque, now: datetime):
        """Drop timestamps older than hour window."""
        cutoff = now - self._hour_window
        while q and q[0] <= cutoff:
            q.popleft()

    def _count_since(self, q: deque, since: datetime) -> int:
        """Count timestamps newer than 'since'. q is sorted by time."""
        # Since q is ordered, we can scan from the right or left.
        # Simple linear scan from right is fine for small/medium q.
        # For large q, you’d use bisect, but deque doesn't support indexing efficiently.
        cnt = 0
        for ts in reversed(q):
            if ts > since:
                cnt += 1
            else:
                break
        return cnt

    def _retry_after_seconds(self, q: deque, now: datetime, window: timedelta) -> int:
        """
        Return seconds until the oldest request inside the window expires.
        If there are no requests, return 0.
        """
        cutoff = now - window
        # Find the oldest timestamp still > cutoff (i.e., within window)
        oldest_in_window = None
        for ts in q:
            if ts > cutoff:
                oldest_in_window = ts
                break
        if oldest_in_window is None:
            return 0
        remaining = window.total_seconds() - (now - oldest_in_window).total_seconds()
        return max(1, int(remaining))

    def check_rate_limit(self, key: str) -> Tuple[bool, dict]:
        """
        Check if request is within rate limit.
        Returns: (allowed, info_dict)
        """
        now = datetime.now(timezone.utc)
        per_minute, per_hour = self.get_limit(key)

        with self._lock:
            q = self._requests[key]
            self._cleanup(q, now)

            minute_cutoff = now - self._minute_window
            hour_cutoff = now - self._hour_window

            minute_count = self._count_since(q, minute_cutoff)
            hour_count = self._count_since(q, hour_cutoff)  # after cleanup this is len(q), but keep explicit

            # Deny if over minute limit
            if minute_count >= per_minute:
                retry_after = self._retry_after_seconds(q, now, self._minute_window)
                return False, {
                    "error": "rate_limit_exceeded",
                    "limit_type": "per_minute",
                    "limit": per_minute,
                    "current": minute_count,
                    "retry_after": retry_after,
                    "reset_in": retry_after,
                }

            # Deny if over hour limit
            if hour_count >= per_hour:
                retry_after = self._retry_after_seconds(q, now, self._hour_window)
                return False, {
                    "error": "rate_limit_exceeded",
                    "limit_type": "per_hour",
                    "limit": per_hour,
                    "current": hour_count,
                    "retry_after": retry_after,
                    "reset_in": retry_after,
                }

            # Record request
            q.append(now)

            # Recompute counts after append for accurate remaining
            minute_count += 1
            hour_count += 1

            reset_minute = self._retry_after_seconds(q, now, self._minute_window) or 60
            reset_hour = self._retry_after_seconds(q, now, self._hour_window) or 3600

            return True, {
                "limit_minute": per_minute,
                "limit_hour": per_hour,
                "remaining_minute": max(0, per_minute - minute_count),
                "remaining_hour": max(0, per_hour - hour_count),
                "reset_in_minute": reset_minute,
                "reset_in_hour": reset_hour,
            }

    def reset(self, key: str):
        """Reset rate limit counter for a key."""
        with self._lock:
            self._requests[key].clear()

    def get_stats(self, key: str) -> dict:
        """Get current rate limit stats for a key."""
        now = datetime.now(timezone.utc)
        per_minute, per_hour = self.get_limit(key)

        with self._lock:
            q = self._requests[key]
            self._cleanup(q, now)
            minute_count = self._count_since(q, now - self._minute_window)
            hour_count = self._count_since(q, now - self._hour_window)

            return {
                "key": key,
                "requests_last_minute": minute_count,
                "requests_last_hour": hour_count,
                "limit_per_minute": per_minute,
                "limit_per_hour": per_hour,
                "remaining_minute": max(0, per_minute - minute_count),
                "remaining_hour": max(0, per_hour - hour_count),
            }


rate_limiter = RateLimiter()


async def rate_limit_check(key: str) -> dict:
    """
    Check rate limit and raise exception if exceeded.
    Returns headers to attach to responses.
    """
    from fastapi import HTTPException

    allowed, info = rate_limiter.check_rate_limit(key)

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "limit_type": info["limit_type"],
                "limit": info["limit"],
                "retry_after": info["retry_after"],
            },
            headers={
                "Retry-After": str(info["retry_after"]),
                "X-RateLimit-Limit": str(info["limit"]),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(info.get("reset_in", info["retry_after"])),
            },
        )

    # Return standard-ish headers (minute-based)
    return {
        "X-RateLimit-Limit": str(info["limit_minute"]),
        "X-RateLimit-Remaining": str(info["remaining_minute"]),
        "X-RateLimit-Reset": str(info["reset_in_minute"]),
        # Optional: expose hour window too (handy for clients)
        "X-RateLimit-Limit-Hour": str(info["limit_hour"]),
        "X-RateLimit-Remaining-Hour": str(info["remaining_hour"]),
        "X-RateLimit-Reset-Hour": str(info["reset_in_hour"]),
    }
