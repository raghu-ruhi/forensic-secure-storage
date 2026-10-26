"""Tiny in-memory sliding-window rate limiter for unauthenticated endpoints.

It protects the OTP/e-mail endpoints from being used to spam arbitrary
addresses through the project's mail account, complementing the per-account
cooldowns stored in the database.

Limitation (documented in the README): state lives in each worker process, so
with N gunicorn workers the effective limit is up to N x the configured limit.
The per-account database limits remain exact regardless of worker count.
"""
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import current_app, jsonify, request

_lock = threading.Lock()
_hits = defaultdict(deque)


def reset_rate_limits() -> None:
    with _lock:
        _hits.clear()


def _check(key: str, limit: int, window_seconds: int) -> int:
    """Record a hit. Returns 0 if allowed, else seconds until a slot frees up."""
    now = time.monotonic()
    with _lock:
        q = _hits[key]
        while q and now - q[0] > window_seconds:
            q.popleft()
        if len(q) >= limit:
            return max(1, int(window_seconds - (now - q[0])))
        q.append(now)
        return 0


def _limited_response(retry_after):
    resp = jsonify({"error": f"Too many attempts. Please wait {retry_after}s and try again.",
                    "code": "RATE_LIMITED", "retry_after": retry_after})
    resp.status_code = 429
    resp.headers["Retry-After"] = str(retry_after)
    return resp


def hit_limit(bucket: str, key: str, limit: int, window_seconds: int):
    """Record a hit for an arbitrary key (e.g. a login e-mail). Returns a 429 response or None."""
    if not current_app.config.get("RATELIMIT_ENABLED", True):
        return None
    retry_after = _check(f"{bucket}:{key}", limit, window_seconds)
    return _limited_response(retry_after) if retry_after else None


def ip_rate_limit(bucket: str, limit: int, window_seconds: int):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if current_app.config.get("RATELIMIT_ENABLED", True):
                retry_after = _check(f"{bucket}:{request.remote_addr}", limit, window_seconds)
                if retry_after:
                    resp = jsonify({
                        "error": f"Too many requests. Please wait {retry_after}s and try again.",
                        "code": "RATE_LIMITED",
                        "retry_after": retry_after,
                    })
                    resp.status_code = 429
                    resp.headers["Retry-After"] = str(retry_after)
                    return resp
            return fn(*args, **kwargs)

        return wrapper

    return decorator
