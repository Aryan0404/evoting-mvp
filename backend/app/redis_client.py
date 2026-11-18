import redis.asyncio as aioredis
from app.config import get_settings

settings = get_settings()

# ── Single shared pool instance ────────────────────────────────
_redis_pool: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    """
    Returns a shared async Redis connection pool.
    Initialised once on first call, reused on all subsequent calls.
    """
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=50,
        )
    return _redis_pool


async def close_redis():
    """
    Gracefully close the Redis connection pool on shutdown.
    """
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.aclose()
        _redis_pool = None

# ── Public bulletin board (separate Redis instance) ─────────────────────────
_bulletin_pool: aioredis.Redis | None = None


async def get_bulletin() -> aioredis.Redis:
    """Shared async connection to the public bulletin board store."""
    global _bulletin_pool
    if _bulletin_pool is None:
        _bulletin_pool = aioredis.from_url(
            settings.bulletin_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=50,
        )
    return _bulletin_pool


async def close_bulletin():
    global _bulletin_pool
    if _bulletin_pool is not None:
        await _bulletin_pool.aclose()
        _bulletin_pool = None
