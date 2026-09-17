"""
Shared HTTP layer.

Two jobs:
  1. Cache every upstream response in SQLite so a live demo never re-hits the
     network for the same package twice, and so a scan is repeatable offline.
  2. Track per-source availability. RippleGuard talks to five public APIs and
     any of them can be down, rate-limited or blocked by a corporate proxy.
     When one is unavailable we degrade the analysis and SAY SO in the UI
     rather than silently producing a score that looks complete.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS http_cache (
    key        TEXT PRIMARY KEY,
    status     INTEGER NOT NULL,
    body       TEXT NOT NULL,
    fetched_at REAL NOT NULL
);
"""


class HttpCache:
    """Tiny persistent response cache. Thread-safe enough for our use."""

    def __init__(self, path: str, ttl: int):
        self.path = path
        self.ttl = ttl
        self._lock = asyncio.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    async def get(self, key: str) -> tuple[int, Any] | None:
        async with self._lock:
            row = self._conn.execute(
                "SELECT status, body, fetched_at FROM http_cache WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        status, body, fetched_at = row
        if self.ttl > 0 and (time.time() - fetched_at) > self.ttl:
            return None
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return None

    async def put(self, key: str, status: int, payload: Any) -> None:
        async with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO http_cache (key, status, body, fetched_at) "
                "VALUES (?, ?, ?, ?)",
                (key, status, json.dumps(payload), time.time()),
            )
            self._conn.commit()

    async def any_cached(self, prefix: str) -> bool:
        async with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM http_cache WHERE key LIKE ? LIMIT 1", (prefix + "%",)
            ).fetchone()
        return row is not None


@dataclass
class SourceHealth:
    """What we know about each upstream API during this process's lifetime."""

    name: str
    reachable: bool | None = None       # None = not yet tried
    calls: int = 0
    cache_hits: int = 0
    failures: int = 0
    last_error: str = ""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        state = (
            "unknown"
            if self.reachable is None
            else ("available" if self.reachable else "unavailable")
        )
        return {
            "name": self.name,
            "state": state,
            "calls": self.calls,
            "cache_hits": self.cache_hits,
            "failures": self.failures,
            "last_error": self.last_error[:220],
        }


class Fetcher:
    """Async JSON fetcher with cache, bounded concurrency and health tracking."""

    def __init__(self) -> None:
        self.cache = HttpCache(settings.cache_path, settings.cache_ttl_seconds)
        self.health: dict[str, SourceHealth] = {}
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._client: httpx.AsyncClient | None = None

    def _h(self, source: str) -> SourceHealth:
        return self.health.setdefault(source, SourceHealth(name=source))

    async def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=settings.http_timeout,
                follow_redirects=True,
                headers={"User-Agent": "RippleGuard/0.1 (hackathon prototype)"},
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_json(
        self,
        source: str,
        url: str,
        *,
        headers: dict | None = None,
        allow_404: bool = True,
    ) -> Any | None:
        return await self._request(
            source, "GET", url, headers=headers, allow_404=allow_404
        )

    async def post_json(
        self,
        source: str,
        url: str,
        payload: Any,
        *,
        headers: dict | None = None,
    ) -> Any | None:
        return await self._request(
            source, "POST", url, json_body=payload, headers=headers
        )

    async def _request(
        self,
        source: str,
        method: str,
        url: str,
        *,
        json_body: Any = None,
        headers: dict | None = None,
        allow_404: bool = True,
    ) -> Any | None:
        health = self._h(source)
        key = f"{source}|{method}|{url}"
        if headers:
            # Accept headers change the response shape (npm's abbreviated vs full
            # packument live at the same URL), so they must be part of the key.
            key += "|h=" + json.dumps(sorted(headers.items()))
        if json_body is not None:
            key += "|" + json.dumps(json_body, sort_keys=True)

        cached = await self.cache.get(key)
        if cached is not None:
            status, payload = cached
            health.cache_hits += 1
            if health.reachable is None:
                health.reachable = True
            return payload if status < 400 else None

        if settings.offline:
            health.reachable = False
            health.last_error = "offline mode: no cached response for this request"
            return None

        async with self._sem:
            try:
                client = await self.client()
                health.calls += 1
                if method == "GET":
                    resp = await client.get(url, headers=headers)
                else:
                    resp = await client.post(url, json=json_body, headers=headers)
            except Exception as exc:  # network down, DNS, proxy block, timeout
                health.failures += 1
                health.reachable = False
                health.last_error = f"{type(exc).__name__}: {exc}"
                return None

        if resp.status_code == 404 and allow_404:
            health.reachable = True
            await self.cache.put(key, 404, None)
            return None
        if resp.status_code >= 400:
            health.failures += 1
            health.last_error = f"HTTP {resp.status_code} for {url}"
            # 403/429 from a proxy or rate limiter means the source is not usable.
            if resp.status_code in (401, 403, 429) or resp.status_code >= 500:
                health.reachable = False
            return None

        try:
            payload = resp.json()
        except Exception as exc:
            health.failures += 1
            health.last_error = f"non-JSON response: {exc}"
            return None

        health.reachable = True
        await self.cache.put(key, resp.status_code, payload)
        return payload

    def health_report(self) -> list[dict]:
        return [h.as_dict() for h in self.health.values()]

    def reset_health(self) -> None:
        self.health.clear()


fetcher = Fetcher()
