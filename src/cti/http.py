"""Shared polite HTTP client.

- Conditional requests (ETag / If-Modified-Since) persisted in `http_cache`.
- Retries with exponential backoff on 429/5xx/network errors, honouring Retry-After.
- robots.txt checked for HTML page fetches (APIs and feeds are published for machine use).
- Per-host minimum delay between requests.
- Response size cap: collected content is data, never executed, never written to disk.
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.robotparser
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session

from cti import USER_AGENT
from cti.db.models import HttpCache

log = logging.getLogger(__name__)

MAX_BYTES = 50 * 1024 * 1024
RETRY_STATUS = {429, 500, 502, 503, 504}


class FetchError(Exception):
    pass


class RobotsDisallowed(FetchError):
    pass


@dataclass
class FetchResult:
    url: str
    status: int
    content: bytes
    headers: httpx.Headers
    not_modified: bool = False

    @property
    def text(self) -> str:
        enc = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype:
            enc = ctype.split("charset=")[-1].split(";")[0].strip() or "utf-8"
        return self.content.decode(enc, errors="replace")

    def json(self):
        import json

        return json.loads(self.content)


class HttpClient:
    def __init__(
        self,
        session: Session | None = None,
        *,
        timeout: float = 30.0,
        max_retries: int = 4,
        min_host_interval: float = 1.0,
        transport: httpx.BaseTransport | None = None,
        throttle: bool = True,
    ):
        self.session = session
        self.max_retries = max_retries
        self.min_host_interval = min_host_interval
        self.throttle = throttle  # False only in tests (recorded fixtures, no remote server)
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
            transport=transport,
        )
        self._last_hit: dict[str, float] = {}
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}
        self._lock = threading.Lock()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    def _throttle(self, host: str, min_interval: float | None) -> None:
        if not self.throttle:
            return
        interval = self.min_host_interval if min_interval is None else min_interval
        with self._lock:
            wait = self._last_hit.get(host, 0) + interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_hit[host] = time.monotonic()

    def robots_allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        base = f"{parts.scheme}://{parts.netloc}"
        if base not in self._robots:
            rp = urllib.robotparser.RobotFileParser()
            try:
                r = self._client.get(base + "/robots.txt", timeout=15)
                if r.status_code >= 400:
                    rp = None  # no robots.txt => allowed
                else:
                    rp.parse(r.text.splitlines())
            except httpx.HTTPError:
                rp = None
            self._robots[base] = rp
        rp = self._robots[base]
        return True if rp is None else rp.can_fetch(USER_AGENT, url)

    # ------------------------------------------------------------------
    def get(
        self,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        conditional: bool = False,
        check_robots: bool = False,
        min_interval: float | None = None,
    ) -> FetchResult:
        if check_robots and not self.robots_allowed(url):
            raise RobotsDisallowed(f"robots.txt interdit {url}")
        req_headers = dict(headers or {})
        cache_row = None
        cache_key = str(httpx.URL(url, params=params))
        if conditional and self.session is not None:
            cache_row = self.session.get(HttpCache, cache_key)
            if cache_row:
                if cache_row.etag:
                    req_headers["If-None-Match"] = cache_row.etag
                if cache_row.last_modified:
                    req_headers["If-Modified-Since"] = cache_row.last_modified

        host = urlsplit(url).netloc
        attempt = 0
        while True:
            attempt += 1
            self._throttle(host, min_interval)
            try:
                resp = self._client.get(url, params=params, headers=req_headers)
            except httpx.HTTPError as e:
                if attempt > self.max_retries:
                    raise FetchError(f"{type(e).__name__} sur {host}: {e}") from e
                self._backoff(attempt, None)
                continue
            if resp.status_code in RETRY_STATUS and attempt <= self.max_retries:
                self._backoff(attempt, resp.headers.get("retry-after"))
                continue
            break

        if resp.status_code == 304:
            return FetchResult(url, 304, b"", resp.headers, not_modified=True)
        if resp.status_code >= 400:
            raise FetchError(f"HTTP {resp.status_code} sur {cache_key.split('?')[0]}")
        if len(resp.content) > MAX_BYTES:
            raise FetchError(f"réponse trop volumineuse ({len(resp.content)} octets)")

        if conditional and self.session is not None:
            etag, lm = resp.headers.get("etag"), resp.headers.get("last-modified")
            if etag or lm:
                if cache_row is None:
                    cache_row = HttpCache(url=cache_key)
                    self.session.add(cache_row)
                cache_row.etag, cache_row.last_modified = etag, lm
        return FetchResult(url, resp.status_code, resp.content, resp.headers)

    def post_json(self, url: str, payload: dict, *, headers: dict | None = None, timeout: float = 20) -> httpx.Response:
        return self._client.post(url, json=payload, headers=headers or {}, timeout=timeout)

    @staticmethod
    def _backoff(attempt: int, retry_after: str | None) -> None:
        delay = min(2**attempt, 60)
        if retry_after and retry_after.isdigit():
            delay = min(int(retry_after), 300)
        time.sleep(delay)
