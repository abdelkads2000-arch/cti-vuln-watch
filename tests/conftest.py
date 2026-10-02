"""Shared fixtures. No test performs network access: HTTP is served from tests/fixtures."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


@pytest.fixture(autouse=True)
def _no_real_secrets(monkeypatch):
    """Tests must never use real credentials from the developer's .env."""
    for k in list(os.environ):
        if k.endswith(("_API_KEY", "_TOKEN", "_WEBHOOK_URL_FR", "_WEBHOOK_URL_KR", "_SECRET", "_PASSWORD")):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.chdir(ROOT / "tests")  # no .env there


@pytest.fixture
def config_dir(tmp_path) -> Path:
    d = tmp_path / "config"
    shutil.copytree(ROOT / "config", d)
    (d / "inventory.yaml").unlink(missing_ok=True)  # always use the fictitious inventory
    return d


@pytest.fixture
def settings(config_dir):
    from cti.settings import Settings

    return Settings(CTI_CONFIG_DIR=str(config_dir), _env_file=None)


def fixture_bytes(rel: str) -> bytes:
    return (FIX / rel).read_bytes()


def fixture_json(rel: str):
    return json.loads(fixture_bytes(rel))


# ---------------------------------------------------------------- database


def _test_db_url() -> str | None:
    url = os.environ.get("CTI_TEST_DATABASE_URL")
    if url:
        return url
    try:  # local development without Docker: embedded PostgreSQL
        import pgserver  # type: ignore
    except ImportError:
        return None
    data = Path(os.environ.get("LOCALAPPDATA", "/tmp")) / "Temp" / "ctipg"
    srv = pgserver.get_server(str(data), cleanup_mode=None)
    return srv.get_uri().replace("postgresql://", "postgresql+psycopg://").rsplit("/", 1)[0] + "/postgres"


@pytest.fixture
def db_url():
    base = _test_db_url()
    if not base:
        pytest.skip("aucune base PostgreSQL de test (CTI_TEST_DATABASE_URL)")
    from sqlalchemy import create_engine, text

    name = f"cti_test_{uuid.uuid4().hex[:8]}"
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
    url = base.rsplit("/", 1)[0] + f"/{name}"
    from cti.db.migrate import upgrade

    upgrade(url)
    yield url
    from cti.db.session import get_engine

    get_engine.cache_clear()
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    admin.dispose()


@pytest.fixture
def session(db_url):
    from cti.db import session as dbs

    dbs.configure(db_url)
    with dbs.session_scope() as s:
        yield s


# ---------------------------------------------------------------- HTTP mock


class FixtureRouter:
    """httpx transport answering from recorded fixtures; unknown URLs -> 404."""

    def __init__(self):
        self.routes: list[tuple[str, callable]] = []
        self.calls: list[str] = []

    def add(self, url_prefix: str, body: bytes | callable, status: int = 200, headers: dict | None = None):
        def handler(request: httpx.Request):
            content = body(request) if callable(body) else body
            return httpx.Response(status, content=content, headers=headers or {})

        self.routes.append((url_prefix, handler))
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(url)
        if url.endswith("/robots.txt"):
            return httpx.Response(404)
        for prefix, handler in sorted(self.routes, key=lambda r: -len(r[0])):
            if url.startswith(prefix):
                return handler(request)
        return httpx.Response(404, content=b"not in fixtures")

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


@pytest.fixture
def router() -> FixtureRouter:
    return FixtureRouter()
