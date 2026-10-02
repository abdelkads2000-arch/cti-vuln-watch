"""Engine / session factory."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from cti.settings import get_settings


@lru_cache
def get_engine(url: str | None = None) -> Engine:
    return create_engine(url or get_settings().db_url, pool_pre_ping=True, future=True)


_factory: sessionmaker[Session] | None = None


def configure(url: str | None = None) -> None:
    """(Re)bind the session factory, e.g. to a test database."""
    global _factory
    _factory = sessionmaker(bind=get_engine(url), expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    if _factory is None:
        configure()
    assert _factory is not None
    session = _factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
