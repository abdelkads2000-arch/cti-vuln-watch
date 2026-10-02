"""Programmatic Alembic entry points (no alembic.ini needed)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from cti.settings import get_settings

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def alembic_config(url: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    # '%' must be escaped for configparser interpolation (passwords may contain it).
    cfg.set_main_option("sqlalchemy.url", (url or get_settings().db_url).replace("%", "%%"))
    return cfg


def upgrade(url: str | None = None) -> None:
    command.upgrade(alembic_config(url), "head")


def autogenerate(message: str, url: str | None = None) -> None:
    """Developer helper: generate a new migration from model changes."""
    command.revision(alembic_config(url), message=message, autogenerate=True)
