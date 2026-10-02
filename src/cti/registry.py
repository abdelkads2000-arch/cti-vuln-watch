"""Source registry: config/sources.yaml validated with Pydantic and mirrored into the DB."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from cti.db.models import Source
from cti.settings import Settings

Role = Literal["vendor", "cert", "reference", "research", "press", "social"]
Status = Literal["active", "observation", "disabled"]

DEFAULT_RELIABILITY = {1: 0.6, 2: 0.4, 3: 0.25, 4: 0.1}

# Secrets required per collector type (in addition to per-source `requires`).
TYPE_REQUIRES: dict[str, list[str]] = {}
# Optional secrets that raise quotas but are not required.
TYPE_OPTIONAL: dict[str, list[str]] = {"nvd": ["NVD_API_KEY"], "ghsa": ["GITHUB_TOKEN"], "cvelist": ["GITHUB_TOKEN"]}


def parse_interval(value: str | int) -> int:
    if isinstance(value, int):
        return value
    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", value)
    if not m:
        raise ValueError(f"intervalle invalide: {value!r} (ex: 30m, 2h, 3600)")
    n, unit = int(m.group(1)), m.group(2) or "s"
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


class SourceDef(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{1,99}$")
    type: str
    role: Role
    tier: int = Field(ge=1, le=4)
    url: str
    interval: int = 3600
    status: Status = "active"
    reliability: float | None = Field(default=None, ge=0, le=1)
    requires: list[str] = Field(default_factory=list)
    config: dict = Field(default_factory=dict)

    @field_validator("interval", mode="before")
    @classmethod
    def _interval(cls, v):
        return parse_interval(v)

    @property
    def effective_reliability(self) -> float:
        return self.reliability if self.reliability is not None else DEFAULT_RELIABILITY[self.tier]

    def missing_secrets(self, settings: Settings) -> list[str]:
        needed = self.requires + TYPE_REQUIRES.get(self.type, [])
        return [k for k in needed if not settings.secret(k.lower())]


class Registry(BaseModel):
    sources: list[SourceDef]

    @field_validator("sources")
    @classmethod
    def _unique(cls, v: list[SourceDef]):
        names = [s.name for s in v]
        dup = {n for n in names if names.count(n) > 1}
        if dup:
            raise ValueError(f"noms de sources dupliqués: {sorted(dup)}")
        return v


def registry_path(settings: Settings) -> Path:
    return settings.config_dir / "sources.yaml"


def load_registry(settings: Settings) -> Registry:
    data = yaml.safe_load(registry_path(settings).read_text(encoding="utf-8")) or {}
    return Registry.model_validate(data)


def save_registry(settings: Settings, registry: Registry) -> None:
    """Rewrite sources.yaml (used by `cti source add/disable/enable`). Comments in the
    header are preserved; per-source comments are not."""
    path = registry_path(settings)
    text = path.read_text(encoding="utf-8")
    header = "".join(line for line in text.splitlines(keepends=True) if line.startswith("#"))
    body = []
    for s in registry.sources:
        d = s.model_dump(exclude_none=True)
        if not d.get("requires"):
            d.pop("requires", None)
        if not d.get("config"):
            d.pop("config", None)
        body.append(d)
    dumped = yaml.safe_dump({"sources": body}, allow_unicode=True, sort_keys=False)
    path.write_text(header + "\n" + dumped, encoding="utf-8")


def sync_sources(session: Session, settings: Settings) -> list[Source]:
    """Upsert YAML definitions into `sources`. Runtime state (cursor, health) is kept.
    Sources whose required secrets are missing are forced to 'disabled' with a reason."""
    registry = load_registry(settings)
    existing = {s.name: s for s in session.scalars(select(Source))}
    result = []
    for d in registry.sources:
        row = existing.pop(d.name, None) or Source(name=d.name, state={}, consecutive_failures=0)
        missing = d.missing_secrets(settings)
        row.type, row.role, row.tier, row.url = d.type, d.role, d.tier, d.url
        row.reliability = d.effective_reliability
        row.interval_s = d.interval
        row.config = d.config
        if missing and d.status != "disabled":
            row.status = "disabled"
            row.disabled_reason = f"clé(s) absente(s) dans .env : {', '.join(missing)}"
        else:
            row.status = d.status
            row.disabled_reason = None if d.status != "disabled" else "désactivée dans sources.yaml"
        session.add(row)
        result.append(row)
    for orphan in existing.values():  # removed from YAML: keep history, stop collecting
        orphan.status = "disabled"
        orphan.disabled_reason = "retirée de sources.yaml"
    session.flush()
    return result
