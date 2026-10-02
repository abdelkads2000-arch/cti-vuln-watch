"""Collector interface.

A collector is a pure-ish function of (source definition, previous state, HTTP client)
returning a CollectResult. It never writes to the DB itself: the pipeline persists
the result, which keeps collectors testable against recorded fixtures and lets
`cti source test` run a dry collection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from cti.http import HttpClient
    from cti.settings import Settings


@dataclass
class SourceCtx:
    """What a collector knows about its source (decoupled from the ORM row)."""

    name: str
    type: str
    role: str
    tier: int
    url: str
    config: dict
    state: dict
    first_run: bool
    known_urls: list[str] = field(default_factory=list)  # e.g. bulletin URLs cited elsewhere
    cve_scope: list[str] = field(default_factory=list)  # e.g. CVEs to enrich (EPSS)


@dataclass
class ItemOut:
    external_id: str
    url: str
    title: str | None
    content: str | None
    published_at: datetime | None
    raw: dict
    cve_ids: list[str]
    links: list[str] = field(default_factory=list)  # outbound links (bulletin discovery, phase-2 source discovery)


@dataclass
class EvidenceOut:
    cve_id: str
    kind: str
    url: str
    assertion: str = "affirms"
    quote: str | None = None
    extracted_by: str = "rule"  # rule | structured | llm
    details: dict = field(default_factory=dict)
    item_external_id: str | None = None


@dataclass
class VulnPatch:
    """Partial update of a vulnerability record. Only non-None scalar fields are applied;
    list fields are merged (union), never replaced. `source_url` is recorded as the
    provenance of every field set by this patch."""

    cve_id: str
    source_url: str
    fields: dict = field(default_factory=dict)
    merge_lists: dict = field(default_factory=dict)  # field -> list of items to union
    # Lower value wins when two sources set the same scalar (1 = vendor/CNA, 2 = NVD...).
    precedence: int = 5
    # False: only update an existing vulnerability (e.g. EPSS scores), never create one.
    create: bool = True


@dataclass
class SnapshotOut:
    advisory_id: str
    url: str
    normalized_text: str
    revision_label: str | None
    cve_ids: list[str]
    affected: list = field(default_factory=list)


@dataclass
class CollectResult:
    items: list[ItemOut] = field(default_factory=list)
    evidence: list[EvidenceOut] = field(default_factory=list)
    patches: list[VulnPatch] = field(default_factory=list)
    snapshots: list[SnapshotOut] = field(default_factory=list)
    new_state: dict | None = None
    not_modified: bool = False
    notes: list[str] = field(default_factory=list)


class Collector:
    type: ClassVar[str]

    def __init__(self, ctx: SourceCtx, http: HttpClient, settings: Settings):
        self.ctx = ctx
        self.http = http
        self.settings = settings

    def collect(self) -> CollectResult:  # pragma: no cover - interface
        raise NotImplementedError


REGISTRY: dict[str, type[Collector]] = {}


def register(cls: type[Collector]) -> type[Collector]:
    REGISTRY[cls.type] = cls
    return cls


def get_collector_class(type_: str) -> type[Collector]:
    from cti import collectors  # noqa: F401  (populates REGISTRY)

    try:
        return REGISTRY[type_]
    except KeyError:
        raise ValueError(f"type de collecteur inconnu: {type_!r} (connus: {sorted(REGISTRY)})") from None
