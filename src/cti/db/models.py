"""ORM models. Schema changes go through Alembic migrations only."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Computed,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _now_col() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Source(Base):
    """Mirror of config/sources.yaml plus runtime state (HTTP cache, health)."""

    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # vendor|cert|reference|research|press|social
    url: Mapped[str] = mapped_column(Text, nullable=False)
    tier: Mapped[int] = mapped_column(Integer, nullable=False)
    reliability: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # active|observation|disabled
    interval_s: Mapped[int] = mapped_column(Integer, nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # Collector-owned cursor (last NVD lastMod date, last cvelist release tag...).
    state: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    disabled_reason: Mapped[str | None] = mapped_column(Text)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now_col()


class HttpCache(Base):
    """Conditional-request validators per URL (ETag / Last-Modified)."""

    __tablename__ = "http_cache"

    url: Mapped[str] = mapped_column(Text, primary_key=True)
    etag: Mapped[str | None] = mapped_column(Text)
    last_modified: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = _now_col()


class CollectorRun(Base):
    __tablename__ = "collector_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # ok|not_modified|error|skipped
    items_seen: Mapped[int] = mapped_column(Integer, default=0)
    items_new: Mapped[int] = mapped_column(Integer, default=0)
    evidence_new: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)


class RawItem(Base):
    """Every collected document, verbatim (JSONB) for traceability and reprocessing."""

    __tablename__ = "raw_items"
    __table_args__ = (
        UniqueConstraint("source_id", "external_id", name="uq_raw_items_source_ext"),
        Index("ix_raw_items_tsv", "tsv", postgresql_using="gin"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fetched_at: Mapped[datetime] = _now_col()
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    cve_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # 'simple' config: content is a mix of FR and EN.
    tsv = mapped_column(
        TSVECTOR,
        Computed(
            "to_tsvector('simple', coalesce(title,'') || ' ' || coalesce(left(content, 200000),''))",
            persisted=True,
        ),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str | None] = mapped_column(Text)
    description_en: Mapped[str | None] = mapped_column(Text)
    summary_fr: Mapped[str | None] = mapped_column(Text)
    vendor: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    cpes: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    # [{"product":..., "text":..., "fixed":..., "source_url":...}]
    affected: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    fixed_versions: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    patch_available: Mapped[bool | None] = mapped_column(Boolean)
    mitigations: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    cvss31_score: Mapped[float | None] = mapped_column(Float)
    cvss31_vector: Mapped[str | None] = mapped_column(Text)
    cvss40_score: Mapped[float | None] = mapped_column(Float)
    cvss40_vector: Mapped[str | None] = mapped_column(Text)
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[str | None] = mapped_column(String(10))
    kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    kev_added: Mapped[str | None] = mapped_column(String(10))
    evidence_level: Mapped[str] = mapped_column(String(32), default="NO_KNOWN_EXPLOIT", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    has_conflict: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    conflict_notes: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    scoring_explain: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    iocs: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    # Field -> URL of the source that provided it (traceability of each attribute).
    field_sources: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[datetime] = _now_col()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    needs_rescore: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    evidence: Mapped[list[Evidence]] = relationship(back_populates="vulnerability", lazy="selectin")


class Evidence(Base):
    """One sourced assertion about one CVE. The core of traceability: url is mandatory."""

    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("cve_id", "source_id", "kind", "url", "assertion", name="uq_evidence_dedup"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    raw_item_id: Mapped[int | None] = mapped_column(ForeignKey("raw_items.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    assertion: Mapped[str] = mapped_column(String(10), default="affirms", nullable=False)  # affirms|denies
    url: Mapped[str] = mapped_column(Text, nullable=False)
    quote: Mapped[str | None] = mapped_column(Text)
    extracted_by: Mapped[str] = mapped_column(String(20), default="rule", nullable=False)  # rule|structured|llm
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    suspicion_reasons: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    observed_at: Mapped[datetime] = _now_col()

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="evidence")
    source: Mapped[Source] = relationship(lazy="joined")


class VulnRelation(Base):
    __tablename__ = "vuln_relations"
    __table_args__ = (UniqueConstraint("cve_id", "related_cve_id", "relation"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    related_cve_id: Mapped[str] = mapped_column(String(32), index=True)
    relation: Mapped[str] = mapped_column(String(30))  # references|variant_of|incomplete_fix_of
    url: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _now_col()


class AdvisorySnapshot(Base):
    """Successive versions of vendor/CERT advisories: basis of revision detection."""

    __tablename__ = "advisory_snapshots"
    __table_args__ = (Index("ix_adv_snap_adv", "source_id", "advisory_id", "fetched_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"))
    advisory_id: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_text: Mapped[str] = mapped_column(Text, nullable=False)
    revision_label: Mapped[str | None] = mapped_column(Text)
    cve_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    affected: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    diff_summary: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    fetched_at: Mapped[datetime] = _now_col()


class Watchlist(Base):
    __tablename__ = "watchlist"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    reason: Mapped[str | None] = mapped_column(Text)
    added_by: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now_col()


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)  # "<client>/<asset>"
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    vendor: Mapped[str] = mapped_column(Text, nullable=False)
    product: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str | None] = mapped_column(Text)
    cpe: Mapped[str | None] = mapped_column(Text)
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    origin: Mapped[str] = mapped_column(String(30), default="declared", nullable=False)


class Match(Base):
    __tablename__ = "matches"
    __table_args__ = (UniqueConstraint("cve_id", "asset_id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(String(64), index=True)
    method: Mapped[str] = mapped_column(String(20))  # cpe|alias
    version_status: Mapped[str] = mapped_column(String(20))  # affected|not_affected|unknown
    detail: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = _now_col()


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_cve_aud", "cve_id", "audience", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_id: Mapped[str | None] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(20), default="vuln", nullable=False)  # vuln|technical|digest
    priority: Mapped[str] = mapped_column(String(4), nullable=False)
    state_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    change_reasons: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    audience: Mapped[str] = mapped_column(String(20), nullable=False)
    lang: Mapped[str] = mapped_column(String(2), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # dry_run|sent|failed|queued_digest
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now_col()
