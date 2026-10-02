"""Run one source and persist its CollectResult.

A failing source never breaks the pipeline: the exception is recorded on the source
(consecutive_failures, last_error), a collector_runs row is written, and after
TECH_ALERT_AFTER consecutive failures a technical alert is emitted.
"""

from __future__ import annotations

import difflib
import json
import logging
import time
import traceback
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from cti.collectors.base import CollectResult, SourceCtx, VulnPatch, get_collector_class
from cti.collectors.common import keywords
from cti.db.models import AdvisorySnapshot, CollectorRun, Evidence, RawItem, Source, Vulnerability, Watchlist
from cti.extraction.claims import extract_claims
from cti.extraction.text import content_hash
from cti.http import HttpClient
from cti.settings import Settings

log = logging.getLogger(__name__)

TECH_ALERT_AFTER = 3
SCALAR_FIELDS = {
    "title", "description_en", "vendor", "product", "patch_available", "cvss31_score", "cvss31_vector",
    "cvss40_score", "cvss40_vector", "epss", "epss_percentile", "epss_date", "kev", "kev_added", "published_at",
}
LIST_FIELDS = {"cpes", "affected", "fixed_versions", "mitigations", "references", "iocs"}
URL_HINTS = {"citrix_bulletins": "support.citrix.com"}


def now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------- context


def build_ctx(session: Session, src: Source) -> SourceCtx:
    ctx = SourceCtx(
        name=src.name, type=src.type, role=src.role, tier=src.tier, url=src.url,
        config=dict(src.config or {}), state=dict(src.state or {}), first_run=src.last_success_at is None,
    )
    hint = URL_HINTS.get(src.type)
    if hint:
        rows = session.execute(
            text(
                "SELECT DISTINCT l FROM raw_items, jsonb_array_elements_text(raw->'_links') AS l "
                "WHERE fetched_at > now() - interval '90 days' AND l LIKE :p LIMIT 2000"
            ),
            {"p": f"%{hint}%"},
        ).scalars()
        refs = session.execute(
            text(
                "SELECT DISTINCT r->>'url' FROM vulnerabilities, jsonb_array_elements(\"references\") AS r "
                "WHERE updated_at > now() - interval '90 days' AND r->>'url' LIKE :p LIMIT 2000"
            ),
            {"p": f"%{hint}%"},
        ).scalars()
        ctx.known_urls = sorted(set(rows) | set(refs))
    if src.type == "nvd":
        # Stubs created from CERT/vendor mentions that still lack NVD data.
        ctx.cve_scope = list(
            session.scalars(
                select(Vulnerability.cve_id)
                .where(Vulnerability.description_en.is_(None))
                .order_by(Vulnerability.first_seen_at.desc())
                .limit(100)
            )
        )
    if src.type == "epss":
        recent = now() - timedelta(days=3)
        ctx.cve_scope = list(
            session.scalars(
                select(Vulnerability.cve_id).where(
                    (Vulnerability.updated_at > recent)
                    | Vulnerability.epss.is_(None)
                    | Vulnerability.cve_id.in_(select(Watchlist.cve_id))
                ).limit(5000)
            )
        )
    return ctx


# ---------------------------------------------------------------- persistence helpers


def _item_key(x) -> str:
    return json.dumps(x, sort_keys=True, default=str)


def ensure_vuln(session: Session, cve_id: str) -> Vulnerability:
    v = session.get(Vulnerability, cve_id)
    if v is None:
        v = Vulnerability(
            cve_id=cve_id, cpes=[], affected=[], fixed_versions=[], mitigations=[], conflict_notes=[],
            scoring_explain={}, iocs=[], references=[], field_sources={}, needs_rescore=True,
            evidence_level="NO_KNOWN_EXPLOIT", confidence=0, kev=False, has_conflict=False,
        )
        session.add(v)
        session.flush()
    return v


def apply_patch(session: Session, p: VulnPatch) -> bool:
    v = session.get(Vulnerability, p.cve_id)
    if v is None:
        if not p.create:
            return False
        v = ensure_vuln(session, p.cve_id)
    changed = False
    sources = dict(v.field_sources or {})
    for f, val in p.fields.items():
        if f not in SCALAR_FIELDS or val is None or val == "":
            continue
        prev = sources.get(f)
        if getattr(v, f) is None or prev is None or p.precedence <= prev.get("precedence", 99):
            if getattr(v, f) != val:
                setattr(v, f, val)
                changed = True
            sources[f] = {"url": p.source_url, "precedence": p.precedence}
    for f, items in p.merge_lists.items():
        if f not in LIST_FIELDS or not items:
            continue
        current = list(getattr(v, f) or [])
        keys = {_item_key(x) for x in current}
        added = [x for x in items if _item_key(x) not in keys]
        if added:
            setattr(v, f, current + added)
            changed = True
    if changed:
        v.field_sources = sources
        v.needs_rescore = True
        v.updated_at = now()
    return changed


def upsert_items(session: Session, source: Source, result: CollectResult) -> tuple[dict[str, int], int]:
    ids, new = {}, 0
    for it in result.items:
        h = content_hash(it.title, it.content, json.dumps(it.raw, sort_keys=True, default=str))
        raw = dict(it.raw)
        raw["_links"] = it.links
        row = session.scalar(select(RawItem).where(RawItem.source_id == source.id, RawItem.external_id == it.external_id))
        if row is None:
            row = RawItem(source_id=source.id, external_id=it.external_id)
            session.add(row)
            new += 1
        if row.content_hash != h:
            row.url, row.title, row.content = it.url, it.title, it.content
            row.published_at, row.cve_ids, row.raw, row.content_hash = it.published_at, it.cve_ids, raw, h
            row.fetched_at = now()
        session.flush()
        ids[it.external_id] = row.id
    return ids, new


def insert_evidence(session: Session, source: Source, result: CollectResult, item_ids: dict, baseline: bool) -> int:
    count = 0
    for e in result.evidence:
        if not e.url:
            continue  # rule: no assertion without a source URL
        ensure_vuln(session, e.cve_id)
        details = dict(e.details)
        if baseline:
            details["baseline"] = True
        stmt = (
            pg_insert(Evidence)
            .values(
                cve_id=e.cve_id, source_id=source.id, raw_item_id=item_ids.get(e.item_external_id or ""),
                kind=e.kind, assertion=e.assertion, url=e.url, quote=e.quote, extracted_by=e.extracted_by,
                suspicious=False, suspicion_reasons=[], details=details,
            )
            .on_conflict_do_nothing(constraint="uq_evidence_dedup")
            .returning(Evidence.id)
        )
        if session.execute(stmt).scalar() is not None:
            count += 1
            session.get(Vulnerability, e.cve_id).needs_rescore = True
    return count


def record_snapshots(session: Session, source: Source, settings: Settings, result: CollectResult, baseline: bool) -> int:
    """Store advisory snapshots; on content change, emit revision (and bypass) evidence."""
    revisions = 0
    kw = keywords(settings)
    for s in result.snapshots:
        h = content_hash(s.normalized_text)
        prev = session.scalar(
            select(AdvisorySnapshot)
            .where(AdvisorySnapshot.source_id == source.id, AdvisorySnapshot.advisory_id == s.advisory_id)
            .order_by(AdvisorySnapshot.fetched_at.desc())
            .limit(1)
        )
        if prev is not None and prev.content_hash == h:
            continue
        diff_summary: dict = {}
        if prev is not None:
            old_lines, new_lines = prev.normalized_text.splitlines(), s.normalized_text.splitlines()
            added = [line[1:] for line in difflib.unified_diff(old_lines, new_lines, lineterm="", n=0) if line.startswith("+") and not line.startswith("+++")]
            removed = [line[1:] for line in difflib.unified_diff(old_lines, new_lines, lineterm="", n=0) if line.startswith("-") and not line.startswith("---")]
            new_cves = sorted(set(s.cve_ids) - set(prev.cve_ids or []))
            aff_added = sorted(set(s.affected) - set(prev.affected or []))
            aff_removed = sorted(set(prev.affected or []) - set(s.affected))
            significant = bool(new_cves or aff_added or aff_removed or s.revision_label != prev.revision_label)
            diff_summary = {
                "from_revision": prev.revision_label, "to_revision": s.revision_label,
                "added_lines": added[:40], "removed_lines": removed[:40], "new_cves": new_cves,
                "affected_added": aff_added, "affected_removed": aff_removed, "significant": significant,
            }
            revisions += 1
            rev_url = f"{s.url}#rev-{h[:8]}"
            added_text = "\n".join(added)
            bypass_claims = [c for c in extract_claims(added_text, kw, doc_cves=s.cve_ids, source_role=source.role) if c.category == "bypass" and c.assertion == "affirms"]
            for cve in s.cve_ids:
                ensure_vuln(session, cve)
                session.execute(
                    pg_insert(Evidence).values(
                        cve_id=cve, source_id=source.id, kind="bulletin_revision", assertion="affirms", url=rev_url,
                        quote=(s.revision_label or "contenu du bulletin modifié")[:400], extracted_by="rule",
                        suspicious=False, suspicion_reasons=[], details={**diff_summary, "baseline": baseline},
                    ).on_conflict_do_nothing(constraint="uq_evidence_dedup")
                )
                session.get(Vulnerability, cve).needs_rescore = True
            for c in bypass_claims:
                ensure_vuln(session, c.cve_ids[0])
                session.execute(
                    pg_insert(Evidence).values(
                        cve_id=c.cve_ids[0], source_id=source.id, kind="bypass_signal", assertion="affirms", url=rev_url,
                        quote=c.quote, extracted_by="rule", suspicious=False, suspicion_reasons=[],
                        details={"via": "bulletin_revision", "attribution": c.attribution},
                    ).on_conflict_do_nothing(constraint="uq_evidence_dedup")
                )
        session.add(
            AdvisorySnapshot(
                source_id=source.id, advisory_id=s.advisory_id, url=s.url, content_hash=h,
                normalized_text=s.normalized_text, revision_label=s.revision_label, cve_ids=s.cve_ids,
                affected=s.affected, diff_summary=diff_summary,
            )
        )
    return revisions


def persist(session: Session, source: Source, settings: Settings, result: CollectResult, *, baseline: bool) -> dict:
    item_ids, new_items = upsert_items(session, source, result)
    patched = sum(1 for p in result.patches if apply_patch(session, p))
    session.flush()
    ev = insert_evidence(session, source, result, item_ids, baseline)
    revs = record_snapshots(session, source, settings, result, baseline)
    return {"items_seen": len(result.items), "items_new": new_items, "patched": patched, "evidence_new": ev, "revisions": revs}


# ---------------------------------------------------------------- run


def run_source(session: Session, source: Source, settings: Settings, *, http: HttpClient | None = None) -> dict:
    """Collect + persist one source. Returns run stats; never raises for collector errors."""
    started, t0 = now(), time.monotonic()
    own_http = http is None
    http = http or HttpClient(session)
    ctx = build_ctx(session, source)
    stats: dict = {"source": source.name, "status": "ok"}
    try:
        cls = get_collector_class(source.type)
        result = cls(ctx, http, settings).collect()
        if result.not_modified:
            stats["status"] = "not_modified"
        else:
            with session.begin_nested():
                stats.update(persist(session, source, settings, result, baseline=ctx.first_run))
        if result.new_state is not None:
            source.state = result.new_state
        source.last_success_at = now()
        source.consecutive_failures = 0
        source.last_error = None
        stats["notes"] = result.notes
    except Exception as exc:  # isolation: one broken source must not stop the others
        source.consecutive_failures = (source.consecutive_failures or 0) + 1
        source.last_error = f"{type(exc).__name__}: {exc}"[:2000]
        stats.update(status="error", error=source.last_error)
        log.error("collecte en échec", extra={"source": source.name, "error": source.last_error, "trace": traceback.format_exc(limit=5)})
        if source.consecutive_failures == TECH_ALERT_AFTER:
            from cti.pipeline.notify import technical_alert

            technical_alert(session, settings, source, source.last_error)
    finally:
        if own_http:
            http.close()
    source.last_run_at = now()
    session.add(
        CollectorRun(
            source_id=source.id, started_at=started, duration_ms=int((time.monotonic() - t0) * 1000),
            status=stats["status"], items_seen=stats.get("items_seen", 0), items_new=stats.get("items_new", 0),
            evidence_new=stats.get("evidence_new", 0), error=stats.get("error"),
        )
    )
    session.flush()
    log.info("collecte terminée", extra={k: v for k, v in stats.items() if k != "notes"})
    return stats


def source_counts(session: Session) -> dict:
    return dict(session.execute(select(Source.status, func.count()).group_by(Source.status)).all())
