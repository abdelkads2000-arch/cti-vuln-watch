"""Scoring, inventory matching, LLM enrichment and priority for vulnerabilities to (re)process."""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from cti.collectors.common import claim_kind, keywords
from cti.db.models import Asset, Client, Evidence, Match, RawItem, Source, Vulnerability, Watchlist
from cti.extraction.claims import extract_claims
from cti.extraction.llm import LlmExtractor
from cti.matching.inventory import ProductResolver, load_catalog, load_inventory, match_vulnerability
from cti.priority import PriorityDecision, PriorityInput, decide, load_rules
from cti.scoring.evidence import EvidenceView, Level, score
from cti.settings import Settings

log = logging.getLogger(__name__)

LLM_MAX_CALLS_PER_CYCLE = 20


def now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------- inventory sync


def sync_inventory(session: Session, settings: Settings) -> int:
    inv = load_inventory(settings)
    seen_clients, seen_assets = set(), set()
    for c in inv.clients:
        seen_clients.add(c.id)
        session.merge(Client(id=c.id, name=c.name, data=c.model_dump(exclude={"assets"})))
        for a in c.assets:
            aid = f"{c.id}/{a.id}"
            seen_assets.add(aid)
            session.merge(
                Asset(id=aid, client_id=c.id, vendor=a.vendor, product=a.product, version=a.version, cpe=a.cpe,
                      internet_exposed=a.internet_exposed, origin="declared")
            )
    session.flush()
    session.execute(delete(Asset).where(Asset.origin == "declared", Asset.id.not_in(seen_assets or {""})))
    session.execute(delete(Client).where(Client.id.not_in(seen_clients or {""})))
    return len(seen_assets)


@lru_cache(maxsize=1)
def _resolver_cached(path: str, mtime: float) -> ProductResolver:
    from cti.settings import Settings as _S

    return ProductResolver(load_catalog(_S(CTI_CONFIG_DIR=path)))


def resolver(settings: Settings) -> ProductResolver:
    p = settings.config_dir / "product_aliases.yaml"
    return _resolver_cached(str(settings.config_dir), p.stat().st_mtime)


# ---------------------------------------------------------------- scoring


def evidence_views(v: Vulnerability) -> list[EvidenceView]:
    return [
        EvidenceView(
            kind=e.kind, assertion=e.assertion, url=e.url, source_name=e.source.name, source_tier=e.source.tier,
            source_role=e.source.role, source_status=e.source.status, reliability=e.source.reliability,
            suspicious=e.suspicious, quote=e.quote,
        )
        for e in v.evidence
    ]


def rescore(v: Vulnerability):
    r = score(evidence_views(v))
    v.evidence_level = r.level.name
    v.confidence = r.confidence
    v.has_conflict = r.has_conflict
    v.conflict_notes = r.conflicts
    v.scoring_explain = {**r.explain, "weak_only": r.weak_only}
    return r


def bypass_signal(v: Vulnerability) -> bool:
    for e in v.evidence:
        if e.source.status != "active" or e.assertion != "affirms":
            continue
        if e.kind == "bypass_signal":
            return True
        if e.kind == "bulletin_revision" and (e.details or {}).get("significant"):
            return True
    return False


def in_watchlist(session: Session, cve_id: str) -> bool:
    w = session.get(Watchlist, cve_id)
    return bool(w and (w.expires_at is None or w.expires_at > now()))


def is_recent(v: Vulnerability, days: int) -> bool:
    limit = now() - timedelta(days=days)
    if v.published_at and v.published_at >= limit:
        return True
    if v.kev_added:
        try:
            return date.fromisoformat(v.kev_added) >= limit.date()
        except ValueError:
            return False
    return False


def is_notifiable(v: Vulnerability, days: int) -> bool:
    """Backfill guard: history loaded on a source's first run only alerts if recent."""
    fresh = any(not (e.details or {}).get("baseline") for e in v.evidence if e.source.status == "active")
    return fresh or is_recent(v, days)


# ---------------------------------------------------------------- LLM enrichment


def llm_enrich(session: Session, v: Vulnerability, extractor: LlmExtractor, settings: Settings) -> list[str]:
    rows = session.execute(
        select(RawItem, Source)
        .join(Source, RawItem.source_id == Source.id)
        .where(RawItem.cve_ids.contains([v.cve_id]), Source.status == "active", Source.tier <= 3)
        .order_by(Source.tier, RawItem.fetched_at.desc())
        .limit(5)
    ).all()
    docs = [{"source": s.name, "url": r.url, "text": r.content or ""} for r, s in rows if r.content]
    if v.description_en:
        docs.insert(0, {"source": "description", "url": f"https://nvd.nist.gov/vuln/detail/{v.cve_id}", "text": v.description_en})
    ex, notes = extractor.extract(v.cve_id, docs)
    if ex is None:
        return notes
    urls = [d["url"] for d in docs]
    v.summary_fr = ex.summary_fr
    fs = dict(v.field_sources or {})
    fs["summary_fr"] = {"url": urls[0] if urls else None, "generated_by": f"LLM {settings.anthropic_model}", "from": urls}
    v.field_sources = fs
    doc_by_quote = lambda q: next((d for d in docs if " ".join(q.split()).casefold() in " ".join(d["text"].split()).casefold()), docs[0])  # noqa: E731
    v.mitigations = list(v.mitigations or []) + [
        {"text": m.text, "quote": m.quote, "source_url": doc_by_quote(m.quote)["url"], "extracted_by": "llm"} for m in ex.mitigations
    ]
    v.iocs = list(v.iocs or []) + [
        {"type": i.type, "value": i.value, "quote": i.quote, "source_url": doc_by_quote(i.quote)["url"]} for i in ex.iocs
    ]
    kw = keywords(settings)
    src_by_name = {s.name: s for _, s in rows}
    for c in ex.claims:
        doc = doc_by_quote(c.quote)
        src = src_by_name.get(doc["source"])
        if src is None:
            continue
        # Deterministic confirmation: the verified quote must itself match our rules.
        rule_claims = extract_claims(c.quote, kw, doc_cves=[c.cve_id], source_role=src.role)
        confirmed = any(rc.category == c.category and rc.assertion == c.assertion for rc in rule_claims)
        kind = claim_kind(c.category, src.role) if confirmed else "llm_claim"
        session.execute(
            pg_insert(Evidence).values(
                cve_id=c.cve_id if c.cve_id == v.cve_id else v.cve_id, source_id=src.id, kind=kind, assertion=c.assertion,
                url=doc["url"], quote=c.quote, extracted_by="llm", suspicious=False, suspicion_reasons=[],
                details={"category": c.category, "rule_confirmed": confirmed, "claimed_cve": c.cve_id},
            ).on_conflict_do_nothing(constraint="uq_evidence_dedup")
        )
    session.flush()
    session.refresh(v)
    return notes


# ---------------------------------------------------------------- main processing


def process_pending(session: Session, settings: Settings, *, notify: bool = True, limit: int = 5000) -> dict:
    from cti.pipeline.notify import dispatch

    sync_inventory(session, settings)
    inv = load_inventory(settings)
    res = resolver(settings)
    rules_path = str(settings.config_dir / "priority.yaml")
    backfill_days = int(load_rules(rules_path).get("backfill_notify_days", 7))
    extractor = LlmExtractor(settings)
    llm_calls = 0
    stats = {"rescored": 0, "matched": 0, "notified": 0, "skipped_backfill": 0, "llm_calls": 0}

    vulns = session.scalars(select(Vulnerability).where(Vulnerability.needs_rescore.is_(True)).limit(limit)).all()
    for v in vulns:
        # Evidence rows are inserted with Core INSERT ... ON CONFLICT: make sure the ORM
        # collection is reloaded instead of reusing a stale identity-map copy.
        session.expire(v, ["evidence"])
        r = rescore(v)
        matches = match_vulnerability(v, inv, res)
        session.execute(delete(Match).where(Match.cve_id == v.cve_id))
        for m in matches:
            session.add(Match(cve_id=v.cve_id, asset_id=m.asset_id, client_id=m.client_id, method=m.method,
                              version_status=m.version_status, detail=m.detail))
        concerned = [m for m in matches if m.version_status != "not_affected"]
        stats["rescored"] += 1
        stats["matched"] += bool(concerned)
        cvss = max([s for s in (v.cvss31_score, v.cvss40_score) if s is not None], default=None)
        pin = PriorityInput(
            cve_id=v.cve_id, level=r.level, weak_only=r.weak_only, cvss=cvss, epss=v.epss,
            client_match=bool(concerned), client_exposed=any(m.internet_exposed for m in concerned),
            in_watchlist=in_watchlist(session, v.cve_id), bypass_signal=bypass_signal(v),
        )
        decision: PriorityDecision = decide(pin, rules_path)
        v.needs_rescore = False
        if not decision.priority or not notify:
            continue
        if not is_notifiable(v, backfill_days) and not pin.in_watchlist:
            stats["skipped_backfill"] += 1
            continue
        if not v.summary_fr and extractor.enabled and llm_calls < LLM_MAX_CALLS_PER_CYCLE:
            llm_calls += 1
            notes = llm_enrich(session, v, extractor, settings)
            if notes:
                log.info("enrichissement LLM", extra={"cve": v.cve_id, "notes": notes})
            new_r = rescore(v)
            if new_r.level != r.level:  # rule-confirmed LLM claim changed the level
                r = new_r
                pin.level, pin.weak_only = r.level, r.weak_only
                decision = decide(pin, rules_path)
        stats["notified"] += dispatch(session, settings, v, r, decision, matches, pin)
    stats["llm_calls"] = llm_calls
    session.flush()
    log.info("traitement terminé", extra=stats)
    return stats


def level_quote(v: Vulnerability) -> str | None:
    """Best quote supporting the retained level (shown in 'why it matters')."""
    target = Level[v.evidence_level]
    from cti.scoring.evidence import KIND_LEVEL

    best = [e for e in v.evidence if e.assertion == "affirms" and KIND_LEVEL.get(e.kind) == target and e.source.status == "active"]
    best.sort(key=lambda e: (e.source.tier, e.kind != "kev_listed"))
    return f"{best[0].source.name}: «{(best[0].quote or '')[:200]}»" if best and best[0].quote else None
