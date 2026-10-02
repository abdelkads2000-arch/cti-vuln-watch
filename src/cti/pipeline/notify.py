"""Alert dispatch: follow-the-sun routing, dedup by state fingerprint, Teams or dry-run."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from cti.db.models import Alert, Source, Vulnerability
from cti.notifiers.message import AlertMessage, build_message
from cti.notifiers.routing import Routing, Team
from cti.notifiers.teams import send_teams
from cti.priority import PriorityDecision, PriorityInput, change_reasons, fingerprint, load_rules
from cti.scoring.evidence import ScoreResult
from cti.settings import Settings

log = logging.getLogger(__name__)


def now() -> datetime:
    return datetime.now(UTC)


def routing(settings: Settings) -> Routing:
    return Routing.load(settings.config_dir / "routing.yaml")


def webhook_for(settings: Settings, team: Team, rt: Routing) -> str:
    url = settings.secret(team.webhook_env.lower()) if team.webhook_env else ""
    if not url and team.id != rt.default_team:
        default = rt.team(rt.default_team)
        url = settings.secret(default.webhook_env.lower()) if default.webhook_env else ""
    return url


def deliver(session: Session, settings: Settings, msg: AlertMessage, team: Team, rt: Routing, *, kind: str,
            state: dict, reasons: list[str]) -> Alert:
    url = webhook_for(settings, team, rt)
    if url:
        ok, err = send_teams(url, msg)
        status, channel = ("sent" if ok else "failed"), "teams"
    else:
        ok, err, status, channel = True, None, "dry_run", "log"
    log.warning(
        "ALERTE " + ("(dry-run) " if status == "dry_run" else "") + f"{msg.priority} {msg.cve_id or ''} -> {team.name}",
        extra={"alert_status": status, "priority": msg.priority, "cve": msg.cve_id, "team": team.id, "rendered": msg.to_text(), "error": err},
    )
    alert = Alert(
        cve_id=msg.cve_id or None, kind=kind, priority=msg.priority, state_fingerprint=fingerprint(state),
        change_reasons=reasons, channel=channel, audience=team.id, lang=msg.lang, status=status,
        payload={"message": msg.to_dict(), "state": state}, error=err,
    )
    session.add(alert)
    return alert


def _last_alert(session: Session, cve_id: str, audience: str) -> Alert | None:
    return session.scalar(
        select(Alert)
        .where(Alert.cve_id == cve_id, Alert.audience == audience, Alert.kind == "vuln", Alert.status.in_(("sent", "dry_run", "queued_digest", "digested")))
        .order_by(Alert.created_at.desc())
        .limit(1)
    )


def notification_state(v: Vulnerability, r: ScoreResult, decision: PriorityDecision, matches, pin: PriorityInput) -> dict:
    revisions = sorted({e.url for e in v.evidence if e.kind == "bulletin_revision"})
    return {
        "level": r.level.name,
        "clients": sorted({m.client_id for m in matches if m.version_status != "not_affected"}),
        "bulletin_revisions": len(revisions),
        "patch_available": bool(v.patch_available or v.fixed_versions),
        "bypass": pin.bypass_signal,
        "priority": decision.priority,
    }


def message_context(v: Vulnerability, r: ScoreResult, decision: PriorityDecision, matches, reasons: list[str], sla: str | None) -> dict:
    from cti.pipeline.process import level_quote

    sources = []
    for s in r.explain.get("supporting", []):
        sources.append({"label": f"{s['source']} ({s['kind']})", "url": s["url"]})
    for e in sorted(v.evidence, key=lambda e: e.source.tier):
        if e.kind in ("vendor_advisory", "cert_advisory", "bulletin_revision", "bypass_signal"):
            sources.append({"label": f"{e.source.name} ({e.kind})", "url": e.url})
    for fname in ("description_en", "cvss31_score", "epss"):
        fs = (v.field_sources or {}).get(fname)
        if fs and fs.get("url"):
            sources.append({"label": f"{fname}", "url": fs["url"]})
    from cti.scoring.evidence import KIND_LEVEL, Level

    # Every source asserting exploitation or a PoC, strongest first. Sources under
    # observation are listed too, flagged as not counted in the evidence level.
    exploit_sources, seen_urls = [], set()
    for e in sorted(v.evidence, key=lambda e: (-KIND_LEVEL.get(e.kind, Level.NO_KNOWN_EXPLOIT), e.source.tier)):
        if e.assertion != "affirms" or KIND_LEVEL.get(e.kind, Level.NO_KNOWN_EXPLOIT) < Level.POC_CLAIMED:
            continue
        # Same page may carry distinct claims (exploited + public PoC): dedup on (url, kind).
        if e.source.status == "disabled" or (e.url, e.kind) in seen_urls:
            continue
        seen_urls.add((e.url, e.kind))
        exploit_sources.append({"label": f"{e.source.name} ({e.kind})", "url": e.url, "quote": e.quote,
                                "counted": e.source.status == "active"})
    return {
        "cve_id": v.cve_id,
        "priority": decision.priority,
        "exploit_sources": exploit_sources[:10],
        "sla": sla,
        "level": r.level.name,
        "level_quote": level_quote(v),
        "confidence": r.confidence,
        "conflicts": r.conflicts,
        "decision_reasons": [x for x in decision.reasons if x],
        "changes": reasons,
        "matches": [m.__dict__ for m in matches],
        "sources": sources,
        "vuln": {
            "vendor": v.vendor, "product": v.product, "description_en": v.description_en, "summary_fr": v.summary_fr,
            "kev": v.kev, "kev_added": v.kev_added, "cvss31_score": v.cvss31_score, "cvss40_score": v.cvss40_score,
            "epss": v.epss, "epss_percentile": v.epss_percentile, "fixed_versions": v.fixed_versions, "mitigations": v.mitigations,
        },
    }


def dispatch(session: Session, settings: Settings, v: Vulnerability, r: ScoreResult, decision: PriorityDecision,
             matches, pin: PriorityInput) -> int:
    rt = routing(settings)
    sla = load_rules(str(settings.config_dir / "priority.yaml")).get("sla", {}).get(decision.priority)
    state = notification_state(v, r, decision, matches, pin)
    fp = fingerprint(state)
    sent = 0
    if decision.priority == "P3":
        audiences = [(rt.team(rt.default_team), "digest")]
    else:
        audiences = [(t, t.id) for t in rt.recipients(decision.priority, now())]
    for team, audience in audiences:
        last = _last_alert(session, v.cve_id, audience)
        if last is not None and last.state_fingerprint == fp:
            continue  # strict dedup: nothing significant changed for this audience
        reasons = change_reasons(last.payload.get("state") if last else None, state)
        if not reasons:
            continue
        ctx = message_context(v, r, decision, matches, reasons, sla)
        msg = build_message(ctx, team.lang)
        if audience == "digest":
            session.add(Alert(cve_id=v.cve_id, kind="vuln", priority="P3", state_fingerprint=fp, change_reasons=reasons,
                              channel="digest", audience="digest", lang=team.lang, status="queued_digest",
                              payload={"message": msg.to_dict(), "state": state, "ctx": ctx}))
        else:
            deliver(session, settings, msg, team, rt, kind="vuln", state=state, reasons=reasons)
        sent += 1
    return sent


def technical_alert(session: Session, settings: Settings, source: Source, error: str) -> None:
    rt = routing(settings)
    team = rt.team(rt.default_team)
    msg = AlertMessage(
        cve_id="", priority="TECH", lang=team.lang,
        title=f"Source en échec : {source.name} ({source.consecutive_failures} échecs consécutifs)",
        summary=error[:500], why=["La collecte de cette source est interrompue ; les autres sources continuent."],
        clients=[], actions=[f"Vérifier la source ({source.url}) et la configuration ; `./cti source test {source.name}`"],
        evidence="n/a", conflicts=[], sources=[{"label": source.name, "url": source.url}], changes=["alerte technique"],
    )
    deliver(session, settings, msg, team, rt, kind="technical", state={"source": source.name, "failures": source.consecutive_failures}, reasons=["alerte technique"])


def send_digest(session: Session, settings: Settings, team_id: str | None = None) -> int:
    """Daily digest of queued P3 alerts (sent to the default team, in its language)."""
    rt = routing(settings)
    team = rt.team(team_id or rt.default_team)
    queued = session.scalars(select(Alert).where(Alert.status == "queued_digest").order_by(Alert.created_at)).all()
    if not queued:
        return 0
    lines, sources = [], []
    for a in queued:
        m = a.payload["message"]
        lines.append(f"{m['title']} — {m['evidence']}")
        sources += m["sources"][:1]
    msg = AlertMessage(
        cve_id="", priority="P3", lang=team.lang,
        title=f"Digest quotidien — {len(queued)} vulnérabilité(s) sans client concerné" if team.lang == "fr" else f"Daily digest — {len(queued)} vulnerabilities, no client affected",
        summary="", why=lines[:40], clients=[], actions=[], evidence="", conflicts=[], sources=sources[:12], changes=["digest"],
    )
    deliver(session, settings, msg, team, rt, kind="digest", state={"count": len(queued)}, reasons=["digest"])
    for a in queued:
        a.status = "digested"
    return len(queued)
