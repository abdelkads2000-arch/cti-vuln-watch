"""Command line interface (run inside the container through ./cti)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select

from cti.logsetup import setup_logging
from cti.settings import get_settings

app = typer.Typer(help="CTI Vuln Watch — agent de veille vulnérabilités", no_args_is_help=True)
source_app = typer.Typer(help="Gestion du registre de sources", no_args_is_help=True)
watch_app = typer.Typer(help="Surveillance renforcée (watchlist)", no_args_is_help=True)
db_app = typer.Typer(help="Base de données", no_args_is_help=True)
app.add_typer(source_app, name="source")
app.add_typer(watch_app, name="watchlist")
app.add_typer(db_app, name="db")
console = Console()


@app.callback()
def _init(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    s = get_settings()
    setup_logging("DEBUG" if verbose else s.log_level, s.all_secret_values())


def _now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------- db / worker


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Appliquer les migrations Alembic (exécuté automatiquement au démarrage)."""
    from cti.db.migrate import upgrade

    upgrade()
    console.print("[green]Schéma à jour.[/]")


@app.command()
def worker() -> None:
    """Planificateur (service long)."""
    from cti.scheduler import run_worker

    run_worker(get_settings())


# ---------------------------------------------------------------- run / status


@app.command()
def run(
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Une seule source"),
    notify: bool = typer.Option(True, "--notify/--no-notify", help="Envoyer les notifications"),
) -> None:
    """Exécuter immédiatement la collecte puis le traitement."""
    from cti.db.models import Source
    from cti.db.session import session_scope
    from cti.pipeline.collect import run_source
    from cti.pipeline.process import process_pending
    from cti.registry import sync_sources

    settings = get_settings()
    with session_scope() as s:
        sync_sources(s, settings)
    with session_scope() as s:
        q = select(Source).where(Source.status.in_(("active", "observation")))
        if source:
            q = select(Source).where(Source.name == source)
        names = [x.name for x in s.scalars(q.order_by(Source.tier, Source.name))]
    if source and not names:
        raise typer.BadParameter(f"source inconnue: {source}")
    table = Table("source", "statut", "items", "nouveaux", "preuves", "révisions", "détail")
    for name in names:
        with session_scope() as s:
            src = s.scalar(select(Source).where(Source.name == name))
            st = run_source(s, src, settings)
        table.add_row(name, st["status"], str(st.get("items_seen", "")), str(st.get("items_new", "")),
                      str(st.get("evidence_new", "")), str(st.get("revisions", "")), (st.get("error") or "; ".join(st.get("notes", [])))[:80])
    console.print(table)
    total: dict = {}
    while True:  # process in batches (one transaction each) until nothing is pending
        with session_scope() as s:
            stats = process_pending(s, settings, notify=notify)
        total = {k: total.get(k, 0) + v for k, v in stats.items()}
        if stats["rescored"] == 0:
            break
    console.print(f"Traitement : {total}")


@app.command()
def status() -> None:
    """État des sources, volumes, alertes récentes et latence de détection."""
    from cti.db.models import Alert, Evidence, Source, Vulnerability, Watchlist
    from cti.db.session import session_scope

    with session_scope() as s:
        t = Table("source", "type", "tier", "statut", "dernier succès", "échecs", "dernière erreur / raison")
        for src in s.scalars(select(Source).order_by(Source.tier, Source.name)):
            color = "green" if src.consecutive_failures == 0 and src.last_success_at else ("red" if src.consecutive_failures else "yellow")
            t.add_row(src.name, src.type, str(src.tier), src.status,
                      f"[{color}]{src.last_success_at:%Y-%m-%d %H:%M}[/]" if src.last_success_at else "[yellow]jamais[/]",
                      str(src.consecutive_failures), (src.last_error or src.disabled_reason or "")[:70])
        console.print(t)
        n_v = s.scalar(select(func.count()).select_from(Vulnerability))
        n_e = s.scalar(select(func.count()).select_from(Evidence))
        levels = dict(s.execute(select(Vulnerability.evidence_level, func.count()).group_by(Vulnerability.evidence_level)).all())
        since = _now() - timedelta(days=1)
        alerts = dict(s.execute(select(Alert.priority, func.count()).where(Alert.created_at > since).group_by(Alert.priority)).all())
        n_w = s.scalar(select(func.count()).select_from(Watchlist))
        console.print(f"Vulnérabilités : {n_v} | preuves : {n_e} | watchlist : {n_w}")
        console.print(f"Niveaux de preuve : {levels}")
        console.print(f"Alertes (24 h) : {alerts or 'aucune'}")
        lat = s.execute(
            select(Alert.cve_id, Alert.created_at, Vulnerability.published_at)
            .join(Vulnerability, Vulnerability.cve_id == Alert.cve_id)
            .where(Alert.kind == "vuln", Alert.priority.in_(("P1", "P2")), Vulnerability.published_at.is_not(None))
            .order_by(Alert.created_at.desc()).limit(20)
        ).all()
        if lat:
            hours = sorted((a - p).total_seconds() / 3600 for _, a, p in lat)
            console.print(f"Latence de détection P1/P2 (publication -> alerte), médiane sur {len(hours)} : {hours[len(hours) // 2]:.1f} h")


@app.command()
def show(cve_id: str) -> None:
    """Fiche détaillée et sourcée d'une CVE."""
    from cti.db.models import Match, Vulnerability
    from cti.db.session import session_scope

    cve_id = cve_id.upper()
    with session_scope() as s:
        v = s.get(Vulnerability, cve_id)
        if v is None:
            raise typer.BadParameter(f"{cve_id} inconnue (lancer `cti run`)")
        console.rule(f"[bold]{cve_id}[/] — {v.vendor or '?'} {v.product or ''}")
        console.print(f"[bold]Niveau de preuve[/] : {v.evidence_level} — confiance {v.confidence}/100" + (" [red]CONFLIT[/]" if v.has_conflict else ""))
        for c in v.conflict_notes or []:
            console.print(f"  [red]⚠ {c}[/]")
        console.print(f"[bold]Résumé FR[/] : {v.summary_fr or '(non généré)'}")
        console.print(f"[bold]Description[/] : {(v.description_en or '')[:600]}")
        console.print(f"[bold]CVSS[/] 3.1={v.cvss31_score} 4.0={v.cvss40_score} | [bold]EPSS[/] {v.epss} (p{v.epss_percentile}) | [bold]KEV[/] {v.kev} {v.kev_added or ''}")
        console.print("[bold]Versions corrigées[/] :")
        for f in v.fixed_versions or []:
            console.print(f"  - {f.get('product')} {('branche ' + f['branch']) if f.get('branch') else ''} -> {f.get('fixed')}  [dim]{f.get('source_url')}[/]")
        for m in v.mitigations or []:
            console.print(f"[bold]Mitigation[/] : {m['text'][:300]}  [dim]{m.get('source_url')}[/]")
        for i in v.iocs or []:
            console.print(f"[bold]IoC[/] {i['type']}: {i['value']}  [dim]{i.get('source_url')}[/]")
        t = Table("source", "tier", "type de preuve", "assertion", "citation", "url")
        for e in sorted(v.evidence, key=lambda e: (e.source.tier, e.kind)):
            t.add_row(e.source.name + ("" if e.source.status == "active" else f" ({e.source.status})"), str(e.source.tier), e.kind,
                      e.assertion, (e.quote or "")[:70], e.url)
        console.print(t)
        mt = Table("client", "actif", "statut version", "détail")
        for m in s.scalars(select(Match).where(Match.cve_id == cve_id)):
            mt.add_row(m.client_id, m.asset_id, m.version_status, m.detail or "")
        console.print(mt)
        console.print("[bold]Provenance des champs[/] :", json.dumps(v.field_sources, ensure_ascii=False)[:1500])


# ---------------------------------------------------------------- watchlist


@watch_app.command("add")
def watch_add(cve_id: str, reason: str = typer.Option("", "--reason", "-r"), days: int = typer.Option(30, "--days", "-d")) -> None:
    """Placer une CVE sous surveillance renforcée pour N jours."""
    from cti.db.models import Vulnerability, Watchlist
    from cti.db.session import session_scope
    from cti.pipeline.collect import ensure_vuln

    cve_id = cve_id.upper()
    with session_scope() as s:
        ensure_vuln(s, cve_id)
        s.merge(Watchlist(cve_id=cve_id, reason=reason or None, added_by="cli", expires_at=_now() + timedelta(days=days)))
        s.get(Vulnerability, cve_id).needs_rescore = True
    console.print(f"[green]{cve_id} sous surveillance renforcée jusqu'au {(_now() + timedelta(days=days)):%Y-%m-%d}[/]")


@watch_app.command("remove")
def watch_remove(cve_id: str) -> None:
    from cti.db.models import Watchlist
    from cti.db.session import session_scope

    with session_scope() as s:
        w = s.get(Watchlist, cve_id.upper())
        if w:
            s.delete(w)
    console.print(f"{cve_id.upper()} retirée de la watchlist")


@watch_app.command("list")
def watch_list() -> None:
    from cti.db.models import Vulnerability, Watchlist
    from cti.db.session import session_scope

    t = Table("CVE", "échéance", "raison", "niveau", "confiance")
    with session_scope() as s:
        for w, v in s.execute(select(Watchlist, Vulnerability).join(Vulnerability, Vulnerability.cve_id == Watchlist.cve_id)):
            expired = w.expires_at and w.expires_at < _now()
            t.add_row(w.cve_id, f"{w.expires_at:%Y-%m-%d}" + (" (expirée)" if expired else "") if w.expires_at else "-",
                      w.reason or "", v.evidence_level, str(v.confidence))
    console.print(t)


# ---------------------------------------------------------------- sources


@source_app.command("list")
def source_list() -> None:
    from cti.registry import load_registry

    settings = get_settings()
    t = Table("nom", "type", "rôle", "tier", "fiabilité", "statut", "intervalle", "clé manquante", "url")
    for d in load_registry(settings).sources:
        miss = d.missing_secrets(settings)
        t.add_row(d.name, d.type, d.role, str(d.tier), f"{d.effective_reliability:.2f}", d.status, f"{d.interval}s", ", ".join(miss), d.url)
    console.print(t)


@source_app.command("test")
def source_test(name: str, limit: int = typer.Option(5, help="Nombre d'éléments affichés")) -> None:
    """Collecte à blanc : rien n'est enregistré, affiche un aperçu."""
    from cti.collectors.base import SourceCtx, get_collector_class
    from cti.http import HttpClient
    from cti.registry import load_registry

    settings = get_settings()
    d = next((x for x in load_registry(settings).sources if x.name == name), None)
    if d is None:
        raise typer.BadParameter(f"source inconnue: {name}")
    ctx = SourceCtx(d.name, d.type, d.role, d.tier, d.url, d.config, {}, True)
    with HttpClient(None) as http:
        res = get_collector_class(d.type)(ctx, http, settings).collect()
    console.print(f"[bold]{name}[/] : {len(res.items)} éléments, {len(res.evidence)} preuves, {len(res.patches)} mises à jour, {len(res.snapshots)} snapshots")
    for it in res.items[:limit]:
        console.print(f" • {it.published_at:%Y-%m-%d} " if it.published_at else " • ", it.title, f"[dim]{it.url}[/]", it.cve_ids[:5])
    kinds: dict = {}
    for e in res.evidence:
        kinds[(e.kind, e.assertion)] = kinds.get((e.kind, e.assertion), 0) + 1
    console.print("Preuves par type :", kinds or "aucune")
    for n in res.notes:
        console.print(f"[dim]{n}[/]")


@source_app.command("add")
def source_add(
    name: str, url: str,
    type: str = typer.Option("rss", "--type", help="rss | json_api | ..."),
    role: str = typer.Option("press", "--role", help="vendor|cert|reference|research|press|social"),
    tier: int = typer.Option(3, "--tier"),
    interval: str = typer.Option("1h", "--interval"),
) -> None:
    """Ajouter une source (statut 'observation' : aucune alerte seule avant validation)."""
    from cti.registry import SourceDef, load_registry, save_registry

    settings = get_settings()
    reg = load_registry(settings)
    if any(s.name == name for s in reg.sources):
        raise typer.BadParameter(f"{name} existe déjà")
    reg.sources.append(SourceDef(name=name, type=type, role=role, tier=tier, url=url, interval=interval, status="observation"))
    save_registry(settings, reg)
    console.print(f"[green]{name} ajoutée en observation.[/] Tester : ./cti source test {name} — valider : ./cti source enable {name}")


def _set_status(name: str, status: str) -> None:
    from cti.registry import load_registry, save_registry

    settings = get_settings()
    reg = load_registry(settings)
    src = next((s for s in reg.sources if s.name == name), None)
    if src is None:
        raise typer.BadParameter(f"source inconnue: {name}")
    src.status = status
    save_registry(settings, reg)
    console.print(f"{name} -> {status}")


@source_app.command("disable")
def source_disable(name: str) -> None:
    _set_status(name, "disabled")


@source_app.command("enable")
def source_enable(name: str) -> None:
    """Validation humaine : passe une source en 'active' (elle pourra alors déclencher des alertes)."""
    _set_status(name, "active")


@source_app.command("observe")
def source_observe(name: str) -> None:
    _set_status(name, "observation")


# ---------------------------------------------------------------- notifications


@app.command("test-notify")
def test_notify(team: str = typer.Option(None, "--team", help="fr | kr (défaut : équipe de référence)")) -> None:
    """Envoyer une notification de test (dry-run si aucun webhook n'est configuré)."""
    from cti.db.session import session_scope
    from cti.notifiers.message import AlertMessage
    from cti.pipeline.notify import deliver, routing

    settings = get_settings()
    rt = routing(settings)
    tm = rt.team(team or rt.default_team)
    msg = AlertMessage(
        cve_id="", priority="P3", lang=tm.lang, title="Test de notification CTI Vuln Watch",
        summary="Message de test : aucune action requise." if tm.lang == "fr" else "Test message: no action required.",
        why=["test"], clients=[], actions=["aucune"], evidence="n/a", conflicts=[],
        sources=[{"label": "CERT-FR", "url": "https://www.cert.ssi.gouv.fr/"}], changes=["test"],
    )
    with session_scope() as s:
        a = deliver(s, settings, msg, tm, rt, kind="test", state={"test": _now().isoformat()}, reasons=["test"])
        console.print(f"Résultat : {a.status} via {a.channel}" + (f" — {a.error}" if a.error else ""))


@app.command()
def digest() -> None:
    """Envoyer maintenant le digest des alertes P3 en attente."""
    from cti.db.session import session_scope
    from cti.pipeline.notify import send_digest

    with session_scope() as s:
        n = send_digest(s, get_settings())
    console.print(f"{n} élément(s) envoyés dans le digest")


if __name__ == "__main__":
    app()
