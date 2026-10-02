"""End-to-end on a real PostgreSQL: NetScaler CTX697096 case, from recorded source responses.

Covers: collection -> evidence -> scoring -> inventory matching -> priority -> dry-run
notification -> strict dedup -> bulletin revision + bypass signal on a watched CVE ->
technical alert on a failing source.
"""

import json
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from conftest import fixture_bytes, fixture_json
from sqlalchemy import select

from cti.db.models import Alert, Evidence, Match, Source, Vulnerability, Watchlist
from cti.http import HttpClient
from cti.pipeline import notify as notify_mod
from cti.pipeline.collect import run_source
from cti.pipeline.process import process_pending
from cti.registry import sync_sources

pytestmark = pytest.mark.db

PARIS_MORNING = datetime(2026, 9, 29, 10, 0, tzinfo=ZoneInfo("Europe/Paris"))  # both teams on shift


def nvd_page(_request=None) -> bytes:
    a = fixture_json("nvd/CVE-2026-88771.json")
    b = fixture_json("nvd/CVE-2026-88772.json")
    a["vulnerabilities"] += b["vulnerabilities"]
    a["totalResults"] = a["resultsPerPage"] = 2
    return json.dumps(a).encode()


@pytest.fixture
def env(session, settings, router, monkeypatch):
    certfr_doc = {"doc": fixture_json("certfr/CERTFR-2026-ALE-011.json")}
    router.add("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
               fixture_bytes("kev/known_exploited_vulnerabilities_2026-09-29.json"), headers={"ETag": '"kev-v1"'})
    router.add("https://services.nvd.nist.gov/rest/json/cves/2.0", nvd_page)
    router.add("https://www.cert.ssi.gouv.fr/alerte/feed/", fixture_bytes("certfr/alerte_feed.xml"))
    router.add("https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-011/json/", lambda r: json.dumps(certfr_doc["doc"]).encode())
    router.add("https://support.citrix.com/external/article/697096", fixture_bytes("psirt/citrix_CTX697096.html"))
    monkeypatch.setattr(notify_mod, "now", lambda: PARIS_MORNING)

    sync_sources(session, settings)
    # Sources considered already initialised (not a historical backfill), except KEV.
    for name in ("nvd", "certfr-alertes", "psirt-citrix"):
        session.scalar(select(Source).where(Source.name == name)).last_success_at = datetime.now(UTC) - timedelta(hours=1)
    session.flush()
    http = HttpClient(session, transport=router.transport(), throttle=False, max_retries=0)

    def run(name):
        return run_source(session, session.scalar(select(Source).where(Source.name == name)), settings, http=http)

    return {"run": run, "certfr_doc": certfr_doc, "session": session, "settings": settings}


def alerts(session, **filters):
    q = select(Alert)
    for k, v in filters.items():
        q = q.where(getattr(Alert, k) == v)
    return session.scalars(q.order_by(Alert.id)).all()


def test_netscaler_end_to_end(env):
    s, settings, run = env["session"], env["settings"], env["run"]

    st = run("certfr-alertes")
    assert st["status"] == "ok" and st["evidence_new"] > 0  # other feed entries 404: isolated, no failure
    assert run("cisa-kev")["status"] == "ok"
    assert run("nvd")["status"] == "ok"
    st = run("psirt-citrix")  # bulletin discovered through the CERT-FR link + config watch list
    assert st["status"] == "ok" and st["items_seen"] == 1

    stats = process_pending(s, settings)
    assert stats["notified"] > 0

    v = s.get(Vulnerability, "CVE-2026-88771")
    assert v.evidence_level == "EXPLOITED_CONFIRMED"
    assert v.confidence >= 90 and not v.has_conflict
    domains = set(v.scoring_explain["independent_domains"])
    assert {"cisa.gov", "ssi.gouv.fr", "citrix.com"} <= domains
    assert v.kev and v.cvss31_score == 9.8 and v.cvss40_score == 9.5
    assert any(f["fixed"] == "14.1-73.37" for f in v.fixed_versions)
    # every evidence row carries a source URL
    assert all(e.url.startswith("https://") for e in v.evidence)
    # 6 other CVEs of the bulletin: known, but not marked exploited by the vendor sentence
    other = s.get(Vulnerability, "CVE-2026-88775")
    assert other is not None and other.evidence_level == "NO_KNOWN_EXPLOIT"

    m = {x.asset_id: x.version_status for x in s.scalars(select(Match).where(Match.cve_id == "CVE-2026-88771"))}
    assert m == {"acme-industrie/vpn-gw-01": "affected", "acme-industrie/adc-lb-01": "not_affected", "sante-plus/netscaler-01": "unknown"}

    p1 = [a for a in alerts(s, cve_id="CVE-2026-88771") if a.priority == "P1"]
    assert {a.audience for a in p1} == {"fr", "kr"}  # follow-the-sun: both on shift
    assert {a.lang for a in p1} == {"fr", "en"}
    assert all(a.status == "dry_run" for a in p1)  # no webhook configured
    fr = next(a for a in p1 if a.audience == "fr").payload["message"]
    assert "ACME" in " ".join(fr["clients"]) and "Santé Plus" in " ".join(fr["clients"])
    assert all("Banque" not in c for c in fr["clients"])
    assert fr["sources"] and all(src["url"].startswith("https://") for src in fr["sources"])
    # exploitation / PoC sources listed with URL and quote
    ex = {e["label"].split(" ")[0]: e for e in fr["exploit_sources"]}
    assert {"psirt-citrix", "certfr-alertes", "cisa-kev"} <= set(ex)
    assert "have been observed" in ex["psirt-citrix"]["quote"]
    assert all(e["url"].startswith("https://") for e in fr["exploit_sources"])

    # --- strict dedup: reprocessing without change sends nothing new
    n_before = len(alerts(s))
    for vv in s.scalars(select(Vulnerability)):
        vv.needs_rescore = True
    process_pending(s, settings)
    assert len(alerts(s)) == n_before

    # --- bulletin revision announcing an incomplete fix, on a watched CVE
    s.merge(Watchlist(cve_id="CVE-2026-88771", reason="demande clients", added_by="test",
                      expires_at=datetime.now(UTC) + timedelta(days=30)))
    doc = env["certfr_doc"]["doc"]
    doc["summary"] += "\n\n**[Mise à jour du 30 septembre 2026]**\nCitrix indique que le correctif initial de la vulnérabilité CVE-2026-88771 est un correctif incomplet."
    doc["revisions"].append({"description": "Correctif incomplet", "revision_date": "2026-09-30T00:00:00.000000"})
    src = s.scalar(select(Source).where(Source.name == "certfr-alertes"))
    src.state = {}  # force re-fetch of feed entries
    s.flush()
    assert run("certfr-alertes")["revisions"] == 1
    kinds = {e.kind for e in s.scalars(select(Evidence).where(Evidence.cve_id == "CVE-2026-88771"))}
    assert {"bulletin_revision", "bypass_signal"} <= kinds

    process_pending(s, settings)
    new =[a for a in alerts(s, cve_id="CVE-2026-88771") if a.id > max(x.id for x in p1)]
    assert new, "a revision + bypass signal on a watched CVE must re-notify"
    reasons = set(sum((a.change_reasons for a in new), []))
    assert {"révision de bulletin", "signal de contournement"} <= reasons


def test_failing_source_isolated_and_technical_alert(env):
    s, run = env["session"], env["run"]
    for _ in range(3):
        st = run("psirt-fortinet")  # not in fixtures -> HTTP 404
        assert st["status"] == "error"
    assert run("cisa-kev")["status"] == "ok"  # other sources unaffected
    src = s.scalar(select(Source).where(Source.name == "psirt-fortinet"))
    assert src.consecutive_failures == 3 and "404" in src.last_error
    tech = alerts(s, kind="technical")
    assert len(tech) == 1 and "psirt-fortinet" in tech[0].payload["message"]["title"]


def test_kev_conditional_request(env, router):
    run = env["run"]
    assert run("cisa-kev")["status"] == "ok"
    router.routes.insert(0, ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                             lambda req: __import__("httpx").Response(304 if req.headers.get("if-none-match") == '"kev-v1"' else 200)))
    assert run("cisa-kev")["status"] == "not_modified"
