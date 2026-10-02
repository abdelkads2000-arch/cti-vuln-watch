from datetime import datetime
from zoneinfo import ZoneInfo

from cti.notifiers.message import build_message
from cti.notifiers.routing import Routing
from cti.notifiers.teams import adaptive_card
from cti.priority import PriorityInput, change_reasons, decide, fingerprint
from cti.scoring.evidence import Level


def pin(**kw):
    base = dict(cve_id="CVE-X", level=Level.NO_KNOWN_EXPLOIT, weak_only=False, cvss=None, epss=None,
                client_match=False, client_exposed=False, in_watchlist=False, bypass_signal=False)
    base.update(kw)
    return PriorityInput(**base)


def test_rules(config_dir):
    rules = str(config_dir / "priority.yaml")
    assert decide(pin(level=Level.EXPLOITED_CONFIRMED, client_match=True), rules).priority == "P1"
    assert decide(pin(bypass_signal=True, in_watchlist=True), rules).priority == "P1"
    assert decide(pin(cvss=9.8, client_match=True, client_exposed=True), rules).priority == "P1"
    assert decide(pin(cvss=9.1, client_match=True), rules).priority == "P2"
    assert decide(pin(epss=0.7, client_match=True), rules).priority == "P2"
    assert decide(pin(level=Level.POC_PUBLIC_VERIFIED, client_match=True), rules).priority == "P2"
    assert decide(pin(level=Level.EXPLOITED_CONFIRMED), rules).priority == "P3"
    assert decide(pin(cvss=9.8), rules).priority == "P3"
    assert decide(pin(cvss=5.0, client_match=True), rules).priority is None


def test_weak_signals_never_trigger_p1_alone(config_dir):
    d = decide(pin(level=Level.EXPLOITED_REPORTED, weak_only=True, client_match=True), str(config_dir / "priority.yaml"))
    assert d.priority == "P3" and "signaux faibles" in d.reasons[-1]


def test_dedup_fingerprint_and_reasons():
    s1 = {"level": "EXPLOITED_CONFIRMED", "clients": ["a"], "bulletin_revisions": 0, "patch_available": True, "bypass": False, "priority": "P1"}
    assert fingerprint(s1) == fingerprint(dict(reversed(list(s1.items()))))
    assert change_reasons(None, s1) == ["première notification"]
    s2 = {**s1, "bulletin_revisions": 1}
    assert change_reasons(s1, s2) == ["révision de bulletin"]
    s3 = {**s1, "clients": []}  # a client leaving the scope: no re-notification
    assert change_reasons(s1, s3) == []


def test_follow_the_sun(config_dir):
    rt = Routing.load(config_dir / "routing.yaml")
    paris_morning = datetime(2026, 9, 29, 10, 0, tzinfo=ZoneInfo("Europe/Paris"))  # 17:00 Seoul
    assert [t.id for t in rt.recipients("P1", paris_morning)] == ["fr", "kr"]
    seoul_morning = datetime(2026, 9, 29, 9, 0, tzinfo=ZoneInfo("Asia/Seoul"))  # 02:00 Paris
    assert [t.id for t in rt.recipients("P2", seoul_morning)] == ["kr"]
    nobody = datetime(2026, 9, 29, 22, 30, tzinfo=ZoneInfo("Europe/Paris"))  # 05:30 Seoul
    assert [t.id for t in rt.recipients("P1", nobody)] == ["fr", "kr"]
    assert [t.id for t in rt.recipients("P2", nobody)] == ["fr"]
    assert rt.recipients("P3", paris_morning) == []


def _ctx():
    return {
        "cve_id": "CVE-2026-88771", "priority": "P1", "sla": "immédiat", "level": "EXPLOITED_CONFIRMED",
        "level_quote": "psirt-citrix: «Exploits of CVE-2026-88771 ... have been observed.»", "confidence": 94,
        "conflicts": [], "decision_reasons": ["exploitation + client"], "changes": ["première notification"],
        "matches": [{"client_name": "ACME", "asset_label": "Citrix NetScaler Gateway 14.1-47.46", "version_status": "affected",
                     "internet_exposed": True, "detail": "14.1-47.46 < 14.1-73.37"}],
        "sources": [{"label": "cisa-kev", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-88771"}],
        "exploit_sources": [
            {"label": "psirt-citrix (vendor_exploited)", "url": "https://support.citrix.com/external/article/697096",
             "quote": "Exploits of CVE-2026-88771 and CVE-2026-88772 on unmitigated NetScaler deployments have been observed.", "counted": True},
            {"label": "watchtowr-labs (research_exploited)", "url": "https://labs.watchtowr.com/x", "quote": None, "counted": False},
        ],
        "vuln": {"vendor": "Citrix", "product": "NetScaler", "description_en": "Improper input validation...", "summary_fr": None,
                 "kev": True, "kev_added": "2026-09-27", "cvss31_score": 9.8, "cvss40_score": 9.5, "epss": 0.0106,
                 "epss_percentile": 0.63, "fixed_versions": [{"fixed": "14.1-73.37"}], "mitigations": []},
    }


def test_message_fr_en_and_card():
    fr = build_message(_ctx(), "fr")
    en = build_message(_ctx(), "en")
    assert "Exploitation CONFIRMÉE" in fr.title and "Exploitation CONFIRMED" in en.title
    assert any("14.1-73.37" in a for a in fr.actions)
    assert any("compromission" in a for a in fr.actions)  # hunt when exploited
    assert "VULNÉRABLE" in fr.clients[0] and "exposé internet" in fr.clients[0]
    text = fr.to_text()
    assert "https://www.cisa.gov/" in text  # every alert carries its sources
    assert "Exploitation / PoC : sources" in text and "https://support.citrix.com/external/article/697096" in text
    assert "non comptée" in text  # observation source shown but flagged
    card = adaptive_card(fr)
    assert "support.citrix.com" in str(card)
    assert card["type"] == "message"
    assert card["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
