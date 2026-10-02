from cti.scoring.evidence import EvidenceView, Level, score


def ev(kind, *, assertion="affirms", url="https://www.cisa.gov/x", name="cisa-kev", tier=1, role="reference",
       status="active", rel=0.6, suspicious=False, quote=None):
    return EvidenceView(kind, assertion, url, name, tier, role, status, rel, suspicious, quote)


def test_no_evidence():
    r = score([])
    assert r.level == Level.NO_KNOWN_EXPLOIT and r.confidence == 0


def test_kev_is_confirmed_and_independent_sources_raise_confidence():
    one = score([ev("kev_listed")])
    two = score([ev("kev_listed"), ev("cert_exploited", url="https://www.cert.ssi.gouv.fr/a", name="certfr", role="cert")])
    assert one.level == two.level == Level.EXPLOITED_CONFIRMED
    assert one.confidence == 60 and two.confidence == 84  # 1-(0.4*0.4)


def test_same_domain_counts_once():
    r = score([ev("kev_listed"), ev("kev_listed", url="https://www.cisa.gov/y", name="nvd")])
    assert r.confidence == 60


def test_observation_sources_have_no_weight():
    r = score([ev("research_exploited", url="https://labs.example/x", name="lab", tier=2, role="research", status="observation")])
    assert r.level == Level.NO_KNOWN_EXPLOIT
    assert r.explain["ignored_observation_sources"] == ["lab"]


def test_research_claim_is_reported_not_confirmed():
    r = score([ev("vendor_exploited", url="https://blog.example/x", name="blog", tier=3, role="press", rel=0.25)])
    assert r.level == Level.EXPLOITED_REPORTED  # role caps the level whatever the kind


def test_weak_only_flag():
    r = score([ev("social_exploited", url="https://infosec.exchange/@x/1", name="masto", tier=4, role="social", rel=0.1)])
    assert r.level == Level.EXPLOITED_REPORTED and r.weak_only


def test_suspicious_poc_only_when_alone():
    alone = score([ev("poc_github", url="https://github.com/a/b", name="gh", tier=2, role="research", suspicious=True)])
    assert alone.level == Level.POC_SUSPICIOUS
    mixed = score([
        ev("poc_github", url="https://github.com/a/b", name="gh", tier=2, role="research", suspicious=True),
        ev("poc_github", url="https://github.com/c/d", name="gh", tier=2, role="research"),
    ])
    assert mixed.level == Level.POC_CLAIMED and mixed.explain["suspicious_poc"] == ["https://github.com/a/b"]


def test_vendor_denial_vs_research_claim_is_a_conflict():
    r = score([
        ev("research_exploited", url="https://labs.watchtowr.com/x", name="watchtowr", tier=2, role="research", rel=0.4),
        ev("vendor_exploited", assertion="denies", url="https://www.ivanti.com/blog/x", name="psirt-ivanti", role="vendor",
           quote="We have no evidence of these vulnerabilities being exploited in the wild."),
    ])
    assert r.level == Level.EXPLOITED_REPORTED  # we do not arbitrate...
    assert r.has_conflict and "psirt-ivanti" in r.conflicts[0]  # ...we flag it
    assert r.confidence == 20  # 40 * 0.5


def test_explicit_denial_without_claim_gives_confidence_in_no_exploit():
    r = score([ev("vendor_exploited", assertion="denies", url="https://www.ivanti.com/b", name="psirt-ivanti", role="vendor")])
    assert r.level == Level.NO_KNOWN_EXPLOIT and r.confidence == 60 and not r.has_conflict


def test_public_poc_from_cert():
    r = score([ev("authority_poc_public", url="https://www.cert.ssi.gouv.fr/a", name="certfr", role="cert")])
    assert r.level == Level.POC_PUBLIC_VERIFIED
