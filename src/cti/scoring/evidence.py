"""Deterministic evidence level, confidence score and conflict detection.

Input : the list of evidence rows for one CVE (each with its source tier/status/role).
Output: evidence level, confidence 0-100, conflicts, and a human-readable explanation.

Rules (see docs/ARCHITECTURE.md §7):
  * Only evidence from sources with status 'active' counts. 'observation' sources are
    reported in the explanation but have zero weight.
  * The level is the highest one reached by at least one counted evidence.
  * Weak signals (tier 4 / social / search) can reach at most EXPLOITED_REPORTED or
    POC_CLAIMED, and are flagged `weak_only` when nothing stronger supports the level.
  * The LLM never produces evidence kinds that raise the level on its own: LLM-extracted
    claims are only accepted when their quote is verified verbatim (see extraction.llm),
    and they are capped at the level of their source role like any rule-based claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from urllib.parse import urlsplit


class Level(IntEnum):
    NO_KNOWN_EXPLOIT = 0
    POC_SUSPICIOUS = 1
    POC_CLAIMED = 2
    POC_PUBLIC_VERIFIED = 3
    EXPLOITED_REPORTED = 4
    EXPLOITED_CONFIRMED = 5


# evidence kind -> level it supports
KIND_LEVEL: dict[str, Level] = {
    "kev_listed": Level.EXPLOITED_CONFIRMED,
    "vendor_exploited": Level.EXPLOITED_CONFIRMED,
    "cert_exploited": Level.EXPLOITED_CONFIRMED,
    "cisa_ssvc_active": Level.EXPLOITED_CONFIRMED,
    "research_exploited": Level.EXPLOITED_REPORTED,
    "vulncheck_kev": Level.EXPLOITED_REPORTED,
    "social_exploited": Level.EXPLOITED_REPORTED,
    "search_exploited": Level.EXPLOITED_REPORTED,
    "poc_metasploit": Level.POC_PUBLIC_VERIFIED,
    "poc_nuclei": Level.POC_PUBLIC_VERIFIED,
    "poc_exploitdb": Level.POC_PUBLIC_VERIFIED,
    "authority_poc_public": Level.POC_PUBLIC_VERIFIED,
    "cisa_ssvc_poc": Level.POC_PUBLIC_VERIFIED,
    "poc_github": Level.POC_CLAIMED,
    "poc_reference": Level.POC_CLAIMED,
    "research_poc": Level.POC_CLAIMED,
    "social_poc": Level.POC_CLAIMED,
    "search_poc": Level.POC_CLAIMED,
}
# Kinds whose support is never sufficient alone for P1/P2.
WEAK_KINDS = {"social_exploited", "search_exploited", "social_poc", "search_poc"}
# Tier-1 roles whose denial of exploitation creates a conflict with lower-tier claims.
AUTHORITATIVE_ROLES = {"vendor", "cert", "reference"}


@dataclass
class EvidenceView:
    """Scoring-relevant projection of an Evidence row (decoupled from the ORM for tests)."""

    kind: str
    assertion: str
    url: str
    source_name: str
    source_tier: int
    source_role: str
    source_status: str
    reliability: float
    suspicious: bool = False
    quote: str | None = None


@dataclass
class ScoreResult:
    level: Level
    confidence: int
    has_conflict: bool
    conflicts: list[str] = field(default_factory=list)
    weak_only: bool = False
    explain: dict = field(default_factory=dict)


# Minimal public-suffix handling for the registrable domain (independence of sources).
_MULTI_LABEL_SUFFIXES = {"gouv.fr", "gov.uk", "co.uk", "com.au", "co.jp", "go.kr", "or.kr", "co.kr", "gov.au"}


def _domain(url: str) -> str:
    host = urlsplit(url).netloc.lower().split(":")[0]
    parts = host.split(".")
    n = 3 if ".".join(parts[-2:]) in _MULTI_LABEL_SUFFIXES else 2
    return ".".join(parts[-n:]) if len(parts) >= n else host


def _effective_level(ev: EvidenceView) -> Level | None:
    lvl = KIND_LEVEL.get(ev.kind)
    if lvl is None:
        return None
    if ev.kind == "poc_github" and ev.suspicious:
        return Level.POC_SUSPICIOUS
    # A claim can never exceed what its source's role allows (defense in depth).
    if ev.source_role in ("research", "press", "social") and lvl == Level.EXPLOITED_CONFIRMED:
        return Level.EXPLOITED_REPORTED
    if ev.source_tier >= 4 and lvl > Level.EXPLOITED_REPORTED:
        return Level.EXPLOITED_REPORTED
    return lvl


def score(evidence: list[EvidenceView]) -> ScoreResult:
    counted = [e for e in evidence if e.source_status == "active"]
    observed = [e for e in evidence if e.source_status == "observation"]
    affirms = [e for e in counted if e.assertion == "affirms"]
    denies = [e for e in counted if e.assertion == "denies"]

    levels = [(lvl, e) for e in affirms if (lvl := _effective_level(e)) is not None]
    # POC_SUSPICIOUS only if it is the ONLY PoC signal; otherwise it stays a flag.
    best = max((lvl for lvl, _ in levels), default=Level.NO_KNOWN_EXPLOIT)
    if best == Level.POC_SUSPICIOUS and any(lvl >= Level.POC_CLAIMED for lvl, _ in levels):
        best = max(lvl for lvl, _ in levels if lvl != Level.POC_SUSPICIOUS)

    supporting = [e for lvl, e in levels if lvl == best]
    weak_only = bool(supporting) and all(e.kind in WEAK_KINDS or e.source_tier >= 4 for e in supporting)

    # Confidence: 1 - prod(1 - w) over independent domains supporting the retained level.
    per_domain: dict[str, float] = {}
    for e in supporting:
        d = _domain(e.url)
        per_domain[d] = max(per_domain.get(d, 0.0), e.reliability)
    conf = 1.0
    for w in per_domain.values():
        conf *= 1.0 - w
    confidence = 1.0 - conf if per_domain else 0.0

    conflicts: list[str] = []
    exploitation_denials = [e for e in denies if KIND_LEVEL.get(e.kind, Level.NO_KNOWN_EXPLOIT) >= Level.EXPLOITED_REPORTED]
    if best >= Level.EXPLOITED_REPORTED and exploitation_denials:
        for d in exploitation_denials:
            if d.source_role in AUTHORITATIVE_ROLES:
                conflicts.append(
                    f"{d.source_name} dément l'exploitation («{(d.quote or '')[:160]}») alors que "
                    f"{', '.join(sorted({e.source_name for e in supporting}))} l'affirme(nt)"
                )
                confidence *= 0.5
    if best == Level.NO_KNOWN_EXPLOIT and exploitation_denials:
        # Explicit vendor denial with no counter-claim: high confidence in "no known exploit".
        doms = {_domain(e.url): e.reliability for e in exploitation_denials}
        c = 1.0
        for w in doms.values():
            c *= 1.0 - w
        confidence = 1.0 - c

    explain = {
        "retained_level": best.name,
        "supporting": [
            {"source": e.source_name, "tier": e.source_tier, "kind": e.kind, "url": e.url, "weight": e.reliability}
            for e in supporting
        ],
        "independent_domains": sorted(per_domain),
        "denials": [{"source": e.source_name, "kind": e.kind, "url": e.url, "quote": e.quote} for e in denies],
        "ignored_observation_sources": sorted({e.source_name for e in observed}),
        "suspicious_poc": [e.url for e in affirms if e.kind == "poc_github" and e.suspicious],
        "formula": "confiance = 1 - Π(1 - fiabilité) sur domaines indépendants ; x0.5 par démenti d'une source de niveau 1",
    }
    return ScoreResult(
        level=best,
        confidence=round(confidence * 100),
        has_conflict=bool(conflicts),
        conflicts=conflicts,
        weak_only=weak_only,
        explain=explain,
    )
