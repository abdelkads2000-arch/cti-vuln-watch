"""Helpers shared by collectors."""

from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from dateutil import parser as dtparser

from cti.collectors.base import EvidenceOut
from cti.extraction.claims import Claim, KeywordSet, extract_claims, load_keywords
from cti.settings import Settings

# (category, source role) -> evidence kind. The kind (not the LLM, not the text) is
# what the scoring rules consume.
_KIND = {
    ("exploitation", "vendor"): "vendor_exploited",
    ("exploitation", "cert"): "cert_exploited",
    ("exploitation", "reference"): "cert_exploited",
    ("exploitation", "research"): "research_exploited",
    ("exploitation", "press"): "research_exploited",
    ("exploitation", "social"): "social_exploited",
    ("poc", "vendor"): "authority_poc_public",
    ("poc", "cert"): "authority_poc_public",
    ("poc", "reference"): "authority_poc_public",
    ("poc", "research"): "research_poc",
    ("poc", "press"): "research_poc",
    ("poc", "social"): "social_poc",
}


def claim_kind(category: str, role: str) -> str:
    if category == "bypass":
        return "bypass_signal"
    return _KIND[(category, role)]


def keywords(settings: Settings) -> KeywordSet:
    return load_keywords(str(settings.config_dir / "keywords.yaml"))


def evidence_from_text(
    text: str,
    *,
    settings: Settings,
    role: str,
    url: str,
    doc_cves: list[str],
    item_external_id: str | None,
    mention_kind: str | None = None,
) -> list[EvidenceOut]:
    """Claims (exploitation/PoC/bypass) + optional mention evidence for each doc CVE."""
    out: list[EvidenceOut] = []
    if mention_kind:
        out += [
            EvidenceOut(cve, mention_kind, url, item_external_id=item_external_id, extracted_by="structured")
            for cve in doc_cves
        ]
    claims: list[Claim] = extract_claims(text, keywords(settings), doc_cves=doc_cves, source_role=role)
    for c in claims:
        out.append(
            EvidenceOut(
                cve_id=c.cve_ids[0],
                kind=claim_kind(c.category, role),
                url=url,
                assertion=c.assertion,
                quote=c.quote,
                extracted_by="rule",
                details={"attribution": c.attribution, "category": c.category},
                item_external_id=item_external_id,
            )
        )
    return out


def parse_date(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            try:
                dt = dtparser.parse(str(value))
            except (ValueError, OverflowError):
                return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)
