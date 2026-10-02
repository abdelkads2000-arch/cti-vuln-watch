"""Deterministic claim extraction (exploitation / PoC / bypass), sentence by sentence.

Attribution of a claim to CVE ids, from strongest to weakest:
  1. CVE ids in the same sentence                     -> attribution="sentence"
  2. CVE ids in the immediately preceding sentence    -> attribution="previous_sentence"
     (handles "CVE-A and CVE-B allow RCE. These vulnerabilities are actively exploited.")
  3. Document-level fallback:
     - affirmations only when the document concerns exactly ONE CVE
     - denials from a vendor/CERT when the document concerns <= 10 CVEs
       (vendors typically deny exploitation for the whole bulletin)
Anything else is left unattributed: we prefer missing a claim to inventing one.
Negations are tested before affirmations on each sentence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from cti.extraction.text import find_cves, paragraphs, sentences

CATEGORIES = ("exploitation", "poc", "bypass")


@dataclass(frozen=True)
class Claim:
    category: str  # exploitation | poc | bypass
    assertion: str  # affirms | denies
    cve_ids: tuple[str, ...]
    quote: str
    attribution: str


@dataclass
class KeywordSet:
    deny: dict[str, list[re.Pattern]] = field(default_factory=dict)
    affirm: dict[str, list[re.Pattern]] = field(default_factory=dict)


@lru_cache(maxsize=4)
def load_keywords(path: str) -> KeywordSet:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    ks = KeywordSet()
    for cat in CATEGORIES:
        block = data.get(cat) or {}
        ks.deny[cat] = [re.compile(p, re.I) for p in block.get("deny", [])]
        ks.affirm[cat] = [re.compile(p, re.I) for p in block.get("affirm", [])]
    return ks


def _match(patterns: list[re.Pattern], sentence: str) -> bool:
    return any(p.search(sentence) for p in patterns)


def extract_claims(
    text: str,
    keywords: KeywordSet,
    *,
    doc_cves: list[str] | None = None,
    source_role: str = "press",
    max_quote: int = 400,
) -> list[Claim]:
    doc_cves = doc_cves if doc_cves is not None else find_cves(text)
    claims: dict[tuple, Claim] = {}
    prev_cves: list[str] = []
    for para in paragraphs(text):
        for sent in sentences(para):
            sent_cves = find_cves(sent)
            for cat in CATEGORIES:
                if _match(keywords.deny.get(cat, []), sent):
                    assertion = "denies"
                elif _match(keywords.affirm.get(cat, []), sent):
                    assertion = "affirms"
                else:
                    continue
                if sent_cves:
                    targets, how = sent_cves, "sentence"
                elif prev_cves:
                    targets, how = prev_cves, "previous_sentence"
                elif assertion == "affirms" and len(doc_cves) == 1:
                    targets, how = doc_cves, "document"
                elif assertion == "denies" and source_role in ("vendor", "cert") and 0 < len(doc_cves) <= 10:
                    targets, how = doc_cves, "document"
                else:
                    continue
                quote = sent if len(sent) <= max_quote else sent[: max_quote - 1] + "…"
                for cve in targets:
                    key = (cat, assertion, cve)
                    if key not in claims:
                        claims[key] = Claim(cat, assertion, (cve,), quote, how)
            prev_cves = sent_cves
    return list(claims.values())
