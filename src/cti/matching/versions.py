"""Version parsing and branch-aware range checks.

Vendors publish fixes per branch: "13.1 before 13.1-64.23", "14.1 before 14.1-73.37".
A naive comparison would flag 13.1-64.23 (fixed) as vulnerable to "< 14.1-73.37".
Rule used here: a fix statement applies to a version only if both share the same
branch prefix (first two numeric components by default). When nothing can be
concluded, the result is 'unknown' — never silently 'not_affected'.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

_NUM_RE = re.compile(r"\d+")
_QUALIFIERS = ("FIPS", "NDCPP")


def version_key(v: str) -> tuple[int, ...]:
    """'14.1-73.37' -> (14, 1, 73, 37); '2019 CU14' -> (2019, 14)."""
    return tuple(int(x) for x in _NUM_RE.findall(v or ""))


def qualifiers(v: str) -> frozenset[str]:
    up = (v or "").upper()
    return frozenset(q for q in _QUALIFIERS if q in up)


def branch(v: str, depth: int = 2) -> tuple[int, ...]:
    return version_key(v)[:depth]


@dataclass(frozen=True)
class FixStatement:
    product_text: str
    branch: str | None  # "14.1" or None when not stated
    fixed: str  # first fixed version, e.g. "14.1-73.37 FIPS"
    source_text: str

    def to_dict(self) -> dict:
        return asdict(self)


_VERSION_TOKEN = r"\d[\w.\-]*"
_QUAL = r"(?:\s+(?:FIPS|NDcPP)(?:\s+(?:and|et)\s+(?:FIPS|NDcPP))?)?"
_FIX_PATTERNS = [
    # EN: "Citrix NetScaler ADC and Citrix NetScaler Gateway 14.1 BEFORE 14.1-73.37"
    #     "FortiOS 7.4.0 through 7.4.4 ... upgrade to 7.4.5" is handled elsewhere (phase 2).
    re.compile(
        rf"^(?P<product>.+?)\s+(?:versions?\s+)?(?:(?P<branch>\d+(?:\.\d+)+)(?:\.x)?\s+)?"
        rf"(?:before|prior to|earlier than|below)\s+(?P<fixed>{_VERSION_TOKEN}{_QUAL})",
        re.I,
    ),
    # FR (CERT-FR): "Citrix NetScaler ADC versions 14.1.x antérieures à 14.1-73.37"
    re.compile(
        rf"^(?P<product>.+?)\s+versions?\s+(?:(?P<branch>\d+(?:\.\d+)*)(?:\.x)?(?:-FIPS)?\s+)?"
        rf"(?:antérieures?|antérieurs?)\s+à\s+(?:la\s+version\s+)?(?P<fixed>{_VERSION_TOKEN}{_QUAL})",
        re.I,
    ),
]


def parse_fix_statement(text: str) -> FixStatement | None:
    line = " ".join(text.split())
    for pat in _FIX_PATTERNS:
        m = pat.search(line)
        if m:
            product = re.sub(r"\s+(?:versions?)$", "", m.group("product").strip(), flags=re.I)
            return FixStatement(product, m.group("branch"), _clean_fixed(line[m.start("fixed"):]), line)
    return None


def _clean_fixed(tail: str) -> str:
    """'13.1-NDcPP 13.1.37.279' -> '13.1.37.279 NDcPP' ; '14.1-73.37 FIPS' unchanged.
    Keeps the most specific version number of the statement plus its build qualifiers."""
    tail = re.split(r"[,;(]", tail)[0]
    tokens = re.findall(r"\d+(?:[.\-]\d+)+", tail)
    if not tokens:
        return tail.strip()
    best = max(tokens, key=lambda t: len(version_key(t)))
    quals = [q for q in ("FIPS", "NDcPP") if q.upper() in tail.upper()]
    return " ".join([best, *quals])


def check_version(version: str | None, fixes: list[FixStatement]) -> tuple[str, str]:
    """Return (status, explanation). status in affected | not_affected | unknown."""
    if not version:
        return "unknown", "version non renseignée dans l'inventaire"
    vkey = version_key(version)
    if not vkey:
        return "unknown", f"version illisible: {version!r}"
    vqual = qualifiers(version)
    applicable = []
    for f in fixes:
        fq = qualifiers(f.fixed) | qualifiers(f.product_text)
        # FIPS/NDcPP builds are separate release trains: only compare like with like.
        if fq != vqual and not (fq and vqual and fq & vqual):
            continue
        fbranch = version_key(f.branch) if f.branch else branch(f.fixed)
        depth = len(fbranch)
        if depth and vkey[:depth] != fbranch[:depth]:
            continue
        applicable.append(f)
    if not applicable:
        branches = sorted({f.branch or ".".join(map(str, branch(f.fixed))) for f in fixes})
        return "unknown", f"branche {'.'.join(map(str, vkey[:2]))} absente des branches publiées ({', '.join(branches)})"
    for f in applicable:
        if vkey < version_key(f.fixed):
            return "affected", f"{version} < {f.fixed} (branche {f.branch or branch(f.fixed)})"
    best = max(applicable, key=lambda f: version_key(f.fixed))
    return "not_affected", f"{version} >= {best.fixed}"
