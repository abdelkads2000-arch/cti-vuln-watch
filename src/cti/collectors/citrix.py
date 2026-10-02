"""Citrix / NetScaler security bulletins.

Citrix has no usable official feed (its "RSS" URL returns an application shell).
Bulletins are server-rendered under support.citrix.com/external/article/<id>
(explicitly allowed by robots.txt). We follow:
  - bulletins listed in the source config (`watch`),
  - bulletins cited by any other collected document (CERT-FR, NVD, cvelist...),
and re-fetch each of them for `follow_days` to detect revisions.
"""

from __future__ import annotations

import json
import re

from bs4 import BeautifulSoup

from cti.collectors.base import CollectResult, Collector, ItemOut, SnapshotOut, VulnPatch, register
from cti.collectors.common import evidence_from_text, parse_date, utcnow
from cti.extraction.text import find_cves, html_to_text
from cti.matching.versions import parse_fix_statement
from cti.settings import Settings

ARTICLE_URL = "https://support.citrix.com/external/article/{num}"
_ID_PATTERNS = [
    re.compile(r"support\.citrix\.com/.*?articleNumber=CTX(\d{5,7})", re.I),
    re.compile(r"support\.citrix\.com/external/article/(?:CTX)?(\d{5,7})", re.I),
    re.compile(r"support\.citrix\.com/(?:s/)?article/CTX(\d{5,7})", re.I),
    re.compile(r"^CTX(\d{5,7})$", re.I),
]
URL_HINT = "support.citrix.com"


def bulletin_ids(urls_or_ids: list[str]) -> list[str]:
    out: dict[str, None] = {}
    for u in urls_or_ids:
        for p in _ID_PATTERNS:
            m = p.search(u.strip())
            if m:
                out.setdefault(f"CTX{m.group(1)}", None)
                break
    return list(out)


def _jsonld(soup: BeautifulSoup) -> dict:
    for tag in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(tag.string or "")
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("@type") == "Article":
            return data
    return {}


SECTION_HEADINGS = (
    "Description of Problem", "Affected Versions", "What Customers Should Do", "Mitigating Factors", "Mitigation",
    "Workaround", "Indicators of Compromise", "Indicators", "Acknowledgements", "Changelog", "What Citrix Is Doing",
    "Obtaining Support on This Issue", "Subscribe to Receive Alerts", "Disclaimer",
)


def _section(body: str, heading: str) -> str | None:
    """Text of a section: from `heading` (on its own line) to the next known heading."""
    m = re.search(rf"(?m)^{re.escape(heading)}\s*$", body)
    if not m:
        return None
    rest = body[m.end():]
    ends = [mm.start() for h in SECTION_HEADINGS if h != heading and (mm := re.search(rf"(?m)^{re.escape(h)}\s*$", rest))]
    text = rest[: min(ends)] if ends else rest[:1500]
    return " ".join(text.split()) or None


def parse_citrix_bulletin(html: str, ctx_id: str, url: str, settings: Settings) -> CollectResult:
    soup = BeautifulSoup(html, "lxml")
    meta = _jsonld(soup)
    title = meta.get("headline") or (soup.title.string.strip() if soup.title and soup.title.string else ctx_id)
    text = html_to_text(html)
    # Keep only the bulletin body (drop the navigation chrome above "Article ID:").
    # Section order varies between bulletins, so we do not rely on it.
    start = text.find("Article ID:")
    body = text[start:] if start >= 0 else text
    cves = list(dict.fromkeys(find_cves(title) + find_cves(body)))
    modified = meta.get("dateModified")
    res = CollectResult()
    res.items.append(
        ItemOut(
            external_id=ctx_id,
            url=url,
            title=title,
            content=body,
            published_at=parse_date(meta.get("datePublished")),
            raw={"jsonld": meta, "ctx": ctx_id},
            cve_ids=cves,
        )
    )
    fixes = []
    for li in soup.find_all("li"):
        line = " ".join(li.get_text(" ").split())
        if re.search(r"\bBEFORE\b", line) and len(line) < 200:
            fs = parse_fix_statement(line)
            if fs:
                fixes.append(fs)
    affected = [{"vendor": "Citrix", "product": f.product_text, "text": f.source_text, "fix": f.to_dict(), "source_url": url} for f in fixes]
    fixed = [{"product": f.product_text, "branch": f.branch, "fixed": f.fixed, "source_url": url} for f in fixes]
    mitig = []
    for heading in ("What Customers Should Do", "Mitigating Factors", "Mitigation", "Workaround"):
        sec = _section(body, heading)
        if sec:
            mitig.append({"text": f"{heading}: {sec[:800]}", "source_url": url})
    for cve in cves:
        res.patches.append(
            VulnPatch(
                cve_id=cve,
                source_url=url,
                precedence=1,
                fields={"vendor": "Citrix", "patch_available": True if fixed else None},
                merge_lists={
                    "affected": affected,
                    "fixed_versions": fixed,
                    "mitigations": mitig,
                    "references": [{"url": url, "source": "citrix", "tags": ["Vendor Advisory"], "title": title}],
                },
            )
        )
    res.evidence += evidence_from_text(
        body, settings=settings, role="vendor", url=url, doc_cves=cves, item_external_id=ctx_id, mention_kind="vendor_advisory"
    )
    res.snapshots.append(
        SnapshotOut(
            advisory_id=ctx_id,
            url=url,
            normalized_text=body,
            revision_label=f"dateModified={modified}" if modified else None,
            cve_ids=cves,
            affected=[f.source_text for f in fixes],
        )
    )
    return res


@register
class CitrixBulletinCollector(Collector):
    type = "citrix_bulletins"

    def collect(self) -> CollectResult:
        follow_days = int(self.ctx.config.get("follow_days", 60))
        tracked: dict = dict(self.ctx.state.get("tracked", {}))  # CTX id -> first seen ISO date
        now = utcnow()
        for cid in bulletin_ids(list(self.ctx.config.get("watch", [])) + self.ctx.known_urls):
            tracked.setdefault(cid, now.isoformat())
        res = CollectResult()
        for cid, first_seen in sorted(tracked.items()):
            if (now - parse_date(first_seen)).days > follow_days and cid not in self.ctx.config.get("watch", []):
                continue
            url = ARTICLE_URL.format(num=cid[3:])
            try:
                r = self.http.get(url, check_robots=True, min_interval=3.0)
                part = parse_citrix_bulletin(r.text, cid, url, self.settings)
            except Exception as exc:  # isolate each bulletin
                res.notes.append(f"{cid}: {type(exc).__name__}: {exc}"[:300])
                continue
            for field_name in ("items", "patches", "evidence", "snapshots"):
                getattr(res, field_name).extend(getattr(part, field_name))
        res.new_state = {"tracked": tracked}
        res.notes.append(f"{len(res.items)} bulletin(s) suivis")
        return res
