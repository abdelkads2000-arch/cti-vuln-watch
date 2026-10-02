"""Fortinet PSIRT: RSS of advisories + per-advisory CVRF XML (structured: CVE, products, revisions)."""

from __future__ import annotations

import re

import feedparser
from lxml import etree

from cti.collectors.base import CollectResult, Collector, ItemOut, SnapshotOut, VulnPatch, register
from cti.collectors.common import evidence_from_text, parse_date
from cti.extraction.text import content_hash, find_cves, html_to_text
from cti.settings import Settings

CVRF_URL = "https://www.fortiguard.com/psirt/cvrf/{id}"
_ID_RE = re.compile(r"FG-IR-\d{2}-\d{3,5}")


def _local(root, name: str):
    return root.xpath(f".//*[local-name()='{name}']")


def _text(el) -> str:
    return " ".join("".join(el.itertext()).split()) if el is not None else ""


def parse_cvrf(xml: bytes, advisory_url: str, settings: Settings) -> CollectResult:
    parser = etree.XMLParser(recover=True, resolve_entities=False, no_network=True)
    root = etree.fromstring(xml, parser)
    adv_id = _text(next(iter(_local(root, "ID")), None))
    title = _text(next(iter(_local(root, "DocumentTitle")), None))
    notes = {n.get("Title"): _text(n) for n in _local(root, "Note")}
    revisions = [
        (_text(next(iter(_local(r, "Number")), None)), _text(next(iter(_local(r, "Date")), None)), _text(next(iter(_local(r, "Description")), None)))
        for r in _local(root, "Revision")
    ]
    products = [_text(p) for p in _local(root, "FullProductName")]
    cves, score, vector = [], None, None
    for v in _local(root, "Vulnerability"):
        cves += [_text(c).upper() for c in _local(v, "CVE") if _text(c)]
        s = next(iter(_local(v, "BaseScoreV3")), None)
        if s is not None and score is None:
            try:
                score = float(_text(s))
            except ValueError:
                pass
            vector = _text(next(iter(_local(v, "VectorV3")), None)) or None
    text = "\n\n".join(x for x in [title] + [f"{k}: {v}" for k, v in notes.items() if v and v != "None"] if x)
    cves = list(dict.fromkeys(cves + find_cves(text)))
    res = CollectResult()
    res.items.append(
        ItemOut(
            external_id=adv_id or advisory_url,
            url=advisory_url,
            title=title,
            content=text,
            published_at=parse_date(revisions[0][1]) if revisions else None,
            raw={"cvrf_id": adv_id, "notes": notes, "revisions": revisions, "products": products},
            cve_ids=cves,
        )
    )
    affected = [{"vendor": "Fortinet", "product": p, "text": p, "source_url": advisory_url} for p in products]
    for cve in cves:
        res.patches.append(
            VulnPatch(
                cve_id=cve,
                source_url=advisory_url,
                precedence=1,
                fields={"vendor": "Fortinet", "title": title, "cvss31_score": score, "cvss31_vector": vector},
                merge_lists={
                    "affected": affected,
                    "references": [{"url": advisory_url, "source": "fortinet", "tags": ["Vendor Advisory"]}],
                },
            )
        )
    res.evidence += evidence_from_text(
        text, settings=settings, role="vendor", url=advisory_url, doc_cves=cves, item_external_id=adv_id, mention_kind="vendor_advisory"
    )
    last = revisions[-1] if revisions else None
    res.snapshots.append(
        SnapshotOut(
            advisory_id=adv_id or advisory_url,
            url=advisory_url,
            normalized_text=text + "\n\nProducts: " + ", ".join(products),
            revision_label=f"rev {last[0]} {last[1][:10]}: {last[2]}" if last else None,
            cve_ids=cves,
            affected=products,
        )
    )
    return res


@register
class FortinetPsirtCollector(Collector):
    type = "fortinet_psirt"

    def collect(self) -> CollectResult:
        r = self.http.get(self.ctx.url, conditional=True)
        if r.not_modified:
            return CollectResult(not_modified=True)
        feed = feedparser.parse(r.content)
        seen: dict = dict(self.ctx.state.get("entries", {}))
        res = CollectResult()
        for e in feed.entries:
            link = e.get("link", "")
            m = _ID_RE.search(link)
            if not m:
                continue
            # The RSS description carries "Revised on ..." so any revision changes the hash.
            h = content_hash(e.get("title"), e.get("summary"))
            if seen.get(m.group(0)) == h:
                continue
            try:
                xml = self.http.get(CVRF_URL.format(id=m.group(0))).content
                part = parse_cvrf(xml, link, self.settings)
            except Exception as exc:  # CVRF missing: fall back to the RSS text only
                summary = html_to_text(e.get("summary", ""))
                part = CollectResult(
                    items=[ItemOut(m.group(0), link, e.get("title"), summary, parse_date(e.get("published")), {"rss": dict(e)}, find_cves(summary))],
                    notes=[f"CVRF indisponible pour {m.group(0)}: {exc}"],
                )
            for field_name in ("items", "patches", "evidence", "snapshots", "notes"):
                getattr(res, field_name).extend(getattr(part, field_name))
            seen[m.group(0)] = h
        res.new_state = {"entries": seen}
        return res
