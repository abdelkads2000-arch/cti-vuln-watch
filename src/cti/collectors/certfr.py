"""CERT-FR: RSS feed (avis / alertes) + structured JSON export of each document (/json/).

The JSON export gives the CVE list, affected systems, and the revision history,
which is what we use to detect bulletin updates ("[MàJ]").
"""

from __future__ import annotations

import json

import feedparser

from cti.collectors.base import CollectResult, Collector, ItemOut, SnapshotOut, VulnPatch, register
from cti.collectors.common import evidence_from_text, parse_date
from cti.extraction.text import content_hash, find_cves
from cti.matching.versions import parse_fix_statement
from cti.settings import Settings

BASE = "https://www.cert.ssi.gouv.fr"


def document_text(doc: dict) -> str:
    parts = [doc.get("title") or "", doc.get("summary") or ""]
    parts += [f"- {a.get('description')}" for a in doc.get("affected_systems", [])]
    parts.append(doc.get("content") or "")
    return "\n\n".join(p for p in parts if p)


def parse_certfr_document(doc: dict, url: str, settings: Settings, role: str = "cert") -> CollectResult:
    res = CollectResult()
    ref = doc.get("reference") or url
    cves = [c["name"].upper() for c in doc.get("cves", []) if c.get("name")]
    text = document_text(doc)
    cves = list(dict.fromkeys(cves + find_cves(text)))
    revisions = doc.get("revisions") or []
    rev_label = f"{len(revisions)}: {revisions[-1].get('description', '').strip()} ({revisions[-1].get('revision_date', '')[:10]})" if revisions else None
    vendor_links = [v["url"] for v in doc.get("vendor_advisories", []) if v.get("url")]
    other_links = [BASE + lk["url"] if lk.get("url", "").startswith("/") else lk.get("url") for lk in doc.get("links", [])]

    res.items.append(
        ItemOut(
            external_id=ref,
            url=url,
            title=doc.get("title"),
            content=text,
            published_at=parse_date(revisions[0]["revision_date"]) if revisions else None,
            raw=doc,
            cve_ids=cves,
            links=[u for u in vendor_links + other_links if u],
        )
    )
    affected, fixed = [], []
    for a in doc.get("affected_systems", []):
        desc = a.get("description") or ""
        prod = (a.get("product") or {}).get("name")
        vendor = ((a.get("product") or {}).get("vendor") or {}).get("name")
        fs = parse_fix_statement(desc)
        affected.append({"vendor": vendor, "product": prod, "text": desc, "fix": fs.to_dict() if fs else None, "source_url": url})
        if fs:
            fixed.append({"product": prod or fs.product_text, "branch": fs.branch, "fixed": fs.fixed, "source_url": url})
    for cve in cves:
        res.patches.append(
            VulnPatch(
                cve_id=cve,
                source_url=url,
                precedence=4,
                fields={"patch_available": True if fixed else None},
                merge_lists={
                    "affected": affected,
                    "fixed_versions": fixed,
                    "references": [{"url": url, "source": "cert-fr", "title": doc.get("title")}]
                    + [{"url": u, "source": "cert-fr", "tags": ["Vendor Advisory"]} for u in vendor_links],
                },
            )
        )
    res.evidence += evidence_from_text(
        text, settings=settings, role=role, url=url, doc_cves=cves, item_external_id=ref, mention_kind="cert_advisory"
    )
    res.snapshots.append(
        SnapshotOut(
            advisory_id=ref,
            url=url,
            normalized_text=json.dumps(
                {k: doc.get(k) for k in ("title", "summary", "affected_systems", "cves", "revisions", "content")},
                ensure_ascii=False,
                sort_keys=True,
                indent=1,
            ),
            revision_label=rev_label,
            cve_ids=cves,
            affected=[a["text"] for a in affected],
        )
    )
    return res


@register
class CertFrCollector(Collector):
    type = "certfr"

    def collect(self) -> CollectResult:
        r = self.http.get(self.ctx.url, conditional=True)
        if r.not_modified:
            return CollectResult(not_modified=True)
        feed = feedparser.parse(r.content)
        seen: dict = dict(self.ctx.state.get("entries", {}))
        res = CollectResult()
        for e in feed.entries:
            link = e.get("link")
            if not link:
                continue
            h = content_hash(e.get("title"), e.get("summary"))
            if seen.get(link) == h:
                continue  # unchanged entry: no need to refetch the document
            try:
                doc = self.http.get(link.rstrip("/") + "/json/").json()
                part = parse_certfr_document(doc, link, self.settings, role=self.ctx.role)
            except Exception as exc:  # one broken document must not fail the whole feed
                res.notes.append(f"{link}: {type(exc).__name__}: {exc}"[:300])
                continue  # not marked as seen: retried next run
            res.items += part.items
            res.patches += part.patches
            res.evidence += part.evidence
            res.snapshots += part.snapshots
            seen[link] = h
        # Keep state bounded to what is still in the feed.
        links_in_feed = {e.get("link") for e in feed.entries}
        res.new_state = {"entries": {k: v for k, v in seen.items() if k in links_in_feed}}
        return res
