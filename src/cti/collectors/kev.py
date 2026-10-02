"""CISA Known Exploited Vulnerabilities catalog (JSON feed)."""

from __future__ import annotations

import json
import re

from cti.collectors.base import CollectResult, Collector, EvidenceOut, ItemOut, VulnPatch, register
from cti.collectors.common import parse_date
from cti.extraction.text import content_hash

KEV_ENTRY_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve}"
_URL_RE = re.compile(r"https?://[^\s;]+")


def parse_kev(data: dict) -> CollectResult:
    res = CollectResult()
    for v in data.get("vulnerabilities", []):
        cve = v["cveID"].upper()
        url = KEV_ENTRY_URL.format(cve=cve)
        res.items.append(
            ItemOut(
                external_id=cve,
                url=url,
                title=v.get("vulnerabilityName"),
                content=v.get("shortDescription"),
                published_at=parse_date(v.get("dateAdded")),
                raw=v,
                cve_ids=[cve],
                links=_URL_RE.findall(v.get("notes") or ""),
            )
        )
        res.patches.append(
            VulnPatch(
                cve_id=cve,
                source_url=url,
                precedence=3,
                fields={
                    "kev": True,
                    "kev_added": v.get("dateAdded"),
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "title": v.get("vulnerabilityName"),
                },
                merge_lists={
                    "references": [{"url": u, "source": "cisa-kev"} for u in _URL_RE.findall(v.get("notes") or "")],
                    "mitigations": [{"text": v["requiredAction"], "source_url": url}] if v.get("requiredAction") else [],
                },
            )
        )
        res.evidence.append(
            EvidenceOut(
                cve_id=cve,
                kind="kev_listed",
                url=url,
                quote=f"Added to CISA KEV on {v.get('dateAdded')}",
                extracted_by="structured",
                details={
                    "date_added": v.get("dateAdded"),
                    "due_date": v.get("dueDate"),
                    "ransomware": v.get("knownRansomwareCampaignUse"),
                },
                item_external_id=cve,
            )
        )
    res.notes.append(f"catalogue v{data.get('catalogVersion')} ({data.get('count')} entrées)")
    return res


@register
class KevCollector(Collector):
    type = "kev"

    def collect(self) -> CollectResult:
        r = self.http.get(self.ctx.url, conditional=True)
        if r.not_modified:
            return CollectResult(not_modified=True)
        data = r.json()
        res = parse_kev(data)
        # Only process entries whose content changed since last run (the catalog is a full dump).
        seen: dict = dict(self.ctx.state.get("hashes", {}))
        changed: set[str] = set()
        for it in res.items:
            h = content_hash(json.dumps(it.raw, sort_keys=True))
            if seen.get(it.external_id) != h:
                changed.add(it.external_id)
                seen[it.external_id] = h
        res.items = [i for i in res.items if i.external_id in changed]
        res.patches = [p for p in res.patches if p.cve_id in changed]
        res.evidence = [e for e in res.evidence if e.cve_id in changed]
        res.new_state = {"hashes": seen, "catalog_version": data.get("catalogVersion")}
        return res
