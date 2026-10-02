"""CVEProject/cvelistV5: hourly 'delta' release assets (zip of CVE JSON 5 records).

We never clone the repository (several GB): we read the release metadata through the
GitHub API, then download only the small delta zip and parse the JSON records in
memory. These are data files (CVE records), not code.
"""

from __future__ import annotations

import io
import json
import zipfile

from cti.collectors.base import CollectResult, Collector, EvidenceOut, ItemOut, VulnPatch, register
from cti.collectors.common import parse_date
from cti.collectors.nvd import affected_from_cve5_style

CVE_ORG = "https://www.cve.org/CVERecord?id={cve}"
MAX_RELEASES_PER_RUN = 24


def parse_cve5(record: dict) -> tuple[ItemOut, VulnPatch, list[EvidenceOut]] | None:
    meta = record.get("cveMetadata", {})
    if meta.get("state") != "PUBLISHED":
        return None
    cve_id = meta["cveId"].upper()
    url = CVE_ORG.format(cve=cve_id)
    cna = record.get("containers", {}).get("cna", {})
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), None)
    fields: dict = {"description_en": desc, "published_at": parse_date(meta.get("datePublished"))}
    for m in cna.get("metrics", []) or []:
        if "cvssV4_0" in m and fields.get("cvss40_score") is None:
            fields["cvss40_score"] = m["cvssV4_0"].get("baseScore")
            fields["cvss40_vector"] = m["cvssV4_0"].get("vectorString")
        for key in ("cvssV3_1", "cvssV3_0"):
            if key in m and fields.get("cvss31_score") is None:
                fields["cvss31_score"] = m[key].get("baseScore")
                fields["cvss31_vector"] = m[key].get("vectorString")
    affected_blocks = cna.get("affected", []) or []
    if affected_blocks:
        fields["vendor"] = affected_blocks[0].get("vendor")
        fields["product"] = affected_blocks[0].get("product")
    patch = VulnPatch(
        cve_id=cve_id,
        source_url=url,
        precedence=1,  # CNA = usually the vendor itself
        fields=fields,
        merge_lists={
            "affected": affected_from_cve5_style(affected_blocks, url),
            "references": [{"url": r["url"], "tags": r.get("tags", []), "source": "cna"} for r in cna.get("references", [])],
        },
    )
    evidence: list[EvidenceOut] = []
    for adp in record.get("containers", {}).get("adp", []) or []:
        for m in adp.get("metrics", []) or []:
            other = m.get("other", {})
            if other.get("type") != "ssvc":
                continue
            opts = {k.lower(): v for o in other.get("content", {}).get("options", []) for k, v in o.items()}
            expl = (opts.get("exploitation") or "").lower()
            if expl in ("active", "poc"):
                evidence.append(
                    EvidenceOut(
                        cve_id,
                        "cisa_ssvc_active" if expl == "active" else "cisa_ssvc_poc",
                        url,
                        quote=f"CISA-ADP SSVC Exploitation={expl}",
                        extracted_by="structured",
                        details={"adp": adp.get("providerMetadata", {}).get("shortName")},
                        item_external_id=cve_id,
                    )
                )
    item = ItemOut(
        external_id=cve_id,
        url=url,
        title=cna.get("title"),
        content=desc,
        published_at=parse_date(meta.get("datePublished")),
        raw=record,
        cve_ids=[cve_id],
        links=[r["url"] for r in cna.get("references", [])],
    )
    return item, patch, evidence


def parse_delta_zip(blob: bytes) -> CollectResult:
    res = CollectResult()
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json") or name.endswith("delta.json") or name.endswith("deltaLog.json"):
                continue
            info = zf.getinfo(name)
            if info.file_size > 5 * 1024 * 1024:  # a CVE record is a few KB; refuse anomalies
                continue
            try:
                record = json.loads(zf.read(name))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            parsed = parse_cve5(record)
            if parsed:
                item, patch, ev = parsed
                res.items.append(item)
                res.patches.append(patch)
                res.evidence += ev
    return res


@register
class CvelistCollector(Collector):
    type = "cvelist"

    def _gh_headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if tok := self.settings.secret("github_token"):
            h["Authorization"] = f"Bearer {tok}"
        return h

    def collect(self) -> CollectResult:
        releases_url = self.ctx.url.replace("/releases/latest", "/releases")
        releases = self.http.get(releases_url, params={"per_page": 30}, headers=self._gh_headers()).json()
        last_tag = self.ctx.state.get("last_tag")
        new = []
        for rel in releases:  # newest first
            if rel["tag_name"] == last_tag:
                break
            new.append(rel)
        if not new:
            return CollectResult(not_modified=True)
        if last_tag is None:
            new = new[:1]  # first run: only the latest delta, NVD covers the lookback
        new = list(reversed(new[:MAX_RELEASES_PER_RUN]))
        res = CollectResult()
        for rel in new:
            asset = next((a for a in rel.get("assets", []) if "_delta_CVEs_" in a["name"] and a["name"].endswith(".zip")), None)
            if not asset or asset.get("size", 0) > 50 * 1024 * 1024:
                continue
            blob = self.http.get(asset["browser_download_url"]).content
            part = parse_delta_zip(blob)
            res.items += part.items
            res.patches += part.patches
            res.evidence += part.evidence
        res.new_state = {"last_tag": new[-1]["tag_name"]}
        res.notes.append(f"{len(new)} release(s) delta, {len(res.items)} CVE")
        return res
