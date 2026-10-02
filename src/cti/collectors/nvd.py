"""NVD API 2.0: incremental by lastModified window + targeted lookups for CVEs cited elsewhere."""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlsplit

from cti.collectors.base import CollectResult, Collector, EvidenceOut, ItemOut, VulnPatch, register
from cti.collectors.common import parse_date, utcnow

NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/{cve}"
KEV_ENTRY_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve}"
REFERENCE_POC_DOMAINS = {"www.exploit-db.com": "poc_exploitdb", "exploit-db.com": "poc_exploitdb"}
PAGE_SIZE = 2000
MAX_TARGETED_PER_RUN = 25


def _pick_metric(metrics: list[dict]) -> dict | None:
    if not metrics:
        return None
    primary = [m for m in metrics if m.get("type") == "Primary"]
    return (primary or metrics)[0]


def _cpe_entries(cve: dict) -> list[dict]:
    out = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = m["criteria"].split(":")
                out.append(
                    {
                        "criteria": m["criteria"],
                        "vendor_product": f"{parts[3]}:{parts[4]}" if len(parts) > 4 else m["criteria"],
                        "update": parts[6] if len(parts) > 6 else "*",
                        **{
                            k: m[k]
                            for k in (
                                "versionStartIncluding",
                                "versionStartExcluding",
                                "versionEndIncluding",
                                "versionEndExcluding",
                            )
                            if k in m
                        },
                    }
                )
    return out


def affected_from_cve5_style(entries: list[dict], source_url: str) -> list[dict]:
    """CVE 5.x 'affected' blocks (also exposed by NVD as affectedData) -> normalized list."""
    out = []
    for a in entries:
        for v in a.get("versions", []) or []:
            if v.get("status") != "affected":
                continue
            fixed = v.get("lessThan")
            text = f"{a.get('vendor', '')} {a.get('product', '')} " + (
                f"< {fixed}" if fixed else f"= {v.get('version')}" if v.get("version") else ""
            )
            out.append(
                {
                    "vendor": a.get("vendor"),
                    "product": a.get("product"),
                    "version": v.get("version"),
                    "less_than": fixed,
                    "less_than_or_equal": v.get("lessThanOrEqual"),
                    "text": " ".join(text.split()),
                    "source_url": source_url,
                }
            )
    return out


def parse_nvd_cve(cve: dict) -> tuple[ItemOut, VulnPatch, list[EvidenceOut]]:
    cve_id = cve["id"].upper()
    url = NVD_DETAIL.format(cve=cve_id)
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    metrics = cve.get("metrics", {})
    m31 = _pick_metric(metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []))
    m40 = _pick_metric(metrics.get("cvssMetricV40", []))
    cpes = _cpe_entries(cve)
    affected = []
    for block in cve.get("affected", []) or []:
        affected += affected_from_cve5_style(block.get("affectedData", []), url)

    fields = {
        "description_en": desc,
        "published_at": parse_date(cve.get("published")),
        "cvss31_score": m31["cvssData"]["baseScore"] if m31 else None,
        "cvss31_vector": m31["cvssData"]["vectorString"] if m31 else None,
        "cvss40_score": m40["cvssData"]["baseScore"] if m40 else None,
        "cvss40_vector": m40["cvssData"]["vectorString"] if m40 else None,
    }
    if cve.get("cisaExploitAdd"):
        fields.update(kev=True, kev_added=cve["cisaExploitAdd"], title=cve.get("cisaVulnerabilityName"))
    patch = VulnPatch(
        cve_id=cve_id,
        source_url=url,
        precedence=2,
        fields=fields,
        merge_lists={
            "cpes": cpes,
            "affected": affected,
            "references": [{"url": r["url"], "tags": r.get("tags", []), "source": "nvd"} for r in cve.get("references", [])],
        },
    )

    evidence: list[EvidenceOut] = []
    if cve.get("cisaExploitAdd"):
        evidence.append(
            EvidenceOut(
                cve_id,
                "kev_listed",
                KEV_ENTRY_URL.format(cve=cve_id),
                quote=f"cisaExploitAdd={cve['cisaExploitAdd']} (NVD)",
                extracted_by="structured",
                details={"via": "nvd"},
                item_external_id=cve_id,
            )
        )
    for ssvc in metrics.get("ssvcV203", []) or []:
        opts = {k.lower(): v for o in ssvc.get("ssvcData", {}).get("options", []) for k, v in o.items()}
        expl = (opts.get("exploitation") or "").lower()
        if expl in ("active", "poc"):
            evidence.append(
                EvidenceOut(
                    cve_id,
                    "cisa_ssvc_active" if expl == "active" else "cisa_ssvc_poc",
                    url,
                    quote=f"CISA SSVC Exploitation={expl}",
                    extracted_by="structured",
                    details={"role": ssvc.get("ssvcData", {}).get("role")},
                    item_external_id=cve_id,
                )
            )
    for r in cve.get("references", []):
        if "Exploit" not in (r.get("tags") or []):
            continue
        host = urlsplit(r["url"]).netloc.lower()
        kind = REFERENCE_POC_DOMAINS.get(host)
        if kind is None:
            kind = "poc_github" if host == "github.com" else "poc_reference"
        evidence.append(
            EvidenceOut(
                cve_id,
                kind,
                r["url"],
                quote="NVD reference tagged 'Exploit'",
                extracted_by="structured",
                details={"via": "nvd_reference", "tags": r.get("tags")},
                item_external_id=cve_id,
            )
        )
    item = ItemOut(
        external_id=cve_id,
        url=url,
        title=cve.get("cisaVulnerabilityName"),
        content=desc,
        published_at=parse_date(cve.get("published")),
        raw=cve,
        cve_ids=[cve_id],
        links=[r["url"] for r in cve.get("references", [])],
    )
    return item, patch, evidence


def parse_nvd_page(data: dict) -> CollectResult:
    res = CollectResult()
    for v in data.get("vulnerabilities", []):
        item, patch, ev = parse_nvd_cve(v["cve"])
        res.items.append(item)
        res.patches.append(patch)
        res.evidence += ev
    return res


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


@register
class NvdCollector(Collector):
    type = "nvd"

    def _headers(self) -> dict:
        key = self.settings.secret("nvd_api_key")
        return {"apiKey": key} if key else {}

    @property
    def _interval(self) -> float:
        # Public limits: 5 req / 30 s without key, 50 req / 30 s with key.
        return 0.8 if self.settings.secret("nvd_api_key") else 6.5

    def collect(self) -> CollectResult:
        res = CollectResult()
        end = utcnow()
        last = parse_date(self.ctx.state.get("last_mod_end"))
        start = last or end - timedelta(days=int(self.ctx.config.get("initial_lookback_days", 3)))
        start = max(start - timedelta(minutes=5), end - timedelta(days=119))  # API max window: 120 days
        index = 0
        while True:
            r = self.http.get(
                self.ctx.url,
                params={
                    "lastModStartDate": _iso(start),
                    "lastModEndDate": _iso(end),
                    "resultsPerPage": PAGE_SIZE,
                    "startIndex": index,
                },
                headers=self._headers(),
                min_interval=self._interval,
            )
            data = r.json()
            page = parse_nvd_page(data)
            res.items += page.items
            res.patches += page.patches
            res.evidence += page.evidence
            index += data.get("resultsPerPage", 0)
            if index >= data.get("totalResults", 0) or not data.get("resultsPerPage"):
                break
        # Targeted lookups: CVEs referenced by other sources but still unknown to us.
        done = {i.external_id for i in res.items}
        for cve in [c for c in self.ctx.cve_scope if c not in done][:MAX_TARGETED_PER_RUN]:
            r = self.http.get(self.ctx.url, params={"cveId": cve}, headers=self._headers(), min_interval=self._interval)
            page = parse_nvd_page(r.json())
            res.items += page.items
            res.patches += page.patches
            res.evidence += page.evidence
        res.new_state = {"last_mod_end": end.isoformat()}
        res.notes.append(f"fenêtre {start:%Y-%m-%d %H:%M} -> {end:%Y-%m-%d %H:%M}, {len(res.items)} CVE")
        return res
