"""FIRST EPSS API: scores for the CVEs we track (scope provided by the pipeline)."""

from __future__ import annotations

from cti.collectors.base import CollectResult, Collector, VulnPatch, register

BATCH = 100
EPSS_ENTRY = "https://api.first.org/data/v1/epss?cve={cve}"


def parse_epss(data: dict) -> list[VulnPatch]:
    out = []
    for row in data.get("data", []):
        cve = row["cve"].upper()
        out.append(
            VulnPatch(
                cve_id=cve,
                source_url=EPSS_ENTRY.format(cve=cve),
                precedence=1,
                create=False,
                fields={
                    "epss": float(row["epss"]),
                    "epss_percentile": float(row["percentile"]),
                    "epss_date": row.get("date"),
                },
            )
        )
    return out


@register
class EpssCollector(Collector):
    type = "epss"

    def collect(self) -> CollectResult:
        res = CollectResult()
        scope = sorted(set(self.ctx.cve_scope))
        for i in range(0, len(scope), BATCH):
            chunk = scope[i : i + BATCH]
            data = self.http.get(self.ctx.url, params={"cve": ",".join(chunk)}).json()
            # EPSS patches only update existing vulnerabilities (never create them).
            res.patches += parse_epss(data)
        res.notes.append(f"{len(res.patches)} scores EPSS / {len(scope)} CVE demandées")
        return res
