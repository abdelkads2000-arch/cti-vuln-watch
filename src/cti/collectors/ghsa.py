"""GitHub global security advisories (REST /advisories).

Note: the REST endpoint exposes the same global advisory database as the GraphQL
API and works with or without token (60 req/h anonymous, 5000 req/h with token);
it is simpler to paginate by modification date.
"""

from __future__ import annotations

from datetime import timedelta

from cti.collectors.base import CollectResult, Collector, ItemOut, VulnPatch, register
from cti.collectors.common import parse_date, utcnow

MAX_PAGES = 10


def parse_ghsa_list(advisories: list[dict]) -> CollectResult:
    res = CollectResult()
    for a in advisories:
        cve = (a.get("cve_id") or "").upper()
        url = a.get("html_url")
        res.items.append(
            ItemOut(
                external_id=a["ghsa_id"],
                url=url,
                title=a.get("summary"),
                content=a.get("description"),
                published_at=parse_date(a.get("published_at")),
                raw=a,
                cve_ids=[cve] if cve else [],
                links=list(a.get("references") or []),
            )
        )
        if not cve or a.get("withdrawn_at"):
            continue
        affected, fixed = [], []
        for v in a.get("vulnerabilities") or []:
            pkg = v.get("package") or {}
            name = f"{pkg.get('ecosystem')}:{pkg.get('name')}"
            affected.append(
                {
                    "vendor": pkg.get("ecosystem"),
                    "product": pkg.get("name"),
                    "range": v.get("vulnerable_version_range"),
                    "less_than": v.get("first_patched_version"),
                    "text": f"{name} {v.get('vulnerable_version_range')}",
                    "source_url": url,
                }
            )
            if v.get("first_patched_version"):
                fixed.append({"product": name, "fixed": v["first_patched_version"], "source_url": url})
        cvss = (a.get("cvss_severities") or {}) or {}
        v3 = cvss.get("cvss_v3") or a.get("cvss") or {}
        v4 = cvss.get("cvss_v4") or {}
        res.patches.append(
            VulnPatch(
                cve_id=cve,
                source_url=url,
                precedence=3,
                fields={
                    "description_en": a.get("description"),
                    "cvss31_score": v3.get("score"),
                    "cvss31_vector": v3.get("vector_string"),
                    "cvss40_score": v4.get("score"),
                    "cvss40_vector": v4.get("vector_string"),
                    "patch_available": True if fixed else None,
                },
                merge_lists={"affected": affected, "fixed_versions": fixed},
            )
        )
    return res


@register
class GhsaCollector(Collector):
    type = "ghsa"

    def collect(self) -> CollectResult:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if tok := self.settings.secret("github_token"):
            headers["Authorization"] = f"Bearer {tok}"
        now = utcnow()
        since = parse_date(self.ctx.state.get("since")) or now - timedelta(
            days=int(self.ctx.config.get("initial_lookback_days", 3))
        )
        params = {"updated": f">={since:%Y-%m-%dT%H:%M:%SZ}", "per_page": 100, "sort": "updated", "direction": "asc"}
        url: str | None = self.ctx.url
        res = CollectResult()
        for _ in range(MAX_PAGES):
            r = self.http.get(url, params=params, headers=headers)
            page = parse_ghsa_list(r.json())
            res.items += page.items
            res.patches += page.patches
            nxt = r.headers.get("link", "")
            url = next((p.split(";")[0].strip(" <>") for p in nxt.split(",") if 'rel="next"' in p), None)
            params = None  # the "next" link already carries the query
            if not url:
                break
        res.new_state = {"since": now.isoformat()}
        return res
