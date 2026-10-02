"""Channel-independent alert message (title, why, clients, action, evidence, sources) in FR/EN."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

LEVEL_LABEL = {
    "fr": {
        "EXPLOITED_CONFIRMED": "Exploitation CONFIRMÉE",
        "EXPLOITED_REPORTED": "Exploitation RAPPORTÉE (non confirmée par l'éditeur)",
        "POC_PUBLIC_VERIFIED": "PoC public vérifié",
        "POC_CLAIMED": "PoC revendiqué (non vérifié)",
        "POC_SUSPICIOUS": "PoC suspect (possible piège)",
        "NO_KNOWN_EXPLOIT": "Aucune exploitation connue",
    },
    "en": {
        "EXPLOITED_CONFIRMED": "Exploitation CONFIRMED",
        "EXPLOITED_REPORTED": "Exploitation REPORTED (not confirmed by vendor)",
        "POC_PUBLIC_VERIFIED": "Verified public PoC",
        "POC_CLAIMED": "Claimed PoC (unverified)",
        "POC_SUSPICIOUS": "Suspicious PoC (possible trap)",
        "NO_KNOWN_EXPLOIT": "No known exploitation",
    },
}

T = {
    "fr": {
        "why": "Pourquoi c'est important",
        "clients": "Clients concernés",
        "none": "Aucun client concerné dans l'inventaire",
        "action": "Action recommandée",
        "evidence": "Niveau de preuve",
        "confidence": "confiance",
        "sources": "Sources",
        "changes": "Motif de la notification",
        "conflict": "⚠ Sources contradictoires",
        "sla": "Délai",
        "exposed": "exposé internet",
        "internal": "interne",
        "affected": "VULNÉRABLE",
        "unknown": "version à confirmer",
        "patch": "Appliquer le correctif : {v}",
        "patch_unknown": "Vérifier la disponibilité d'un correctif auprès de l'éditeur",
        "mitigate": "Mitigation éditeur : {m}",
        "hunt": "Rechercher des traces de compromission (exploitation active) : IoC éditeur / CERT, journaux des équipements exposés",
        "kev": "Présente dans le catalogue CISA KEV (ajout {d})",
        "cvss": "CVSS {s}",
        "epss": "EPSS {e:.1%} (percentile {p:.0%})",
        "summary_missing": "(résumé FR indisponible — description éditeur ci-dessous)",
        "exploits": "Exploitation / PoC : sources",
        "not_counted": "source en observation, non comptée",
    },
    "en": {
        "why": "Why it matters",
        "clients": "Affected clients",
        "none": "No client affected in the inventory",
        "action": "Recommended action",
        "evidence": "Evidence level",
        "confidence": "confidence",
        "sources": "Sources",
        "changes": "Notification reason",
        "conflict": "⚠ Conflicting sources",
        "sla": "Target",
        "exposed": "internet-facing",
        "internal": "internal",
        "affected": "VULNERABLE",
        "unknown": "version to confirm",
        "patch": "Apply the fix: {v}",
        "patch_unknown": "Check fix availability with the vendor",
        "mitigate": "Vendor mitigation: {m}",
        "hunt": "Hunt for compromise (active exploitation): vendor / CERT IoCs, logs of exposed devices",
        "kev": "Listed in CISA KEV (added {d})",
        "cvss": "CVSS {s}",
        "epss": "EPSS {e:.1%} (percentile {p:.0%})",
        "summary_missing": "",
        "exploits": "Exploitation / PoC: sources",
        "not_counted": "source under observation, not counted",
    },
}


@dataclass
class AlertMessage:
    cve_id: str
    priority: str
    lang: str
    title: str
    summary: str
    why: list[str]
    clients: list[str]
    actions: list[str]
    evidence: str
    conflicts: list[str]
    sources: list[dict]  # {label, url}
    changes: list[str]
    sla: str | None = None
    # Sources asserting exploitation or a PoC: {label, url, quote, counted}
    exploit_sources: list[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_text(self) -> str:
        t = T[self.lang]
        lines = [f"[{self.priority}] {self.title}", self.summary, "", f"{t['why']}:"]
        lines += [f"  - {w}" for w in self.why]
        lines += [f"{t['clients']}:"] + ([f"  - {c}" for c in self.clients] or [f"  - {t['none']}"])
        lines += [f"{t['action']}:"] + [f"  - {a}" for a in self.actions]
        lines += [f"{t['evidence']}: {self.evidence}"]
        if self.exploit_sources:
            lines += [f"{t['exploits']}:"] + [f"  - {line}" for line in exploit_lines(self.exploit_sources, self.lang)]
        lines += [f"{t['conflict']}: {c}" for c in self.conflicts]
        lines += [f"{t['changes']}: {', '.join(self.changes)}", f"{t['sources']}:"]
        lines += [f"  - {s['label']}: {s['url']}" for s in self.sources]
        return "\n".join(lines)


def exploit_lines(items: list[dict], lang: str) -> list[str]:
    t = T[lang]
    out = []
    for e in items:
        note = "" if e.get("counted", True) else f" ({t['not_counted']})"
        quote = f" «{e['quote'][:160]}»" if e.get("quote") else ""
        out.append(f"{e['label']}{note}{quote} — {e['url']}")
    return out


def build_message(ctx: dict, lang: str) -> AlertMessage:
    """ctx is produced by the pipeline (vulnerability + score + matches + decision)."""
    t = T[lang]
    v = ctx["vuln"]
    level_label = LEVEL_LABEL[lang][ctx["level"]]
    product = " ".join(x for x in (v.get("vendor"), v.get("product")) if x) or "?"
    title = f"{ctx['cve_id']} — {product} — {level_label}"

    summary = v.get("summary_fr") if lang == "fr" and v.get("summary_fr") else None
    if summary is None:
        desc = (v.get("description_en") or "").strip()
        summary = (t["summary_missing"] + "\n" if lang == "fr" and t["summary_missing"] else "") + desc[:500]

    why = [level_label + (f" — {ctx['level_quote']}" if ctx.get("level_quote") else "")]
    if v.get("kev"):
        why.append(t["kev"].format(d=v.get("kev_added") or "?"))
    cvss = v.get("cvss40_score") or v.get("cvss31_score")
    if cvss is not None:
        why.append(t["cvss"].format(s=cvss))
    if v.get("epss") is not None:
        why.append(t["epss"].format(e=v["epss"], p=v.get("epss_percentile") or 0))
    why += ctx.get("decision_reasons", [])

    clients = []
    for m in ctx.get("matches", []):
        if m["version_status"] == "not_affected":
            continue
        status = t["affected"] if m["version_status"] == "affected" else t["unknown"]
        expo = t["exposed"] if m["internet_exposed"] else t["internal"]
        clients.append(f"{m['client_name']} — {m['asset_label']} — {status} ({expo}) — {m['detail']}")

    actions = []
    fixed = sorted({f["fixed"] for f in v.get("fixed_versions", []) if f.get("fixed")})
    actions.append(t["patch"].format(v=", ".join(fixed)) if fixed else t["patch_unknown"])
    for mit in (v.get("mitigations") or [])[:2]:
        actions.append(t["mitigate"].format(m=mit["text"][:300]))
    if ctx["level"].startswith("EXPLOITED"):
        actions.append(t["hunt"])

    evidence = f"{level_label} — {t['confidence']} {ctx['confidence']}/100"
    sources = []
    seen = set()
    for s in ctx.get("sources", []):
        if s["url"] not in seen:
            seen.add(s["url"])
            sources.append(s)
    return AlertMessage(
        cve_id=ctx["cve_id"],
        priority=ctx["priority"],
        lang=lang,
        title=title,
        summary=summary,
        why=why,
        clients=clients,
        actions=actions,
        evidence=evidence,
        conflicts=ctx.get("conflicts", []),
        sources=sources[:12],
        changes=ctx.get("changes", []),
        sla=ctx.get("sla"),
        exploit_sources=ctx.get("exploit_sources", []),
    )
