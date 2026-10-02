"""Priority rules (config/priority.yaml) and deduplication fingerprint."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from cti.scoring.evidence import Level


@dataclass
class PriorityInput:
    cve_id: str
    level: Level
    weak_only: bool
    cvss: float | None
    epss: float | None
    client_match: bool
    client_exposed: bool
    in_watchlist: bool
    bypass_signal: bool


@dataclass
class PriorityDecision:
    priority: str | None  # P1 | P2 | P3 | None
    rule: str | None
    reasons: list[str] = field(default_factory=list)


@lru_cache(maxsize=4)
def load_rules(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def _eval(cond: dict, x: PriorityInput) -> bool:
    for key, want in cond.items():
        if key == "any_of":
            if not any(_eval(sub, x) for sub in want):
                return False
        elif key == "exploited":
            if (x.level >= Level.EXPLOITED_REPORTED) != bool(want):
                return False
        elif key == "exploited_confirmed":
            if (x.level == Level.EXPLOITED_CONFIRMED) != bool(want):
                return False
        elif key == "poc_public_verified":
            if (x.level >= Level.POC_PUBLIC_VERIFIED) != bool(want):
                return False
        elif key == "client_match":
            if x.client_match != bool(want):
                return False
        elif key == "client_exposed":
            if x.client_exposed != bool(want):
                return False
        elif key == "in_watchlist":
            if x.in_watchlist != bool(want):
                return False
        elif key == "bypass_signal":
            if x.bypass_signal != bool(want):
                return False
        elif key == "min_cvss":
            if x.cvss is None or x.cvss < float(want):
                return False
        elif key == "min_epss":
            if x.epss is None or x.epss < float(want):
                return False
        else:
            raise ValueError(f"condition de priorité inconnue: {key}")
    return True


def decide(x: PriorityInput, rules_path: str) -> PriorityDecision:
    cfg = load_rules(rules_path)
    for rule in cfg.get("rules", []):
        if not _eval(rule.get("when", {}), x):
            continue
        prio = rule["priority"]
        reasons = [rule.get("name", "")]
        # Non-negotiable guard: weak signals alone never trigger P1/P2 through the
        # evidence level. Rules that do not depend on the level (CVSS on an exposed
        # asset, watchlist bypass) are unaffected.
        level_based = any(k in rule.get("when", {}) for k in ("exploited", "exploited_confirmed", "poc_public_verified"))
        if prio in ("P1", "P2") and level_based and x.weak_only:
            reasons.append("rétrogradée en P3 : niveau de preuve reposant uniquement sur des signaux faibles")
            prio = "P3"
        return PriorityDecision(prio, rule.get("name"), reasons)
    return PriorityDecision(None, None, [])


def fingerprint(state: dict) -> str:
    """Stable hash of the notification-relevant state of a CVE for one audience."""
    return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()


def change_reasons(prev: dict | None, cur: dict) -> list[str]:
    if prev is None:
        return ["première notification"]
    labels = {
        "level": "nouveau niveau de preuve",
        "clients": "nouveau(x) client(s) concerné(s)",
        "bulletin_revisions": "révision de bulletin",
        "patch_available": "correctif publié",
        "bypass": "signal de contournement",
        "priority": "changement de priorité",
    }
    out = []
    for k, label in labels.items():
        if prev.get(k) != cur.get(k):
            if k == "clients" and set(cur.get(k) or []) <= set(prev.get(k) or []):
                continue  # a client leaving the scope is not worth a new alert
            out.append(label)
    return out
