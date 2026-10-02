"""Client inventory + product catalog, and matching of vulnerabilities to assets."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from cti.matching.versions import FixStatement, check_version, parse_fix_statement
from cti.settings import Settings

# ---------------------------------------------------------------- models


class Contact(BaseModel):
    name: str
    email: str | None = None


class Exposure(BaseModel):
    declared: list[str] = Field(default_factory=list)


class AssetDef(BaseModel):
    id: str
    vendor: str
    product: str
    version: str | None = None
    cpe: str | None = None
    internet_exposed: bool = False


class ClientDef(BaseModel):
    id: str
    name: str
    contacts: list[Contact] = Field(default_factory=list)
    exposure: Exposure = Field(default_factory=Exposure)
    assets: list[AssetDef] = Field(default_factory=list)


class Inventory(BaseModel):
    clients: list[ClientDef]


class ProductDef(BaseModel):
    id: str
    vendor: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)


class Catalog(BaseModel):
    products: list[ProductDef]


def inventory_path(settings: Settings) -> Path:
    real = settings.config_dir / "inventory.yaml"
    return real if real.exists() else settings.config_dir / "inventory.example.yaml"


def load_inventory(settings: Settings) -> Inventory:
    return Inventory.model_validate(yaml.safe_load(inventory_path(settings).read_text(encoding="utf-8")) or {"clients": []})


def load_catalog(settings: Settings) -> Catalog:
    path = settings.config_dir / "product_aliases.yaml"
    return Catalog.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {"products": []})


# ---------------------------------------------------------------- normalization

_QUAL_RE = re.compile(r"\b(fips|ndcpp)\b", re.I)


def norm(text: str) -> str:
    text = _QUAL_RE.sub(" ", text or "")
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text.lower()).split())


def split_products(text: str) -> list[str]:
    """'Citrix NetScaler ADC and Citrix NetScaler Gateway' -> two segments."""
    return [p for p in re.split(r"\s+(?:and|et|&)\s+|\s*[,/]\s*", text or "") if p.strip()]


class ProductResolver:
    def __init__(self, catalog: Catalog):
        self.catalog = catalog

    @cached_property
    def _alias_index(self) -> list[tuple[str, str]]:
        idx = []
        for p in self.catalog.products:
            for a in {p.name, f"{p.vendor} {p.name}", *p.aliases}:
                idx.append((norm(a), p.id))
        # Longest aliases first: "netscaler gateway" must win over "netscaler".
        return sorted(idx, key=lambda x: -len(x[0]))

    @cached_property
    def _cpe_index(self) -> dict[str, str]:
        return {c.lower(): p.id for p in self.catalog.products for c in p.cpe}

    def by_cpe(self, vendor_product: str) -> str | None:
        return self._cpe_index.get(vendor_product.lower())

    def resolve(self, text: str, vendor: str | None = None) -> set[str]:
        """Canonical product ids named in a free-text product string."""
        found: set[str] = set()
        for seg in split_products(text):
            candidates = [norm(seg)]
            if vendor and not norm(seg).startswith(norm(vendor)):
                candidates.insert(0, norm(f"{vendor} {seg}"))
            hit = None
            for cand in candidates:
                hit = next((pid for alias, pid in self._alias_index if alias == cand), None)
                if hit:
                    break
            if hit is None:  # containment on word boundaries, multi-word aliases only
                padded = f" {candidates[0]} "
                hit = next(
                    (pid for alias, pid in self._alias_index if " " in alias and f" {alias} " in padded),
                    None,
                )
            if hit:
                found.add(hit)
        return found

    def resolve_asset(self, asset: AssetDef) -> str | None:
        if asset.cpe:
            parts = asset.cpe.split(":")
            if len(parts) > 4 and (pid := self.by_cpe(f"{parts[3]}:{parts[4]}")):
                return pid
        ids = self.resolve(asset.product, asset.vendor)
        return next(iter(ids)) if len(ids) == 1 else None


# ---------------------------------------------------------------- vuln side


@dataclass
class VulnProducts:
    products: set[str]
    fixes: dict[str, list[FixStatement]]  # product id -> fix statements
    sources: dict[str, set[str]]  # product id -> source URLs that name it


def vuln_products(vuln, resolver: ProductResolver) -> VulnProducts:
    products: set[str] = set()
    fixes: dict[str, list[FixStatement]] = {}
    sources: dict[str, set[str]] = {}

    def add(pids: set[str], fix: FixStatement | None, url: str | None):
        for pid in pids:
            products.add(pid)
            if url:
                sources.setdefault(pid, set()).add(url)
            if fix:
                fixes.setdefault(pid, [])
                if fix not in fixes[pid]:
                    fixes[pid].append(fix)

    for a in vuln.affected or []:
        text = " ".join(x for x in (a.get("product"),) if x) or a.get("text", "")
        pids = resolver.resolve(text, a.get("vendor"))
        if not pids and a.get("text"):
            pids = resolver.resolve(a["text"], a.get("vendor"))
        fix = None
        if a.get("fix"):
            f = a["fix"]
            fix = FixStatement(f["product_text"], f.get("branch"), f["fixed"], f["source_text"])
        elif a.get("less_than"):
            fix = FixStatement(text, None, a["less_than"], a.get("text", ""))
        elif a.get("text"):
            fix = parse_fix_statement(a["text"])
        add(pids, fix, a.get("source_url"))
    for f in vuln.fixed_versions or []:
        pids = resolver.resolve(f.get("product") or "")
        add(pids, FixStatement(f.get("product") or "", f.get("branch"), f["fixed"], f.get("product") or ""), f.get("source_url"))
    for c in vuln.cpes or []:
        pid = resolver.by_cpe(c.get("vendor_product", ""))
        if not pid:
            continue
        fix = None
        end = c.get("versionEndExcluding")
        if end:
            start = c.get("versionStartIncluding") or c.get("versionStartExcluding")
            fix = FixStatement(c["criteria"], start if start and "-" not in start else None, end, c["criteria"])
        # CPE ranges are only a fallback: vendor/CNA/CERT statements are more precise.
        add({pid}, fix if pid not in fixes else None, "https://nvd.nist.gov/vuln/detail/" + vuln.cve_id)
    if vuln.vendor and vuln.product and not products:
        add(resolver.resolve(vuln.product, vuln.vendor), None, None)
    return VulnProducts(products, fixes, sources)


@dataclass
class MatchResult:
    client_id: str
    client_name: str
    asset_id: str
    product_id: str
    asset_label: str
    version: str | None
    internet_exposed: bool
    version_status: str  # affected | not_affected | unknown
    detail: str
    method: str = "alias"


def match_vulnerability(vuln, inventory: Inventory, resolver: ProductResolver) -> list[MatchResult]:
    vp = vuln_products(vuln, resolver)
    if not vp.products:
        return []
    out = []
    for client in inventory.clients:
        for asset in client.assets:
            pid = resolver.resolve_asset(asset)
            if pid is None or pid not in vp.products:
                continue
            fixes = vp.fixes.get(pid, [])
            if fixes:
                status, detail = check_version(asset.version, fixes)
            else:
                status, detail = "unknown", "aucune information de version corrigée publiée à ce stade"
            out.append(
                MatchResult(
                    client_id=client.id,
                    client_name=client.name,
                    asset_id=f"{client.id}/{asset.id}",
                    product_id=pid,
                    asset_label=f"{asset.vendor} {asset.product} {asset.version or '(version inconnue)'}",
                    version=asset.version,
                    internet_exposed=asset.internet_exposed,
                    version_status=status,
                    detail=detail,
                    method="cpe" if asset.cpe else "alias",
                )
            )
    return out
