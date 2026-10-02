from types import SimpleNamespace

from conftest import fixture_bytes, fixture_json

from cti.collectors.certfr import parse_certfr_document
from cti.collectors.citrix import parse_citrix_bulletin
from cti.collectors.nvd import parse_nvd_page
from cti.matching.inventory import ProductResolver, load_catalog, load_inventory, match_vulnerability


def netscaler_vuln(settings):
    """CVE-2026-88771 as the pipeline would assemble it from NVD + CERT-FR + Citrix."""
    affected, fixed, cpes = [], [], []
    nvd = parse_nvd_page(fixture_json("nvd/CVE-2026-88771.json")).patches[0]
    cpes += nvd.merge_lists["cpes"]
    affected += nvd.merge_lists["affected"]
    cert = parse_certfr_document(fixture_json("certfr/CERTFR-2026-ALE-011.json"), "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-011/", settings)
    affected += cert.patches[0].merge_lists["affected"]
    fixed += cert.patches[0].merge_lists["fixed_versions"]
    ctx = parse_citrix_bulletin(fixture_bytes("psirt/citrix_CTX697096.html").decode(), "CTX697096", "https://support.citrix.com/external/article/697096", settings)
    affected += ctx.patches[0].merge_lists["affected"]
    fixed += ctx.patches[0].merge_lists["fixed_versions"]
    return SimpleNamespace(cve_id="CVE-2026-88771", vendor="Citrix", product=None, affected=affected, fixed_versions=fixed, cpes=cpes)


def test_alias_resolution(settings):
    r = ProductResolver(load_catalog(settings))
    assert r.resolve("Citrix ADC") == {"citrix-netscaler-adc"}
    assert r.resolve("Citrix NetScaler ADC and Citrix NetScaler Gateway") == {"citrix-netscaler-adc", "citrix-netscaler-gateway"}
    assert r.resolve("Gateway", vendor="Citrix NetScaler") == {"citrix-netscaler-gateway"}
    assert r.resolve("Citrix NetScaler ADC FIPS") == {"citrix-netscaler-adc"}
    assert r.by_cpe("citrix:netscaler_application_delivery_controller") == "citrix-netscaler-adc"
    assert r.resolve("Totally Unknown Product") == set()


def test_netscaler_matching_on_example_inventory(settings):
    matches = match_vulnerability(netscaler_vuln(settings), load_inventory(settings), ProductResolver(load_catalog(settings)))
    by_asset = {m.asset_id: m for m in matches}
    # ACME VPN gateway 14.1-47.46, internet-facing: vulnerable
    assert by_asset["acme-industrie/vpn-gw-01"].version_status == "affected"
    assert by_asset["acme-industrie/vpn-gw-01"].internet_exposed
    # ACME ADC 13.1-64.23 is already fixed: must not be flagged by the 14.1 range
    assert by_asset["acme-industrie/adc-lb-01"].version_status == "not_affected"
    # Santé Plus NetScaler with unknown version: "version à confirmer"
    assert by_asset["sante-plus/netscaler-01"].version_status == "unknown"
    # Unrelated products are not matched
    assert not any(m.asset_id.startswith("banque-horizon/") for m in matches)
