import pytest

from cti.matching.versions import FixStatement, check_version, parse_fix_statement

CITRIX_FIXES = [
    parse_fix_statement("Citrix NetScaler ADC and Citrix NetScaler Gateway 14.1 BEFORE 14.1-73.37"),
    parse_fix_statement("Citrix NetScaler ADC and Citrix NetScaler Gateway 13.1 BEFORE 13.1-64.23"),
    parse_fix_statement("Citrix NetScaler ADC FIPS BEFORE 14.1-73.37 FIPS"),
    parse_fix_statement("Citrix NetScaler ADC FIPS and NDcPP BEFORE 13.1-37.279"),
]


def test_parse_citrix_statements():
    assert [(f.branch, f.fixed) for f in CITRIX_FIXES] == [
        ("14.1", "14.1-73.37"), ("13.1", "13.1-64.23"), (None, "14.1-73.37 FIPS"), (None, "13.1-37.279"),
    ]


@pytest.mark.parametrize(
    "text, branch, fixed",
    [
        ("Citrix NetScaler ADC versions 14.1.x antérieures à 14.1-73.37", "14.1", "14.1-73.37"),
        ("NetScaler Gateway versions 13.1.x antérieures à 13.1-64.23", "13.1", "13.1-64.23"),
        ("Citrix NetScaler ADC versions 13.1-FIPS antérieures à 13.1-NDcPP 13.1.37.279", "13.1", "13.1.37.279 NDcPP"),
        ("Roundcube Webmail versions 1.6.x antérieures à 1.6.16", "1.6", "1.6.16"),
        ("FortiOS versions antérieures à 7.4.5", None, "7.4.5"),
    ],
)
def test_parse_certfr_statements(text, branch, fixed):
    f = parse_fix_statement(text)
    assert f is not None and (f.branch, f.fixed) == (branch, fixed)


@pytest.mark.parametrize(
    "version, expected",
    [
        ("14.1-47.46", "affected"),       # older build on 14.1
        ("14.1-73.37", "not_affected"),   # exactly the fixed build
        ("13.1-64.23", "not_affected"),   # fixed on 13.1 — must NOT be flagged by the 14.1 range
        ("13.1-51.15", "affected"),
        ("12.1-55.330", "unknown"),       # EOL branch not listed: never silently "not affected"
        (None, "unknown"),
        ("14.1-60.1 FIPS", "affected"),   # FIPS train compared only with FIPS fixes
    ],
)
def test_branch_aware_check(version, expected):
    status, _ = check_version(version, CITRIX_FIXES)
    assert status == expected


def test_unparseable_version_is_unknown():
    assert check_version("latest", [FixStatement("x", None, "1.2.3", "")])[0] == "unknown"
