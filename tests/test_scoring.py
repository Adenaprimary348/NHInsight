# MIT License — Copyright (c) 2026 cvemula1
# Tests for NHI security scoring engine

from nhinsight.analyzers.scoring import (
    NIST_CONTROL_MAP,
    compute_scorecard,
    get_nist_controls_for_code,
    get_nist_family,
)
from nhinsight.core.models import (
    Identity,
    IdentityType,
    Provider,
    RiskFlag,
    Severity,
)


def _make_nhi(name="test", risk_flags=None, owner="", **kw):
    return Identity(
        id=f"test:{name}",
        name=name,
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        risk_flags=risk_flags or [],
        owner=owner,
        **kw,
    )


# ── Scorecard basic tests ───────────────────────────────────────────

def test_empty_scorecard():
    card = compute_scorecard([])
    assert card.total_identities == 0
    assert card.attack_surface_score == 0.0
    assert card.grade == "F"


def test_all_healthy():
    nhis = [_make_nhi(f"h{i}", owner="team-a") for i in range(10)]
    card = compute_scorecard(nhis)
    assert card.total_identities == 10
    assert card.risk_score == 0
    assert card.severity_counts["healthy"] == 10
    assert card.attack_surface_score >= 75.0
    assert card.grade in ("A", "B")


def test_all_critical():
    flags = [RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS", "admin")]
    nhis = [_make_nhi(f"c{i}", risk_flags=list(flags)) for i in range(5)]
    card = compute_scorecard(nhis)
    assert card.risk_score == 50  # 5 * 10
    assert card.severity_counts["critical"] == 5
    assert card.ciso_metrics.pct_admin == 100.0
    assert card.attack_surface_score < 50.0


def test_mixed_severities():
    nhis = [
        _make_nhi("crit", risk_flags=[
            RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS", "admin"),
        ]),
        _make_nhi("high", risk_flags=[
            RiskFlag(Severity.HIGH, "AWS_KEY_NOT_ROTATED", "old key"),
        ]),
        _make_nhi("med", risk_flags=[
            RiskFlag(Severity.MEDIUM, "STALE_IDENTITY", "stale"),
        ]),
        _make_nhi("low", risk_flags=[
            RiskFlag(Severity.LOW, "NO_OWNER", "no owner"),
        ]),
        _make_nhi("ok", owner="team-a"),
    ]
    card = compute_scorecard(nhis)
    assert card.total_identities == 5
    assert card.severity_counts["critical"] == 1
    assert card.severity_counts["high"] == 1
    assert card.severity_counts["medium"] == 1
    assert card.severity_counts["low"] == 1
    assert card.severity_counts["healthy"] == 1
    # Risk = 10 + 6 + 3 + 1 = 20
    assert card.risk_score == 20


# ── CISO Metrics ────────────────────────────────────────────────────

def test_ownership_metric():
    nhis = [
        _make_nhi("owned", owner="alice"),
        _make_nhi("owned2", created_by="bob"),
        _make_nhi("orphan"),
    ]
    card = compute_scorecard(nhis)
    assert 60.0 < card.ciso_metrics.pct_with_owner < 70.0  # ~66.7%


def test_stale_metric():
    nhis = [
        _make_nhi("stale", risk_flags=[
            RiskFlag(Severity.MEDIUM, "STALE_IDENTITY", "stale"),
        ]),
        _make_nhi("fresh"),
    ]
    card = compute_scorecard(nhis)
    assert card.ciso_metrics.pct_stale == 50.0


def test_admin_metric():
    nhis = [
        _make_nhi("admin", risk_flags=[
            RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS", "admin"),
        ]),
        _make_nhi("normal"),
        _make_nhi("normal2"),
    ]
    card = compute_scorecard(nhis)
    assert 33.0 < card.ciso_metrics.pct_admin < 34.0  # ~33.3%


# ── Governance Scores ───────────────────────────────────────────────

def test_governance_all_owned_no_issues():
    nhis = [_make_nhi(f"h{i}", owner="team-a") for i in range(10)]
    card = compute_scorecard(nhis)
    assert card.governance.ownership_coverage == 1.0
    assert card.governance.credential_rotation == 1.0
    assert card.governance.least_privilege == 1.0
    assert card.governance.lifecycle_hygiene == 1.0
    assert card.governance.overall == 1.0


def test_governance_partial():
    nhis = [
        _make_nhi("owned", owner="team-a"),
        _make_nhi("orphan"),
        _make_nhi("admin", risk_flags=[
            RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS", "admin"),
        ]),
    ]
    card = compute_scorecard(nhis)
    assert 0.3 < card.governance.ownership_coverage < 0.4  # ~33%
    assert 0.6 < card.governance.least_privilege < 0.7     # ~67%


# ── NIST Compliance ─────────────────────────────────────────────────

def test_nist_all_pass():
    nhis = [_make_nhi("clean", owner="team-a")]
    card = compute_scorecard(nhis)
    for ctrl in card.nist_controls.values():
        assert ctrl.status == "PASS"


def test_nist_fail_on_admin():
    nhis = [
        _make_nhi(f"a{i}", risk_flags=[
            RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS", "admin"),
        ]) for i in range(5)
    ]
    card = compute_scorecard(nhis)
    # AC-6 should be FAIL (5/5 = 100%)
    assert card.nist_controls["AC-6"].status == "FAIL"
    assert card.nist_controls["AC-6"].identities == 5


def test_nist_partial_threshold():
    # 1 violation out of 10 = 10% < 20% threshold → PARTIAL
    nhis = [_make_nhi(f"n{i}") for i in range(10)]
    nhis[0].risk_flags = [
        RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS", "admin"),
    ]
    card = compute_scorecard(nhis)
    assert card.nist_controls["AC-6"].status == "PARTIAL"


# ── NIST mapping helpers ────────────────────────────────────────────

def test_all_risk_codes_mapped():
    """Every risk code in the map should return controls."""
    for code, controls in NIST_CONTROL_MAP.items():
        assert len(controls) > 0, f"{code} has no NIST controls"
        result = get_nist_controls_for_code(code)
        assert result == controls


def test_nist_family_lookup():
    assert get_nist_family("AC-6") == "Access Control"
    assert get_nist_family("IA-5(1)") == "Identification & Authentication"
    assert get_nist_family("SC-28") == "System & Communications Protection"


def test_unknown_code_returns_empty():
    assert get_nist_controls_for_code("DOES_NOT_EXIST") == []


# ── Grade boundaries ────────────────────────────────────────────────

def test_grade_a():
    nhis = [_make_nhi(f"h{i}", owner="team-a") for i in range(20)]
    card = compute_scorecard(nhis)
    assert card.grade == "A"


def test_grade_f_all_critical():
    flags = [RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS", "admin")]
    nhis = [_make_nhi(f"c{i}", risk_flags=list(flags)) for i in range(20)]
    card = compute_scorecard(nhis)
    assert card.grade in ("D", "F")


# ── to_dict serialization ──────────────────────────────────────────

def test_scorecard_to_dict():
    nhis = [
        _make_nhi("a", owner="team", risk_flags=[
            RiskFlag(Severity.HIGH, "AWS_KEY_NOT_ROTATED", "old key"),
        ]),
        _make_nhi("b", owner="team"),
    ]
    card = compute_scorecard(nhis)
    d = card.to_dict()
    assert "attack_surface_score" in d
    assert "grade" in d
    assert "governance" in d
    assert "ciso_metrics" in d
    assert "nist_controls" in d
    assert isinstance(d["governance"]["ownership_coverage"], float)
    assert isinstance(d["ciso_metrics"]["pct_admin"], float)
