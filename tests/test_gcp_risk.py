# MIT License — Copyright (c) 2026 cvemula1
# Tests for GCP risk analysis

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from nhinsight.analyzers.risk import analyze_risk
from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import (
    Identity,
    IdentityType,
    Provider,
)


def _cfg() -> NHInsightConfig:
    return NHInsightConfig(rotation_max_days=365, stale_days=90)


def _gcp_sa(
    name: str = "test-sa",
    policies: list | None = None,
    disabled: bool = False,
    gcp_managed: bool = False,
    **raw_extra,
) -> Identity:
    raw = {
        "email": f"{name}@my-project.iam.gserviceaccount.com",
        "display_name": name,
        "unique_id": "100000000000000001",
        "disabled": disabled,
        "project_id": "my-project",
        "gcp_managed": gcp_managed,
    }
    raw.update(raw_extra)
    return Identity(
        id=f"gcp:sa:my-project:{name}",
        name=name,
        provider=Provider.GCP,
        identity_type=IdentityType.GCP_SERVICE_ACCOUNT,
        policies=policies or [],
        raw=raw,
    )


def _gcp_key(
    name: str = "test-key",
    sa_email: str = "test-sa@my-project.iam.gserviceaccount.com",
    age_days: int = 100,
    disabled: bool = False,
    expires_at: str | None = None,
) -> Identity:
    now = datetime.now(timezone.utc)
    return Identity(
        id=f"gcp:sa_key:my-project:{name}",
        name=f"test-sa/key:{name[:8]}",
        provider=Provider.GCP,
        identity_type=IdentityType.GCP_SA_KEY,
        created_at=now - timedelta(days=age_days),
        raw={
            "key_id": name,
            "key_type": "USER_MANAGED",
            "sa_email": sa_email,
            "project_id": "my-project",
            "disabled": disabled,
            "expires_at": expires_at,
        },
    )


# ── SA role risks ──────────────────────────────────────────────────


def test_sa_owner_is_critical():
    sa = _gcp_sa(policies=["roles/owner"])
    analyze_risk([sa], _cfg())
    codes = [f.code for f in sa.risk_flags]
    assert "GCP_SA_DANGEROUS_ROLE" in codes
    critical = [f for f in sa.risk_flags if f.code == "GCP_SA_DANGEROUS_ROLE"]
    assert critical[0].severity.value == "critical"


def test_sa_editor_is_critical():
    sa = _gcp_sa(policies=["roles/editor"])
    analyze_risk([sa], _cfg())
    codes = [f.code for f in sa.risk_flags]
    assert "GCP_SA_DANGEROUS_ROLE" in codes
    critical = [f for f in sa.risk_flags if f.code == "GCP_SA_DANGEROUS_ROLE"]
    assert critical[0].severity.value == "critical"


def test_sa_compute_admin_is_high():
    sa = _gcp_sa(policies=["roles/compute.admin"])
    analyze_risk([sa], _cfg())
    codes = [f.code for f in sa.risk_flags]
    assert "GCP_SA_DANGEROUS_ROLE" in codes
    flags = [f for f in sa.risk_flags if f.code == "GCP_SA_DANGEROUS_ROLE"]
    assert flags[0].severity.value == "high"


def test_sa_viewer_no_flag():
    sa = _gcp_sa(policies=["roles/viewer"])
    analyze_risk([sa], _cfg())
    codes = [f.code for f in sa.risk_flags]
    assert "GCP_SA_DANGEROUS_ROLE" not in codes


def test_sa_disabled_with_roles():
    sa = _gcp_sa(policies=["roles/storage.objectViewer"], disabled=True)
    analyze_risk([sa], _cfg())
    codes = [f.code for f in sa.risk_flags]
    assert "GCP_SA_DISABLED_WITH_ROLES" in codes


def test_sa_disabled_no_roles_no_flag():
    sa = _gcp_sa(policies=[], disabled=True)
    analyze_risk([sa], _cfg())
    codes = [f.code for f in sa.risk_flags]
    assert "GCP_SA_DISABLED_WITH_ROLES" not in codes


def test_managed_sa_overprivileged():
    sa = _gcp_sa(
        policies=["roles/editor"],
        gcp_managed=True,
    )
    analyze_risk([sa], _cfg())
    codes = [f.code for f in sa.risk_flags]
    assert "GCP_MANAGED_SA_OVERPRIVILEGED" in codes


def test_managed_sa_viewer_ok():
    sa = _gcp_sa(
        policies=["roles/viewer"],
        gcp_managed=True,
    )
    analyze_risk([sa], _cfg())
    codes = [f.code for f in sa.risk_flags]
    assert "GCP_MANAGED_SA_OVERPRIVILEGED" not in codes


# ── SA key risks ───────────────────────────────────────────────────


def test_key_not_rotated():
    key = _gcp_key(age_days=400)
    analyze_risk([key], _cfg())
    codes = [f.code for f in key.risk_flags]
    assert "GCP_KEY_NOT_ROTATED" in codes


def test_key_young_no_rotation_flag():
    key = _gcp_key(age_days=100)
    analyze_risk([key], _cfg())
    codes = [f.code for f in key.risk_flags]
    assert "GCP_KEY_NOT_ROTATED" not in codes


def test_key_expired():
    expired = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    key = _gcp_key(expires_at=expired)
    analyze_risk([key], _cfg())
    codes = [f.code for f in key.risk_flags]
    assert "GCP_KEY_EXPIRED" in codes


def test_key_expiring_soon():
    soon = (datetime.now(timezone.utc) + timedelta(days=15)).isoformat()
    key = _gcp_key(expires_at=soon)
    analyze_risk([key], _cfg())
    codes = [f.code for f in key.risk_flags]
    assert "GCP_KEY_EXPIRING_SOON" in codes


def test_key_disabled():
    key = _gcp_key(disabled=True)
    analyze_risk([key], _cfg())
    codes = [f.code for f in key.risk_flags]
    assert "GCP_KEY_DISABLED" in codes


def test_key_healthy_no_flags():
    future = (datetime.now(timezone.utc) + timedelta(days=200)).isoformat()
    key = _gcp_key(age_days=100, expires_at=future)
    analyze_risk([key], _cfg())
    # Only universal checks (NO_OWNER) should fire, not GCP-specific
    gcp_codes = [f.code for f in key.risk_flags if f.code.startswith("GCP_")]
    assert len(gcp_codes) == 0
