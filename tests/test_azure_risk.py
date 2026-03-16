# MIT License — Copyright (c) 2026 cvemula1
# Tests for Azure risk analysis

from datetime import datetime, timedelta, timezone

import pytest

from nhinsight.analyzers.risk import analyze_risk
from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import (
    Identity,
    IdentityType,
    Provider,
    Severity,
)


@pytest.fixture
def config():
    return NHInsightConfig(stale_days=90, rotation_max_days=365)


def _make_sp(name="test-sp", policies=None, enabled=True, **kw):
    return Identity(
        id=f"azure:sp:{name}",
        name=name,
        provider=Provider.AZURE,
        identity_type=IdentityType.AZURE_SP,
        policies=policies or [],
        raw={"app_id": "aaa", "object_id": "bbb",
             "sp_type": "Application", "enabled": enabled,
             "tags": [], "app_owner_org": "t1"},
        **kw,
    )


def _make_mi(name="test-mi", policies=None, **kw):
    return Identity(
        id=f"azure:mi:{name}",
        name=name,
        provider=Provider.AZURE,
        identity_type=IdentityType.AZURE_MANAGED_IDENTITY,
        policies=policies or [],
        raw={"app_id": "ccc", "object_id": "ddd",
             "mi_type": "user-assigned", "resource_id": "/sub/...", "tags": []},
        **kw,
    )


def _make_secret(name="test-app/secret:hint", age_days=100, expires_in_days=90, **kw):
    now = datetime.now(timezone.utc)
    return Identity(
        id=f"azure:app_secret:{name}",
        name=name,
        provider=Provider.AZURE,
        identity_type=IdentityType.AZURE_APP_SECRET,
        created_at=now - timedelta(days=age_days),
        raw={"app_id": "eee", "app_name": "test-app",
             "cred_id": "s1", "hint": "hint",
             "expires_at": (now + timedelta(days=expires_in_days)).isoformat()},
        **kw,
    )


# ── Service Principal tests ──────────────────────────────────────

def test_sp_owner_at_subscription_critical(config):
    sp = _make_sp(policies=["Owner @ /subscriptions/sub-123"])
    analyze_risk([sp], config)
    codes = [f.code for f in sp.risk_flags]
    assert "AZURE_SP_DANGEROUS_ROLE" in codes
    assert any(f.severity == Severity.CRITICAL for f in sp.risk_flags)


def test_sp_contributor_at_subscription_critical(config):
    sp = _make_sp(policies=["Contributor @ /subscriptions/sub-123"])
    analyze_risk([sp], config)
    codes = [f.code for f in sp.risk_flags]
    assert "AZURE_SP_DANGEROUS_ROLE" in codes


def test_sp_contributor_at_rg_medium(config):
    sp = _make_sp(policies=[
        "Contributor @ /subscriptions/sub-123/resourceGroups/my-rg"
    ])
    analyze_risk([sp], config)
    codes = [f.code for f in sp.risk_flags]
    assert "AZURE_SP_ELEVATED_ROLE" in codes
    assert any(f.severity == Severity.MEDIUM for f in sp.risk_flags)


def test_sp_reader_no_flag(config):
    sp = _make_sp(policies=["Reader @ /subscriptions/sub-123"])
    analyze_risk([sp], config)
    codes = [f.code for f in sp.risk_flags]
    assert "AZURE_SP_DANGEROUS_ROLE" not in codes
    assert "AZURE_SP_ELEVATED_ROLE" not in codes


def test_sp_disabled_with_roles_flagged(config):
    sp = _make_sp(
        policies=["Contributor @ /subscriptions/sub-123/resourceGroups/rg"],
        enabled=False,
    )
    analyze_risk([sp], config)
    codes = [f.code for f in sp.risk_flags]
    assert "AZURE_SP_DISABLED_WITH_ROLES" in codes


def test_sp_disabled_no_roles_not_flagged(config):
    sp = _make_sp(policies=[], enabled=False)
    analyze_risk([sp], config)
    codes = [f.code for f in sp.risk_flags]
    assert "AZURE_SP_DISABLED_WITH_ROLES" not in codes


# ── Managed Identity tests ───────────────────────────────────────

def test_mi_owner_at_subscription_high(config):
    mi = _make_mi(policies=["Owner @ /subscriptions/sub-123"])
    analyze_risk([mi], config)
    codes = [f.code for f in mi.risk_flags]
    assert "AZURE_MI_DANGEROUS_ROLE" in codes
    assert any(f.severity == Severity.HIGH for f in mi.risk_flags)


def test_mi_reader_no_flag(config):
    mi = _make_mi(policies=["Reader @ /subscriptions/sub-123"])
    analyze_risk([mi], config)
    codes = [f.code for f in mi.risk_flags]
    assert "AZURE_MI_DANGEROUS_ROLE" not in codes


def test_mi_contributor_at_rg_no_flag(config):
    mi = _make_mi(policies=[
        "Contributor @ /subscriptions/sub-123/resourceGroups/rg"
    ])
    analyze_risk([mi], config)
    codes = [f.code for f in mi.risk_flags]
    assert "AZURE_MI_DANGEROUS_ROLE" not in codes


# ── App credential tests ─────────────────────────────────────────

def test_secret_not_rotated(config):
    secret = _make_secret(age_days=400)
    analyze_risk([secret], config)
    codes = [f.code for f in secret.risk_flags]
    assert "AZURE_SECRET_NOT_ROTATED" in codes
    assert any(f.severity == Severity.HIGH for f in secret.risk_flags)


def test_secret_young_no_rotation_flag(config):
    secret = _make_secret(age_days=100)
    analyze_risk([secret], config)
    codes = [f.code for f in secret.risk_flags]
    assert "AZURE_SECRET_NOT_ROTATED" not in codes


def test_secret_expired(config):
    secret = _make_secret(age_days=400, expires_in_days=-30)
    analyze_risk([secret], config)
    codes = [f.code for f in secret.risk_flags]
    assert "AZURE_CRED_EXPIRED" in codes


def test_secret_expiring_soon(config):
    secret = _make_secret(age_days=100, expires_in_days=10)
    analyze_risk([secret], config)
    codes = [f.code for f in secret.risk_flags]
    assert "AZURE_CRED_EXPIRING_SOON" in codes


def test_secret_not_expiring_soon(config):
    secret = _make_secret(age_days=100, expires_in_days=90)
    analyze_risk([secret], config)
    codes = [f.code for f in secret.risk_flags]
    assert "AZURE_CRED_EXPIRING_SOON" not in codes
    assert "AZURE_CRED_EXPIRED" not in codes
