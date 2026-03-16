# MIT License — Copyright (c) 2026 cvemula1
# Tests for risk analysis

from nhinsight.analyzers.risk import analyze_risk
from nhinsight.core.models import Severity


def test_admin_access_flagged(machine_user, config):
    analyze_risk([machine_user], config)
    codes = [f.code for f in machine_user.risk_flags]
    assert "AWS_ADMIN_ACCESS" in codes
    assert any(f.severity == Severity.CRITICAL for f in machine_user.risk_flags)


def test_key_not_rotated(stale_key, config):
    config.rotation_max_days = 365
    analyze_risk([stale_key], config)
    codes = [f.code for f in stale_key.risk_flags]
    assert "AWS_KEY_NOT_ROTATED" in codes


def test_stale_identity(stale_key, config):
    config.stale_days = 90
    analyze_risk([stale_key], config)
    codes = [f.code for f in stale_key.risk_flags]
    assert "STALE_IDENTITY" in codes


def test_no_owner_flagged(stale_key, config):
    stale_key.owner = ""
    stale_key.created_by = ""
    analyze_risk([stale_key], config)
    codes = [f.code for f in stale_key.risk_flags]
    assert "NO_OWNER" in codes


def test_wildcard_trust(wildcard_role, config):
    analyze_risk([wildcard_role], config)
    codes = [f.code for f in wildcard_role.risk_flags]
    assert "AWS_WILDCARD_TRUST" in codes
    assert "AWS_ADMIN_ACCESS" in codes


def test_healthy_role_no_critical(healthy_role, config):
    analyze_risk([healthy_role], config)
    critical_flags = [f for f in healthy_role.risk_flags if f.severity == Severity.CRITICAL]
    assert len(critical_flags) == 0


def test_human_no_mfa_console(human_user, config):
    human_user.raw["has_mfa"] = False
    analyze_risk([human_user], config)
    codes = [f.code for f in human_user.risk_flags]
    assert "AWS_NO_MFA" in codes


def test_human_with_mfa_ok(human_user, config):
    analyze_risk([human_user], config)
    codes = [f.code for f in human_user.risk_flags]
    assert "AWS_NO_MFA" not in codes


def test_inactive_key_flagged(stale_key, config):
    stale_key.raw["status"] = "Inactive"
    analyze_risk([stale_key], config)
    codes = [f.code for f in stale_key.risk_flags]
    assert "AWS_KEY_INACTIVE" in codes
