# MIT License — Copyright (c) 2026 cvemula1
# Tests for GitHub provider risk checks and classification

from datetime import datetime, timedelta, timezone

from nhinsight.analyzers.classification import classify_identities
from nhinsight.analyzers.risk import analyze_risk
from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import (
    Classification,
    Identity,
    IdentityType,
    Provider,
)


def _config():
    return NHInsightConfig(stale_days=90, rotation_max_days=365)


def _now():
    return datetime.now(timezone.utc)


def test_deploy_key_classified_machine():
    ident = Identity(
        id="github:deploy_key:org/repo:1",
        name="prod-deploy → org/repo",
        provider=Provider.GITHUB,
        identity_type=IdentityType.DEPLOY_KEY,
        permissions=["repo:read"],
    )
    classify_identities([ident])
    assert ident.classification == Classification.MACHINE


def test_github_app_classified_machine():
    ident = Identity(
        id="github:app:org:1",
        name="renovate (app)",
        provider=Provider.GITHUB,
        identity_type=IdentityType.GITHUB_APP,
    )
    classify_identities([ident])
    assert ident.classification == Classification.MACHINE


def test_webhook_classified_machine():
    ident = Identity(
        id="github:hook:org:1",
        name="org-webhook → https://example.com/...",
        provider=Provider.GITHUB,
        identity_type=IdentityType.WEBHOOK,
    )
    classify_identities([ident])
    assert ident.classification == Classification.MACHINE


def test_deploy_key_write_flagged():
    ident = Identity(
        id="github:deploy_key:org/repo:1",
        name="prod-deploy → org/repo",
        provider=Provider.GITHUB,
        identity_type=IdentityType.DEPLOY_KEY,
        permissions=["repo:write"],
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "GH_DEPLOY_KEY_WRITE" in codes


def test_deploy_key_readonly_ok():
    ident = Identity(
        id="github:deploy_key:org/repo:1",
        name="prod-deploy → org/repo",
        provider=Provider.GITHUB,
        identity_type=IdentityType.DEPLOY_KEY,
        permissions=["repo:read"],
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "GH_DEPLOY_KEY_WRITE" not in codes


def test_github_app_dangerous_perms():
    ident = Identity(
        id="github:app:org:1",
        name="custom-bot (app)",
        provider=Provider.GITHUB,
        identity_type=IdentityType.GITHUB_APP,
        permissions=["administration:write", "contents:read"],
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "GH_APP_DANGEROUS_PERMS" in codes


def test_github_app_safe_perms():
    ident = Identity(
        id="github:app:org:1",
        name="renovate (app)",
        provider=Provider.GITHUB,
        identity_type=IdentityType.GITHUB_APP,
        permissions=["contents:read", "pull_requests:write"],
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "GH_APP_DANGEROUS_PERMS" not in codes


def test_inactive_webhook_flagged():
    ident = Identity(
        id="github:hook:org:1",
        name="org-webhook → https://old.example.com/...",
        provider=Provider.GITHUB,
        identity_type=IdentityType.WEBHOOK,
        raw={"active": False},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "GH_WEBHOOK_INACTIVE" in codes


def test_active_webhook_ok():
    ident = Identity(
        id="github:hook:org:1",
        name="org-webhook → https://ci.example.com/...",
        provider=Provider.GITHUB,
        identity_type=IdentityType.WEBHOOK,
        raw={"active": True},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "GH_WEBHOOK_INACTIVE" not in codes


def test_pat_admin_scope():
    ident = Identity(
        id="github:pat:org:1",
        name="deploy-token",
        provider=Provider.GITHUB,
        identity_type=IdentityType.GITHUB_PAT,
        permissions=["admin:org", "repo"],
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "GH_ADMIN_SCOPE" in codes
    assert "GH_REPO_WRITE" in codes


def test_stale_deploy_key():
    now = _now()
    ident = Identity(
        id="github:deploy_key:org/repo:1",
        name="old-key → org/repo",
        provider=Provider.GITHUB,
        identity_type=IdentityType.DEPLOY_KEY,
        created_at=now - timedelta(days=500),
        last_used=now - timedelta(days=120),
        permissions=["repo:read"],
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "STALE_IDENTITY" in codes
