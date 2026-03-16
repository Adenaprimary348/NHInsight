# MIT License — Copyright (c) 2026 cvemula1
# Tests for Kubernetes provider risk checks and classification

from datetime import datetime, timedelta, timezone

from nhinsight.analyzers.classification import classify_identities
from nhinsight.analyzers.risk import analyze_risk
from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import (
    Classification,
    Identity,
    IdentityType,
    Provider,
    Severity,
)


def _config():
    return NHInsightConfig(stale_days=90, rotation_max_days=365)


def _now():
    return datetime.now(timezone.utc)


def test_service_account_classified_machine():
    ident = Identity(
        id="k8s:sa:prod:payments:deploy-bot",
        name="payments/deploy-bot",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
    )
    classify_identities([ident])
    assert ident.classification == Classification.MACHINE


def test_cluster_admin_flagged():
    ident = Identity(
        id="k8s:sa:prod:default:tiller",
        name="default/tiller",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        policies=["cluster-admin"],
        raw={"automount_token": True},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_CLUSTER_ADMIN" in codes
    assert any(f.severity == Severity.CRITICAL for f in ident.risk_flags)


def test_automount_privileged_flagged():
    ident = Identity(
        id="k8s:sa:prod:kube-system:admin-sa",
        name="kube-system/admin-sa",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        policies=["cluster-admin"],
        raw={"automount_token": True},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_AUTOMOUNT_PRIVILEGED" in codes


def test_automount_non_privileged_ok():
    ident = Identity(
        id="k8s:sa:prod:app:reader",
        name="app/reader",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        policies=["view"],
        raw={"automount_token": True},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_AUTOMOUNT_PRIVILEGED" not in codes


def test_default_sa_flagged():
    ident = Identity(
        id="k8s:sa:prod:default:default",
        name="default/default",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        raw={},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_DEFAULT_SA" in codes


def test_orphaned_sa_flagged():
    ident = Identity(
        id="k8s:sa:prod:monitoring:old-exporter",
        name="monitoring/old-exporter",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        raw={"orphaned": True},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_ORPHANED_SA" in codes


def test_active_sa_not_orphaned():
    ident = Identity(
        id="k8s:sa:prod:app:api-server",
        name="app/api-server",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        raw={"orphaned": False},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_ORPHANED_SA" not in codes


def test_no_workload_identity_flagged():
    ident = Identity(
        id="k8s:sa:prod:app:s3-reader",
        name="app/s3-reader",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        raw={
            "secret_count": 2,
            "irsa_role_arn": "",
            "workload_identity_email": "",
            "labels": {"app": "s3-backup", "cloud": "aws"},
        },
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_NO_WORKLOAD_IDENTITY" in codes


def test_irsa_configured_ok():
    ident = Identity(
        id="k8s:sa:prod:app:s3-reader",
        name="app/s3-reader",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        raw={
            "secret_count": 1,
            "irsa_role_arn": "arn:aws:iam::123456789012:role/s3-reader",
            "workload_identity_email": "",
            "labels": {"cloud": "aws"},
        },
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_NO_WORKLOAD_IDENTITY" not in codes


def test_multiple_risks_on_one_sa():
    now = _now()
    ident = Identity(
        id="k8s:sa:prod:default:tiller",
        name="default/tiller",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        created_at=now - timedelta(days=1000),
        last_used=now - timedelta(days=200),
        policies=["cluster-admin"],
        raw={"orphaned": True, "automount_token": True},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_CLUSTER_ADMIN" in codes
    assert "K8S_ORPHANED_SA" in codes
    assert "K8S_AUTOMOUNT_PRIVILEGED" in codes
    assert "STALE_IDENTITY" in codes
    assert ident.highest_severity == Severity.CRITICAL


def test_deploy_using_default_sa_flagged():
    ident = Identity(
        id="k8s:sa:prod:default:default",
        name="default/default",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        raw={"used_as_default_by_deployments": ["api-server", "worker"]},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_DEPLOY_DEFAULT_SA" in codes


def test_deploy_with_dedicated_sa_ok():
    ident = Identity(
        id="k8s:sa:prod:app:api-sa",
        name="app/api-sa",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        raw={"used_as_default_by_deployments": [], "orphaned": False},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_DEPLOY_DEFAULT_SA" not in codes


def test_cluster_role_prefix_format():
    """Verify ClusterRole/ prefix from RBAC map is recognized."""
    ident = Identity(
        id="k8s:sa:prod:kube-system:tiller",
        name="kube-system/tiller",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        policies=["ClusterRole/cluster-admin"],
        raw={"automount_token": True},
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_CLUSTER_ADMIN" in codes
    assert "K8S_AUTOMOUNT_PRIVILEGED" in codes


# ── Secrets tests ──────────────────────────────────────────────────


def test_k8s_secret_classified_machine():
    ident = Identity(
        id="k8s:secret:prod:app:db-creds",
        name="app/db-creds",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.K8S_SECRET,
    )
    classify_identities([ident])
    assert ident.classification == Classification.MACHINE


def test_opaque_secret_with_credentials_flagged():
    ident = Identity(
        id="k8s:secret:prod:app:db-creds",
        name="app/db-creds",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.K8S_SECRET,
        raw={
            "secret_type": "Opaque",
            "data_keys": ["DB_PASSWORD", "API_KEY", "username"],
            "managed_by": "",
        },
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_SECRET_CREDENTIALS" in codes


def test_opaque_secret_no_credentials_ok():
    ident = Identity(
        id="k8s:secret:prod:app:config",
        name="app/config",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.K8S_SECRET,
        raw={
            "secret_type": "Opaque",
            "data_keys": ["config.yaml", "settings.json"],
            "managed_by": "",
        },
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_SECRET_CREDENTIALS" not in codes


def test_tls_secret_unmanaged_flagged():
    ident = Identity(
        id="k8s:secret:prod:ingress:tls-cert",
        name="ingress/tls-cert",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.K8S_SECRET,
        raw={
            "secret_type": "kubernetes.io/tls",
            "data_keys": ["tls.crt", "tls.key"],
            "managed_by": "",
        },
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_TLS_UNMANAGED" in codes


def test_tls_secret_managed_by_certmanager_ok():
    ident = Identity(
        id="k8s:secret:prod:ingress:tls-cert",
        name="ingress/tls-cert",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.K8S_SECRET,
        raw={
            "secret_type": "kubernetes.io/tls",
            "data_keys": ["tls.crt", "tls.key"],
            "managed_by": "cert-manager",
        },
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_TLS_UNMANAGED" not in codes


def test_legacy_sa_token_flagged():
    ident = Identity(
        id="k8s:secret:prod:kube-system:sa-token-abc",
        name="kube-system/sa-token-abc",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.K8S_SECRET,
        raw={
            "secret_type": "kubernetes.io/service-account-token",
            "data_keys": ["token", "ca.crt", "namespace"],
            "managed_by": "",
            "service_account": "dashboard",
        },
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_LEGACY_SA_TOKEN" in codes
    assert any(f.severity == Severity.HIGH for f in ident.risk_flags)


def test_azure_workload_identity_ok():
    ident = Identity(
        id="k8s:sa:prod:app:azure-reader",
        name="app/azure-reader",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        raw={
            "secret_count": 1,
            "irsa_role_arn": "",
            "workload_identity_gcp": "",
            "workload_identity_azure": "12345-abcde",
            "labels": {"cloud": "azure"},
        },
    )
    analyze_risk([ident], _config())
    codes = [f.code for f in ident.risk_flags]
    assert "K8S_NO_WORKLOAD_IDENTITY" not in codes
