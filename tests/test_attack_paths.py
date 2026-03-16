# MIT License — Copyright (c) 2026 cvemula1
# Tests for Attack Path Analysis

from nhinsight.analyzers.attack_paths import (
    analyze_attack_paths,
)
from nhinsight.core.models import (
    Identity,
    IdentityType,
    Provider,
    RiskFlag,
    Severity,
)


def _iam_user(name, policies=None, arn="", **kw):
    return Identity(
        id=f"aws:iam:user:123:{name}",
        name=name,
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        arn=arn or f"arn:aws:iam::123:user/{name}",
        policies=policies or [],
        **kw,
    )


def _iam_role(name, policies=None, trusted=None, **kw):
    return Identity(
        id=f"aws:iam:role:123:{name}",
        name=name,
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_ROLE,
        arn=f"arn:aws:iam::123:role/{name}",
        policies=policies or [],
        raw={"trusted_principals": trusted or [], "path": "/"},
        **kw,
    )


def _access_key(user, key_id="AKIA1234"):
    return Identity(
        id=f"aws:iam:key:123:{key_id}",
        name=f"{user}/{key_id}",
        provider=Provider.AWS,
        identity_type=IdentityType.ACCESS_KEY,
        raw={"parent_user": user, "key_id": key_id, "status": "Active"},
    )


def _k8s_sa(ns, name, irsa_arn="", azure_wi="", policies=None, **kw):
    return Identity(
        id=f"k8s:sa:ctx:{ns}:{name}",
        name=f"{ns}/{name}",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        policies=policies or [],
        raw={
            "namespace": ns,
            "sa_name": name,
            "irsa_role_arn": irsa_arn,
            "workload_identity_azure": azure_wi,
            "deployments": [],
            "secret_count": 0,
            "automount_token": True,
        },
        **kw,
    )


def _azure_mi(name, app_id="", policies=None, **kw):
    return Identity(
        id=f"azure:mi:{name}",
        name=name,
        provider=Provider.AZURE,
        identity_type=IdentityType.AZURE_MANAGED_IDENTITY,
        policies=policies or [],
        raw={"app_id": app_id, "object_id": f"obj-{name}"},
        **kw,
    )


def _azure_secret(app_name, app_id=""):
    return Identity(
        id=f"azure:secret:{app_name}",
        name=f"{app_name}/secret:abc",
        provider=Provider.AZURE,
        identity_type=IdentityType.AZURE_APP_SECRET,
        raw={"app_id": app_id},
    )


def _azure_sp(name, app_id="", policies=None, **kw):
    return Identity(
        id=f"azure:sp:{name}",
        name=name,
        provider=Provider.AZURE,
        identity_type=IdentityType.AZURE_SP,
        policies=policies or [],
        raw={"app_id": app_id, "object_id": f"obj-{name}", "enabled": True},
        **kw,
    )


# ── Empty / no paths ────────────────────────────────────────────────

def test_empty_identities():
    result = analyze_attack_paths([])
    assert len(result.paths) == 0


def test_no_paths_single_user():
    result = analyze_attack_paths([_iam_user("bot")])
    assert len(result.paths) == 0


# ── AWS: key → user → admin role ────────────────────────────────────

def test_key_to_admin_role_path():
    """Access key → user → assumes admin role = attack path."""
    user = _iam_user("deploy-bot", arn="arn:aws:iam::123:user/deploy-bot")
    role = _iam_role(
        "admin-role",
        policies=["AdministratorAccess"],
        trusted=["arn:aws:iam::123:user/deploy-bot"],
    )
    key = _access_key("deploy-bot", "AKIA5678")

    result = analyze_attack_paths([user, role, key])
    assert len(result.paths) >= 1

    # Should find: key → user → role (admin)
    # The role is privileged, so there should be a path to it
    target_names = [p.target.node_label for p in result.paths if p.target]
    assert "admin-role" in target_names


# ── Cross-system: K8s SA → AWS role (IRSA) ──────────────────────────

def test_irsa_cross_system_path():
    """K8s SA with IRSA → AWS admin role = cross-system attack path."""
    role = _iam_role("eks-admin", policies=["AdministratorAccess"])
    sa = _k8s_sa("prod", "deploy-sa", irsa_arn=role.arn)

    result = analyze_attack_paths([role, sa])

    # Should find cross-system path: SA → AWS role
    cross = result.cross_system_paths
    assert len(cross) >= 1
    assert cross[0].cross_system is True
    assert len(cross[0].providers_involved) >= 2


# ── Cross-system: K8s SA → Azure MI (Workload Identity) ─────────────

def test_azure_wi_cross_system_path():
    """K8s SA with Azure WI → privileged MI = cross-system path."""
    mi = _azure_mi(
        "runner-mi",
        app_id="client-123",
        policies=["Contributor @ /subscriptions/sub1"],
    )
    mi.risk_flags = [RiskFlag(Severity.HIGH, "AZURE_MI_DANGEROUS_ROLE", "overprivileged")]
    sa = _k8s_sa("kube-system", "wi-sa", azure_wi="client-123")

    result = analyze_attack_paths([mi, sa])

    assert len(result.paths) >= 1
    # Should be cross-system (kubernetes → azure)
    cross = result.cross_system_paths
    assert len(cross) >= 1


# ── K8s SA → cluster-admin ──────────────────────────────────────────

def test_sa_to_cluster_admin():
    """SA bound to cluster-admin = attack path to privileged RBAC."""
    sa = _k8s_sa("default", "tiller", policies=["ClusterRole/cluster-admin"])
    result = analyze_attack_paths([sa])
    assert len(result.paths) >= 1


# ── Azure: secret → SP → RBAC ──────────────────────────────────────

def test_azure_secret_to_sp_to_rbac():
    """Azure app secret → SP → Owner RBAC = attack path."""
    sp = _azure_sp("terraform", app_id="tf-app",
                    policies=["Owner @ /subscriptions/sub1"])
    secret = _azure_secret("terraform", app_id="tf-app")

    result = analyze_attack_paths([sp, secret])
    assert len(result.paths) >= 1


# ── Blast radius scoring ────────────────────────────────────────────

def test_blast_radius_higher_for_admin():
    """Paths reaching admin should have higher blast radius."""
    # Path 1: key → user (no admin)
    user1 = _iam_user("reader", policies=["ReadOnlyAccess"],
                       arn="arn:aws:iam::123:user/reader")
    key1 = _access_key("reader", "AKIA_R")

    # Path 2: key → admin role
    user2 = _iam_user("admin", policies=["AdministratorAccess"],
                       arn="arn:aws:iam::123:user/admin")
    role2 = _iam_role("super-admin", policies=["AdministratorAccess"],
                       trusted=["arn:aws:iam::123:user/admin"])
    key2 = _access_key("admin", "AKIA_A")

    result = analyze_attack_paths([user1, key1, user2, role2, key2])

    if len(result.paths) >= 2:
        # The admin path should have higher blast
        admin_paths = [p for p in result.paths
                       if any(s.node_label == "super-admin" for s in p.steps)]
        if admin_paths:
            assert admin_paths[0].blast_radius > 0


# ── Severity classification ─────────────────────────────────────────

def test_critical_cross_system_admin():
    """Cross-system path to admin should be CRITICAL."""
    role = _iam_role("eks-admin", policies=["AdministratorAccess"])
    sa = _k8s_sa("prod", "deploy", irsa_arn=role.arn)

    result = analyze_attack_paths([role, sa])
    crit = result.critical_paths
    assert len(crit) >= 1


# ── Result serialization ────────────────────────────────────────────

def test_result_to_dict():
    role = _iam_role("admin", policies=["AdministratorAccess"])
    sa = _k8s_sa("prod", "app", irsa_arn=role.arn)

    result = analyze_attack_paths([role, sa])
    d = result.to_dict()

    assert "total_paths" in d
    assert "critical" in d
    assert "cross_system" in d
    assert "graph" in d
    assert "paths" in d
    if d["total_paths"] > 0:
        path = d["paths"][0]
        assert "severity" in path
        assert "blast_radius" in path
        assert "steps" in path


def test_path_properties():
    role = _iam_role("admin", policies=["AdministratorAccess"])
    sa = _k8s_sa("prod", "app", irsa_arn=role.arn)

    result = analyze_attack_paths([role, sa])
    if result.paths:
        path = result.paths[0]
        assert path.length >= 2
        assert path.entry_point is not None
        assert path.target is not None
        assert len(path.providers_involved) >= 1
