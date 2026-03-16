# MIT License — Copyright (c) 2026 cvemula1
# Tests for Identity Graph construction

from nhinsight.analyzers.graph import (
    EdgeType,
    build_graph,
)
from nhinsight.core.models import (
    Identity,
    IdentityType,
    Provider,
)


def _iam_user(name, policies=None, **kw):
    return Identity(
        id=f"aws:iam:user:123:{name}",
        name=name,
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
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


def _k8s_secret(ns, name, sa_name=""):
    return Identity(
        id=f"k8s:secret:ctx:{ns}:{name}",
        name=f"{ns}/{name}",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.K8S_SECRET,
        raw={
            "namespace": ns,
            "secret_name": name,
            "service_account": sa_name,
            "secret_type": "Opaque",
            "data_keys": ["PASSWORD"],
        },
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


# ── Basic graph construction ────────────────────────────────────────

def test_empty_graph():
    graph = build_graph([])
    assert len(graph.nodes) == 0
    assert len(graph.edges) == 0


def test_single_identity():
    graph = build_graph([_iam_user("deploy-bot")])
    assert len(graph.nodes) == 1
    assert graph.nodes["aws:iam:user:123:deploy-bot"].label == "deploy-bot"


# ── AWS edges ───────────────────────────────────────────────────────

def test_user_to_access_key_edge():
    """Edge direction: key → user (attacker steals key, acts as user)."""
    user = _iam_user("deploy-bot")
    key = _access_key("deploy-bot")
    graph = build_graph([user, key])
    assert len(graph.edges) == 1
    assert graph.edges[0].edge_type == EdgeType.OWNS_KEY
    assert graph.edges[0].source_id == key.id
    assert graph.edges[0].target_id == user.id


def test_role_trust_edge():
    user = _iam_user("ci-bot")
    role = _iam_role(
        "deploy-prod",
        policies=["AdministratorAccess"],
        trusted=[user.arn or "arn:aws:iam::123:user/ci-bot"],
    )
    # Need to set the user ARN
    user.arn = "arn:aws:iam::123:user/ci-bot"
    graph = build_graph([user, role])
    trust_edges = [e for e in graph.edges if e.edge_type == EdgeType.ASSUMES_ROLE]
    assert len(trust_edges) == 1
    assert trust_edges[0].source_id == user.id
    assert trust_edges[0].target_id == role.id


# ── K8s → AWS IRSA edge ────────────────────────────────────────────

def test_irsa_edge_with_matching_role():
    role = _iam_role("eks-deploy", policies=["AmazonS3FullAccess"])
    sa = _k8s_sa("prod", "app-sa", irsa_arn=role.arn)
    graph = build_graph([role, sa])
    irsa_edges = [e for e in graph.edges if e.edge_type == EdgeType.IRSA_MAPS_TO]
    assert len(irsa_edges) == 1
    assert irsa_edges[0].source_id == sa.id
    assert irsa_edges[0].target_id == role.id


def test_irsa_edge_synthetic_role():
    """When the AWS role isn't in scan data, create a synthetic node."""
    sa = _k8s_sa("prod", "app-sa", irsa_arn="arn:aws:iam::999:role/external")
    graph = build_graph([sa])
    irsa_edges = [e for e in graph.edges if e.edge_type == EdgeType.IRSA_MAPS_TO]
    assert len(irsa_edges) == 1
    # Synthetic node should exist
    synth_id = irsa_edges[0].target_id
    assert synth_id in graph.nodes
    assert graph.nodes[synth_id].metadata.get("synthetic") is True


# ── K8s → Azure WI edge ────────────────────────────────────────────

def test_azure_wi_edge():
    mi = _azure_mi("runner-mi", app_id="client-123",
                    policies=["Contributor @ /subscriptions/sub1"])
    sa = _k8s_sa("kube-system", "wi-sa", azure_wi="client-123")
    graph = build_graph([mi, sa])
    wi_edges = [e for e in graph.edges if e.edge_type == EdgeType.AZURE_WI_MAPS_TO]
    assert len(wi_edges) == 1
    assert wi_edges[0].source_id == sa.id
    assert wi_edges[0].target_id == mi.id


def test_azure_wi_synthetic():
    sa = _k8s_sa("kube-system", "wi-sa", azure_wi="unknown-client-id")
    graph = build_graph([sa])
    wi_edges = [e for e in graph.edges if e.edge_type == EdgeType.AZURE_WI_MAPS_TO]
    assert len(wi_edges) == 1
    synth_id = wi_edges[0].target_id
    assert graph.nodes[synth_id].metadata.get("synthetic") is True


# ── K8s RBAC edge ───────────────────────────────────────────────────

def test_rbac_binding_edge():
    sa = _k8s_sa("prod", "deploy-sa", policies=["ClusterRole/cluster-admin"])
    graph = build_graph([sa])
    rbac_edges = [e for e in graph.edges if e.edge_type == EdgeType.BOUND_TO_RBAC]
    assert len(rbac_edges) == 1
    role_id = rbac_edges[0].target_id
    assert graph.nodes[role_id].is_privileged is True


# ── K8s secret → SA edge ───────────────────────────────────────────

def test_secret_to_sa_edge():
    sa = _k8s_sa("prod", "app-sa")
    secret = _k8s_secret("prod", "app-token", sa_name="app-sa")
    graph = build_graph([sa, secret])
    sec_edges = [e for e in graph.edges if e.edge_type == EdgeType.USES_SECRET]
    assert len(sec_edges) == 1
    assert sec_edges[0].source_id == secret.id
    assert sec_edges[0].target_id == sa.id


# ── Azure edges ─────────────────────────────────────────────────────

def test_azure_rbac_edge():
    sp = _azure_sp("terraform", app_id="tf-app",
                    policies=["Owner @ /subscriptions/sub1"])
    graph = build_graph([sp])
    rbac_edges = [e for e in graph.edges if e.edge_type == EdgeType.AZURE_RBAC]
    assert len(rbac_edges) == 1


def test_azure_app_secret_edge():
    sp = _azure_sp("my-app", app_id="app-123")
    secret = _azure_secret("my-app", app_id="app-123")
    graph = build_graph([sp, secret])
    sec_edges = [e for e in graph.edges if e.edge_type == EdgeType.APP_HAS_SECRET]
    assert len(sec_edges) == 1
    assert sec_edges[0].source_id == secret.id
    assert sec_edges[0].target_id == sp.id


# ── Privileged / entry point classification ─────────────────────────

def test_admin_user_is_privileged():
    user = _iam_user("admin", policies=["AdministratorAccess"])
    graph = build_graph([user])
    assert graph.nodes[user.id].is_privileged is True


def test_access_key_is_entry_point():
    key = _access_key("bot", "AKIA9999")
    graph = build_graph([key])
    assert graph.nodes[key.id].is_entry_point is True


def test_sa_with_irsa_is_entry_point():
    sa = _k8s_sa("prod", "irsa-sa", irsa_arn="arn:aws:iam::123:role/x")
    graph = build_graph([sa])
    assert graph.nodes[sa.id].is_entry_point is True


# ── Graph stats ─────────────────────────────────────────────────────

def test_graph_to_dict():
    user = _iam_user("bot", policies=["AdministratorAccess"])
    key = _access_key("bot")
    graph = build_graph([user, key])
    d = graph.to_dict()
    assert d["nodes"] == 2
    assert d["edges"] == 1
    assert d["entry_points"] >= 1
    assert d["privileged_nodes"] >= 1
