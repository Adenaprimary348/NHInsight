# MIT License — Copyright (c) 2026 cvemula1
# Tests for GCP identity graph construction and attack paths

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from nhinsight.analyzers.attack_paths import analyze_attack_paths
from nhinsight.analyzers.graph import EdgeType, build_graph
from nhinsight.core.models import (
    Identity,
    IdentityType,
    Provider,
    RiskFlag,
    Severity,
)


def _gcp_sa(
    name: str = "test-sa",
    policies: list | None = None,
    email: str | None = None,
    risk_flags: list | None = None,
) -> Identity:
    email = email or f"{name}@my-project.iam.gserviceaccount.com"
    return Identity(
        id=f"gcp:sa:my-project:{email}",
        name=name,
        provider=Provider.GCP,
        identity_type=IdentityType.GCP_SERVICE_ACCOUNT,
        arn=email,
        policies=policies or [],
        risk_flags=risk_flags or [],
        raw={
            "email": email,
            "display_name": name,
            "unique_id": "1000001",
            "disabled": False,
            "project_id": "my-project",
            "gcp_managed": False,
        },
    )


def _gcp_key(
    key_id: str = "key001",
    sa_email: str = "test-sa@my-project.iam.gserviceaccount.com",
) -> Identity:
    now = datetime.now(timezone.utc)
    sa_name = sa_email.split("@")[0]
    return Identity(
        id=f"gcp:sa_key:my-project:{key_id}",
        name=f"{sa_name}/key:{key_id[:8]}",
        provider=Provider.GCP,
        identity_type=IdentityType.GCP_SA_KEY,
        arn=sa_email,
        created_at=now - timedelta(days=100),
        raw={
            "key_id": key_id,
            "key_type": "USER_MANAGED",
            "sa_email": sa_email,
            "project_id": "my-project",
            "disabled": False,
        },
    )


def _k8s_sa(
    name: str = "app-sa",
    namespace: str = "default",
    wi_gcp: str = "",
) -> Identity:
    return Identity(
        id=f"k8s:sa:ctx:{namespace}:{name}",
        name=f"{namespace}/{name}",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        raw={
            "namespace": namespace,
            "sa_name": name,
            "workload_identity_gcp": wi_gcp,
        },
    )


# ── Graph construction tests ───────────────────────────────────────


def test_gcp_sa_node_created():
    sa = _gcp_sa()
    graph = build_graph([sa])
    assert sa.id in graph.nodes


def test_gcp_sa_is_entry_point():
    sa = _gcp_sa()
    graph = build_graph([sa])
    assert graph.nodes[sa.id].is_entry_point


def test_gcp_key_to_sa_edge():
    sa = _gcp_sa(name="deploy-sa")
    key = _gcp_key(
        sa_email="deploy-sa@my-project.iam.gserviceaccount.com"
    )
    graph = build_graph([sa, key])
    edges = [e for e in graph.edges if e.edge_type == EdgeType.GCP_SA_HAS_KEY]
    assert len(edges) == 1
    assert edges[0].source_id == key.id
    assert edges[0].target_id == sa.id


def test_gcp_key_synthetic_sa_node():
    """Key referencing SA not in scan → synthetic node created."""
    key = _gcp_key(sa_email="missing@other-project.iam.gserviceaccount.com")
    graph = build_graph([key])
    edges = [e for e in graph.edges if e.edge_type == EdgeType.GCP_SA_HAS_KEY]
    assert len(edges) == 1
    # Synthetic node should exist
    synth_id = edges[0].target_id
    assert synth_id in graph.nodes
    assert graph.nodes[synth_id].node_type == "gcp_service_account"


def test_gcp_sa_iam_binding_edge():
    sa = _gcp_sa(policies=["roles/storage.admin", "roles/viewer"])
    graph = build_graph([sa])
    iam_edges = [
        e for e in graph.edges if e.edge_type == EdgeType.GCP_IAM_BINDING
    ]
    assert len(iam_edges) == 2


def test_gcp_dangerous_role_creates_privileged_node():
    sa = _gcp_sa(policies=["roles/owner"])
    graph = build_graph([sa])
    iam_edges = [
        e for e in graph.edges if e.edge_type == EdgeType.GCP_IAM_BINDING
    ]
    assert len(iam_edges) == 1
    role_node = graph.nodes[iam_edges[0].target_id]
    assert role_node.is_privileged


def test_gcp_safe_role_not_privileged():
    sa = _gcp_sa(policies=["roles/viewer"])
    graph = build_graph([sa])
    iam_edges = [
        e for e in graph.edges if e.edge_type == EdgeType.GCP_IAM_BINDING
    ]
    assert len(iam_edges) == 1
    role_node = graph.nodes[iam_edges[0].target_id]
    assert not role_node.is_privileged


def test_k8s_sa_to_gcp_sa_wi_edge():
    gcp_sa = _gcp_sa(name="workload-sa")
    k8s_sa = _k8s_sa(
        wi_gcp="workload-sa@my-project.iam.gserviceaccount.com"
    )
    graph = build_graph([gcp_sa, k8s_sa])
    wi_edges = [
        e for e in graph.edges if e.edge_type == EdgeType.GCP_WI_MAPS_TO
    ]
    assert len(wi_edges) == 1
    assert wi_edges[0].source_id == k8s_sa.id
    assert wi_edges[0].target_id == gcp_sa.id


def test_k8s_sa_to_gcp_sa_wi_synthetic():
    """K8s SA references GCP SA not in scan → synthetic."""
    k8s_sa = _k8s_sa(
        wi_gcp="absent@other-project.iam.gserviceaccount.com"
    )
    graph = build_graph([k8s_sa])
    wi_edges = [
        e for e in graph.edges if e.edge_type == EdgeType.GCP_WI_MAPS_TO
    ]
    assert len(wi_edges) == 1
    synth_id = wi_edges[0].target_id
    assert synth_id in graph.nodes


# ── Attack path tests ──────────────────────────────────────────────


def test_gcp_key_to_owner_attack_path():
    """SA key → SA → roles/owner should produce a CRITICAL attack path."""
    sa = _gcp_sa(
        name="admin-sa",
        policies=["roles/owner"],
        risk_flags=[
            RiskFlag(Severity.CRITICAL, "GCP_SA_DANGEROUS_ROLE",
                     "Service account has roles/owner", ""),
        ],
    )
    key = _gcp_key(
        sa_email="admin-sa@my-project.iam.gserviceaccount.com"
    )
    result = analyze_attack_paths([sa, key])
    assert len(result.paths) > 0
    # Should find at least one critical/high path
    critical_or_high = [
        p for p in result.paths
        if p.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert len(critical_or_high) > 0


def test_k8s_to_gcp_cross_system_path():
    """K8s SA → GCP SA (WI) → roles/owner = cross-system path."""
    gcp_sa = _gcp_sa(
        name="gke-workload",
        policies=["roles/owner"],
        risk_flags=[
            RiskFlag(Severity.CRITICAL, "GCP_SA_DANGEROUS_ROLE",
                     "Service account has roles/owner", ""),
        ],
    )
    k8s_sa = _k8s_sa(
        name="my-app",
        namespace="prod",
        wi_gcp="gke-workload@my-project.iam.gserviceaccount.com",
    )
    result = analyze_attack_paths([gcp_sa, k8s_sa])
    assert len(result.paths) > 0
    cross = [p for p in result.paths if p.cross_system]
    assert len(cross) > 0


def test_no_paths_for_safe_sa():
    """SA with roles/viewer should produce no attack paths."""
    sa = _gcp_sa(policies=["roles/viewer"])
    result = analyze_attack_paths([sa])
    assert len(result.paths) == 0


def test_gcp_attack_path_has_recommendation():
    sa = _gcp_sa(
        name="deployer",
        policies=["roles/editor"],
        risk_flags=[
            RiskFlag(Severity.CRITICAL, "GCP_SA_DANGEROUS_ROLE",
                     "Service account has roles/editor", ""),
        ],
    )
    key = _gcp_key(
        sa_email="deployer@my-project.iam.gserviceaccount.com"
    )
    result = analyze_attack_paths([sa, key])
    for path in result.paths:
        assert path.recommendation  # non-empty recommendation


def test_gcp_result_serialization():
    sa = _gcp_sa(
        name="admin",
        policies=["roles/owner"],
        risk_flags=[
            RiskFlag(Severity.CRITICAL, "GCP_SA_DANGEROUS_ROLE",
                     "Service account has roles/owner", ""),
        ],
    )
    result = analyze_attack_paths([sa])
    d = result.to_dict()
    assert "total_paths" in d
    assert "paths" in d
    assert isinstance(d["paths"], list)
