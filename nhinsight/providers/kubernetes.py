# MIT License — Copyright (c) 2026 cvemula1
# Kubernetes provider — discovers ServiceAccounts, RBAC, Secrets, Deployments, Pods, Annotations

from __future__ import annotations

import logging
from datetime import timezone
from typing import Dict, List, Set, Tuple

from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import Identity, IdentityType, Provider
from nhinsight.providers.base import BaseProvider

logger = logging.getLogger(__name__)

# Secret types that contain credentials / NHI material
CREDENTIAL_SECRET_TYPES = {
    "Opaque",
    "kubernetes.io/tls",
    "kubernetes.io/ssh-auth",
    "kubernetes.io/basic-auth",
    "kubernetes.io/dockerconfigjson",
    "kubernetes.io/dockercfg",
    "kubernetes.io/service-account-token",
}


class KubernetesProvider(BaseProvider):
    """Discover non-human identities in a Kubernetes cluster.

    Covers:
      1. ServiceAccounts           — all SAs across namespaces
      2. RoleBindings              — mapped to SAs as policies
      3. ClusterRoleBindings       — mapped to SAs as policies
      4. Secrets                   — credential-bearing secrets (Opaque, TLS, SA tokens, …)
      5. Deployments               — SA usage per deployment, flag default-SA usage
      6. Pods                      — active SA detection, pod-level SA mapping
      7. Annotations (IAM roles)   — IRSA, Workload Identity, Azure Workload Identity
    """

    name = "kubernetes"

    def __init__(self, config: NHInsightConfig):
        super().__init__(config)
        self._v1 = None
        self._apps_v1 = None
        self._rbac_v1 = None

    def _load_config(self):
        """Load kubeconfig and create API clients."""
        from kubernetes import client
        from kubernetes import config as k8s_config

        try:
            kube_kwargs = {}
            if self.config.kubeconfig:
                kube_kwargs["config_file"] = self.config.kubeconfig
            if self.config.kube_context:
                kube_kwargs["context"] = self.config.kube_context

            if kube_kwargs:
                k8s_config.load_kube_config(**kube_kwargs)
            else:
                try:
                    k8s_config.load_incluster_config()
                except k8s_config.ConfigException:
                    k8s_config.load_kube_config()
        except Exception as e:
            raise RuntimeError(f"Failed to load kubeconfig: {e}") from e

        self._v1 = client.CoreV1Api()
        self._apps_v1 = client.AppsV1Api()
        self._rbac_v1 = client.RbacAuthorizationV1Api()

    def is_available(self) -> bool:
        try:
            self._load_config()
            self._v1.list_namespace(limit=1)
            return True
        except Exception:
            return False

    # ── helpers ──────────────────────────────────────────────────────

    def _namespaces(self) -> List[str]:
        if self.config.kube_namespace:
            return [self.config.kube_namespace]
        ns_list = self._v1.list_namespace()
        return [ns.metadata.name for ns in ns_list.items]

    # ── main entry point ────────────────────────────────────────────

    def discover(self) -> List[Identity]:
        """Discover all K8s NHIs: ServiceAccounts, RBAC, Secrets, Deployments, Pods, Annotations."""
        identities: List[Identity] = []

        try:
            self._load_config()
            context = self.config.kube_context or "current"
            namespaces = self._namespaces()
            logger.info("Scanning K8s cluster (context: %s, namespaces: %d)", context, len(namespaces))

            # 1. ServiceAccounts
            service_accounts = self._discover_service_accounts(context, namespaces)

            # 2+3. RoleBindings + ClusterRoleBindings → map to SAs
            rbac_map = self._build_rbac_map()

            # 5. Deployments → map SA usage
            deploy_sa_map, deploy_default_sa = self._discover_deployments(context, namespaces)

            # 6. Pods → active SA detection
            active_sas, pod_sa_counts = self._discover_pods(namespaces)

            # Enrich SAs with RBAC, orphan status, deployment info, pod counts
            for sa in service_accounts:
                ns = sa.raw.get("namespace", "")
                sa_name = sa.raw.get("sa_name", "")
                sa_key = f"{ns}/{sa_name}"

                sa.policies = rbac_map.get(sa_key, [])
                sa.raw["orphaned"] = sa_key not in active_sas
                sa.raw["pod_count"] = pod_sa_counts.get(sa_key, 0)
                sa.raw["deployments"] = deploy_sa_map.get(sa_key, [])
                sa.raw["used_as_default_by_deployments"] = deploy_default_sa.get(sa_key, [])

            identities.extend(service_accounts)

            # 4. Secrets (credential-bearing)
            identities.extend(self._discover_secrets(context, namespaces))

        except ImportError:
            logger.error("kubernetes package not installed. Run: pip install kubernetes")
        except Exception as e:
            logger.error("Kubernetes discovery failed: %s", e)

        return identities

    # ── 1. ServiceAccounts ──────────────────────────────────────────

    def _discover_service_accounts(self, context: str, namespaces: List[str]) -> List[Identity]:
        identities: List[Identity] = []

        for ns in namespaces:
            try:
                sa_list = self._v1.list_namespaced_service_account(namespace=ns)
                for sa in sa_list.items:
                    sa_name = sa.metadata.name
                    created = sa.metadata.creation_timestamp
                    if created and created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)

                    secret_count = len(sa.secrets) if sa.secrets else 0
                    automount = sa.automount_service_account_token
                    if automount is None:
                        automount = True  # K8s default

                    annotations = dict(sa.metadata.annotations or {})
                    labels = dict(sa.metadata.labels or {})

                    # 7. Annotations — IAM role bindings
                    owner = annotations.get("nhinsight.io/owner", "") or annotations.get("owner", "")
                    irsa_role = annotations.get("eks.amazonaws.com/role-arn", "")
                    wi_gcp = annotations.get("iam.gke.io/gcp-service-account", "")
                    wi_azure = annotations.get(
                        "azure.workload.identity/client-id", ""
                    )

                    # Build permissions list from IAM annotations
                    iam_permissions: List[str] = []
                    if irsa_role:
                        iam_permissions.append(f"aws-irsa:{irsa_role}")
                    if wi_gcp:
                        iam_permissions.append(f"gcp-wi:{wi_gcp}")
                    if wi_azure:
                        iam_permissions.append(f"azure-wi:{wi_azure}")

                    ident = Identity(
                        id=f"k8s:sa:{context}:{ns}:{sa_name}",
                        name=f"{ns}/{sa_name}",
                        provider=Provider.KUBERNETES,
                        identity_type=IdentityType.SERVICE_ACCOUNT,
                        created_at=created,
                        owner=owner,
                        permissions=iam_permissions,
                        raw={
                            "namespace": ns,
                            "sa_name": sa_name,
                            "secret_count": secret_count,
                            "automount_token": automount,
                            "irsa_role_arn": irsa_role,
                            "workload_identity_gcp": wi_gcp,
                            "workload_identity_azure": wi_azure,
                            "annotations": annotations,
                            "labels": labels,
                        },
                    )
                    identities.append(ident)

            except Exception as e:
                logger.warning("Failed to list service accounts in %s: %s", ns, e)

        logger.info("Found %d service accounts", len(identities))
        return identities

    # ── 2+3. RoleBindings + ClusterRoleBindings ─────────────────────

    def _build_rbac_map(self) -> Dict[str, List[str]]:
        """Map ServiceAccount (ns/name) -> list of bound role names."""
        rbac_map: Dict[str, List[str]] = {}

        # ClusterRoleBindings
        try:
            crb_list = self._rbac_v1.list_cluster_role_binding()
            for crb in crb_list.items:
                role_name = crb.role_ref.name if crb.role_ref else ""
                for subject in (crb.subjects or []):
                    if subject.kind == "ServiceAccount":
                        sa_key = f"{subject.namespace or 'default'}/{subject.name}"
                        rbac_map.setdefault(sa_key, []).append(f"ClusterRole/{role_name}")
        except Exception as e:
            logger.warning("Failed to list ClusterRoleBindings: %s", e)

        # RoleBindings
        try:
            rb_list = self._rbac_v1.list_role_binding_for_all_namespaces()
            for rb in rb_list.items:
                role_ref = rb.role_ref
                role_kind = role_ref.kind if role_ref else "Role"
                role_name = role_ref.name if role_ref else ""
                ns = rb.metadata.namespace or "default"
                for subject in (rb.subjects or []):
                    if subject.kind == "ServiceAccount":
                        sa_ns = subject.namespace or ns
                        sa_key = f"{sa_ns}/{subject.name}"
                        rbac_map.setdefault(sa_key, []).append(f"{role_kind}/{role_name}")
        except Exception as e:
            logger.warning("Failed to list RoleBindings: %s", e)

        return rbac_map

    # ── 4. Secrets ──────────────────────────────────────────────────

    def _discover_secrets(self, context: str, namespaces: List[str]) -> List[Identity]:
        """Discover credential-bearing Secrets (Opaque, TLS, SA tokens, docker configs)."""
        identities: List[Identity] = []

        for ns in namespaces:
            try:
                secret_list = self._v1.list_namespaced_secret(namespace=ns)
                for secret in secret_list.items:
                    secret_type = secret.type or "Opaque"
                    if secret_type not in CREDENTIAL_SECRET_TYPES:
                        continue

                    secret_name = secret.metadata.name
                    created = secret.metadata.creation_timestamp
                    if created and created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)

                    annotations = dict(secret.metadata.annotations or {})
                    labels = dict(secret.metadata.labels or {})
                    owner = annotations.get("nhinsight.io/owner", "") or annotations.get("owner", "")

                    # Detect what SA owns this token (if SA token type)
                    sa_name = annotations.get("kubernetes.io/service-account.name", "")

                    # Data keys (don't read values — just key names for classification)
                    data_keys = list((secret.data or {}).keys())

                    ident = Identity(
                        id=f"k8s:secret:{context}:{ns}:{secret_name}",
                        name=f"{ns}/{secret_name}",
                        provider=Provider.KUBERNETES,
                        identity_type=IdentityType.K8S_SECRET,
                        created_at=created,
                        owner=owner or sa_name,
                        raw={
                            "namespace": ns,
                            "secret_name": secret_name,
                            "secret_type": secret_type,
                            "data_keys": data_keys,
                            "service_account": sa_name,
                            "annotations": annotations,
                            "labels": labels,
                            "managed_by": labels.get("app.kubernetes.io/managed-by", ""),
                        },
                    )
                    identities.append(ident)

            except Exception as e:
                logger.warning("Failed to list secrets in %s: %s", ns, e)

        logger.info("Found %d credential-bearing secrets", len(identities))
        return identities

    # ── 5. Deployments ──────────────────────────────────────────────

    def _discover_deployments(
        self, context: str, namespaces: List[str]
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """Map which Deployments use which ServiceAccounts.

        Returns:
            deploy_sa_map: {sa_key: [deployment_names]}
            deploy_default_sa: {sa_key: [deployment_names]} for deployments using the default SA
        """
        deploy_sa_map: Dict[str, List[str]] = {}
        deploy_default_sa: Dict[str, List[str]] = {}

        for ns in namespaces:
            try:
                dep_list = self._apps_v1.list_namespaced_deployment(namespace=ns)
                for dep in dep_list.items:
                    dep_name = dep.metadata.name
                    spec = dep.spec.template.spec if dep.spec and dep.spec.template else None
                    if not spec:
                        continue

                    sa_name = spec.service_account_name or "default"
                    sa_key = f"{ns}/{sa_name}"
                    deploy_sa_map.setdefault(sa_key, []).append(dep_name)

                    # Track deployments that rely on the namespace default SA
                    if not spec.service_account_name or spec.service_account_name == "default":
                        deploy_default_sa.setdefault(f"{ns}/default", []).append(dep_name)

            except Exception as e:
                logger.warning("Failed to list deployments in %s: %s", ns, e)

        return deploy_sa_map, deploy_default_sa

    # ── 6. Pods ─────────────────────────────────────────────────────

    def _discover_pods(
        self, namespaces: List[str]
    ) -> Tuple[Set[str], Dict[str, int]]:
        """Discover running pods to determine active SAs and per-SA pod counts.

        Returns:
            active_sas:    set of SA keys (ns/name) with running pods
            pod_sa_counts: {sa_key: number_of_pods}
        """
        active_sas: Set[str] = set()
        pod_sa_counts: Dict[str, int] = {}

        try:
            if self.config.kube_namespace:
                pod_list = self._v1.list_namespaced_pod(namespace=self.config.kube_namespace)
            else:
                pod_list = self._v1.list_pod_for_all_namespaces()

            for pod in pod_list.items:
                ns = pod.metadata.namespace or "default"
                sa = pod.spec.service_account_name or "default"
                sa_key = f"{ns}/{sa}"
                active_sas.add(sa_key)
                pod_sa_counts[sa_key] = pod_sa_counts.get(sa_key, 0) + 1

        except Exception as e:
            logger.warning("Failed to list pods: %s", e)

        return active_sas, pod_sa_counts
