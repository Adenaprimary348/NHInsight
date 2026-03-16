# MIT License — Copyright (c) 2026 cvemula1
# Classify identities as human or machine (rule-based, ML layer added later)

from __future__ import annotations

from typing import List

from nhinsight.core.models import Classification, Identity, IdentityType, Provider

# Name prefixes that strongly indicate a machine identity
MACHINE_PREFIXES = (
    "svc-", "svc_", "service-", "service_",
    "bot-", "bot_",
    "deploy-", "deploy_",
    "ci-", "ci_", "cd-", "cd_",
    "automation-", "automation_",
    "pipeline-", "pipeline_",
    "terraform-", "terraform_",
    "github-actions", "github_actions",
    "lambda-", "lambda_",
    "ecs-task", "ecs_task",
    "eks-", "eks_",
    "gha-", "gha_",
    "jenkins-", "jenkins_",
    "argocd-", "argocd_",
    "flux-", "flux_",
    "system:", "kube-",
    "cronjob-", "cron-",
    "backup-", "monitoring-",
    "prometheus-", "grafana-",
    "alertmanager-",
    "external-secrets",
    "cert-manager",
    "ingress-nginx",
    "coredns",
)

# Name patterns that indicate a human
HUMAN_INDICATORS = (
    "@",            # email-like
    ".",            # first.last format
)


def classify_identities(identities: List[Identity]) -> List[Identity]:
    """Classify each identity as human, machine, or unknown.

    Uses a rule-based approach:
    1. Certain identity types are always machine (access keys, roles, SAs, apps)
    2. IAM users: check name patterns, console access, MFA
    3. Fall back to unknown if unsure
    """
    for ident in identities:
        ident.classification = _classify_single(ident)
    return identities


def _classify_single(ident: Identity) -> Classification:
    """Classify a single identity."""

    # Types that are always machine
    always_machine = {
        IdentityType.ACCESS_KEY,
        IdentityType.IAM_ROLE,
        IdentityType.SERVICE_ACCOUNT,
        IdentityType.K8S_SECRET,
        IdentityType.GITHUB_APP,
        IdentityType.DEPLOY_KEY,
        IdentityType.WEBHOOK,
        IdentityType.OAUTH_APP,
        IdentityType.AZURE_SP,
        IdentityType.AZURE_MANAGED_IDENTITY,
        IdentityType.AZURE_APP_SECRET,
        IdentityType.AZURE_APP_CERT,
        IdentityType.GCP_SERVICE_ACCOUNT,
        IdentityType.GCP_SA_KEY,
    }
    if ident.identity_type in always_machine:
        return Classification.MACHINE

    # For IAM users and PATs, use heuristics
    name_lower = ident.name.lower()

    # Score-based approach
    machine_score = 0
    human_score = 0

    # Machine name patterns
    if any(name_lower.startswith(p) for p in MACHINE_PREFIXES):
        machine_score += 3

    if any(kw in name_lower for kw in ("service", "bot", "automation", "pipeline", "deploy", "system")):
        machine_score += 2

    # Human name patterns
    if any(ind in ident.name for ind in HUMAN_INDICATORS):
        human_score += 2

    # AWS-specific signals
    if ident.provider == Provider.AWS:
        has_console = ident.raw.get("has_console_access", False)
        has_mfa = ident.raw.get("has_mfa", False)

        if has_console:
            human_score += 3
        if has_mfa:
            human_score += 2

        # No console + no MFA strongly suggests machine
        if not has_console and not has_mfa:
            machine_score += 2

    # Decide
    if machine_score > human_score:
        return Classification.MACHINE
    elif human_score > machine_score:
        return Classification.HUMAN

    return Classification.UNKNOWN
