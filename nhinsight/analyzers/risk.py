# MIT License — Copyright (c) 2026 cvemula1
# Risk analysis for discovered identities

from __future__ import annotations

from typing import List

from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import (
    Identity,
    IdentityType,
    Provider,
    RiskFlag,
    Severity,
)

# Policies that grant dangerous levels of access
ADMIN_POLICIES = {
    "AdministratorAccess",
    "PowerUserAccess",
    "IAMFullAccess",
    "AmazonS3FullAccess",
    "AmazonEC2FullAccess",
}

CLUSTER_ADMIN_BINDINGS = {
    "cluster-admin",
    "ClusterRole/cluster-admin",
}


def analyze_risk(identities: List[Identity], config: NHInsightConfig) -> List[Identity]:
    """Run all risk checks against discovered identities and attach RiskFlags."""
    for ident in identities:
        # Preserve risk flags set by upstream scanners (e.g. workflow_scanner)
        preserved = [f for f in ident.risk_flags
                     if f.code.startswith("GH_OIDC_") or f.code.startswith("GH_WF_")]
        ident.risk_flags = preserved

        if ident.provider == Provider.AWS:
            _check_aws_risks(ident, config)
        elif ident.provider == Provider.AZURE:
            _check_azure_risks(ident, config)
        elif ident.provider == Provider.KUBERNETES:
            if ident.identity_type == IdentityType.K8S_SECRET:
                _check_k8s_secret_risks(ident, config)
            else:
                _check_k8s_risks(ident, config)
        elif ident.provider == Provider.GCP:
            _check_gcp_risks(ident, config)
        elif ident.provider == Provider.GITHUB:
            _check_github_risks(ident, config)

        # Universal checks
        _check_stale(ident, config)
        _check_no_owner(ident)

    return identities


def _check_aws_risks(ident: Identity, config: NHInsightConfig) -> None:
    """AWS-specific risk checks."""

    # Overprivileged — admin policies
    for policy in ident.policies:
        policy_name = policy.split("/")[-1] if "/" in policy else policy
        if policy_name in ADMIN_POLICIES:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.CRITICAL,
                code="AWS_ADMIN_ACCESS",
                message=f"Has {policy_name} policy attached",
                detail="This grants near-unlimited access to the AWS account. "
                       "Scope down to only the permissions actually needed.",
            ))

    # Access key never rotated
    if ident.identity_type == IdentityType.ACCESS_KEY:
        age = ident.age_days
        if age is not None and age > config.rotation_max_days:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.HIGH,
                code="AWS_KEY_NOT_ROTATED",
                message=f"Access key is {age} days old (max {config.rotation_max_days})",
                detail="Access keys should be rotated regularly. Consider using "
                       "IAM roles with temporary credentials (OIDC/IRSA) instead.",
            ))

        # Inactive key
        status = ident.raw.get("status", "")
        if status == "Inactive":
            ident.risk_flags.append(RiskFlag(
                severity=Severity.MEDIUM,
                code="AWS_KEY_INACTIVE",
                message="Access key is inactive but not deleted",
                detail="Inactive keys should be deleted if no longer needed.",
            ))

    # IAM user without MFA
    if ident.identity_type == IdentityType.IAM_USER:
        has_console = ident.raw.get("has_console_access", False)
        has_mfa = ident.raw.get("has_mfa", False)
        if has_console and not has_mfa:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.HIGH,
                code="AWS_NO_MFA",
                message="Console access enabled without MFA",
                detail="Any IAM user with console access should have MFA enabled.",
            ))

    # IAM role with wildcard trust
    if ident.identity_type == IdentityType.IAM_ROLE:
        trusted = ident.raw.get("trusted_principals", [])
        if "*" in trusted:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.CRITICAL,
                code="AWS_WILDCARD_TRUST",
                message="Role trust policy allows any AWS principal (*)",
                detail="Any AWS account can assume this role. Restrict the trust "
                       "policy to specific accounts or services.",
            ))


AZURE_DANGEROUS_ROLES = {
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Key Vault Administrator",
}


def _check_azure_risks(ident: Identity, config: NHInsightConfig) -> None:
    """Azure-specific risk checks."""

    # Service Principal with Owner/Contributor at subscription scope
    if ident.identity_type == IdentityType.AZURE_SP:
        for role_str in ident.policies:
            role_name = role_str.split(" @ ")[0] if " @ " in role_str else role_str
            scope = role_str.split(" @ ")[1] if " @ " in role_str else ""

            if role_name in AZURE_DANGEROUS_ROLES:
                # Subscription-level or above is critical
                is_sub_scope = (
                    scope.startswith("/subscriptions/")
                    and scope.count("/") <= 2
                ) or scope == "/"

                if is_sub_scope:
                    ident.risk_flags.append(RiskFlag(
                        severity=Severity.CRITICAL,
                        code="AZURE_SP_DANGEROUS_ROLE",
                        message=f"SP has {role_name} at subscription scope",
                        detail=f"Grants broad {role_name} access across the entire subscription. "
                               "Scope down to a specific resource group.",
                    ))
                else:
                    ident.risk_flags.append(RiskFlag(
                        severity=Severity.MEDIUM,
                        code="AZURE_SP_ELEVATED_ROLE",
                        message=f"SP has {role_name} role",
                        detail=f"{role_name} at resource group level. "
                               "Review if this scope is still needed.",
                    ))

        # Disabled SP with role assignments
        if not ident.raw.get("enabled", True) and ident.policies:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.MEDIUM,
                code="AZURE_SP_DISABLED_WITH_ROLES",
                message="Disabled SP still has active RBAC role assignments",
                detail="Remove role assignments from disabled service principals.",
            ))

    # Managed Identity — check for overprivilege
    if ident.identity_type == IdentityType.AZURE_MANAGED_IDENTITY:
        for role_str in ident.policies:
            role_name = role_str.split(" @ ")[0] if " @ " in role_str else role_str
            scope = role_str.split(" @ ")[1] if " @ " in role_str else ""

            if role_name in AZURE_DANGEROUS_ROLES:
                is_sub_scope = (
                    scope.startswith("/subscriptions/")
                    and scope.count("/") <= 2
                ) or scope == "/"

                if is_sub_scope:
                    ident.risk_flags.append(RiskFlag(
                        severity=Severity.HIGH,
                        code="AZURE_MI_DANGEROUS_ROLE",
                        message=f"Managed Identity has {role_name} at subscription scope",
                        detail="Scope the role assignment to a specific resource group.",
                    ))

    # App credentials — check expiry
    if ident.identity_type in (IdentityType.AZURE_APP_SECRET, IdentityType.AZURE_APP_CERT):
        _check_azure_credential_risks(ident, config)


def _check_azure_credential_risks(ident: Identity, config: NHInsightConfig) -> None:
    """Risk checks for Azure app secrets and certificates."""
    from datetime import datetime
    from datetime import timezone as tz

    expires_str = ident.raw.get("expires_at")
    if expires_str:
        try:
            expires_at = datetime.fromisoformat(expires_str)
            now = datetime.now(tz.utc)
            days_until_expiry = (expires_at - now).days

            if days_until_expiry < 0:
                ident.risk_flags.append(RiskFlag(
                    severity=Severity.HIGH,
                    code="AZURE_CRED_EXPIRED",
                    message=f"Credential expired {abs(days_until_expiry)} days ago",
                    detail="Expired credentials should be deleted. If still in use, "
                           "rotate immediately.",
                ))
            elif days_until_expiry < 30:
                ident.risk_flags.append(RiskFlag(
                    severity=Severity.MEDIUM,
                    code="AZURE_CRED_EXPIRING_SOON",
                    message=f"Credential expires in {days_until_expiry} days",
                    detail="Rotate this credential before it expires to avoid outages.",
                ))
        except (ValueError, TypeError):
            pass

    # Client secret age check
    if ident.identity_type == IdentityType.AZURE_APP_SECRET:
        age = ident.age_days
        if age is not None and age > config.rotation_max_days:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.HIGH,
                code="AZURE_SECRET_NOT_ROTATED",
                message=f"Client secret is {age} days old (max {config.rotation_max_days})",
                detail="Rotate client secrets regularly. Consider using "
                       "managed identities or federated credentials instead.",
            ))


def _check_k8s_risks(ident: Identity, config: NHInsightConfig) -> None:
    """Kubernetes-specific risk checks."""

    # cluster-admin binding
    for policy in ident.policies:
        if policy in CLUSTER_ADMIN_BINDINGS:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.CRITICAL,
                code="K8S_CLUSTER_ADMIN",
                message="ServiceAccount bound to cluster-admin",
                detail="cluster-admin grants full control over the entire cluster. "
                       "Create a scoped ClusterRole with only needed permissions.",
            ))

    # Default namespace service account
    if ident.name.startswith("default/default"):
        ident.risk_flags.append(RiskFlag(
            severity=Severity.MEDIUM,
            code="K8S_DEFAULT_SA",
            message="Using the default ServiceAccount in default namespace",
            detail="Workloads should use dedicated ServiceAccounts, not the default.",
        ))

    # Orphaned — no running pods
    if ident.raw.get("orphaned", False):
        ident.risk_flags.append(RiskFlag(
            severity=Severity.MEDIUM,
            code="K8S_ORPHANED_SA",
            message="No running pods reference this ServiceAccount",
            detail="This ServiceAccount may be unused. Verify and delete if safe.",
        ))

    # Automount token enabled (default is True, which is dangerous)
    if ident.raw.get("automount_token", True) and ident.name != "kube-system/default":
        # Only flag if SA has elevated roles
        if any(p in CLUSTER_ADMIN_BINDINGS for p in ident.policies):
            ident.risk_flags.append(RiskFlag(
                severity=Severity.HIGH,
                code="K8S_AUTOMOUNT_PRIVILEGED",
                message="Automount token enabled on privileged ServiceAccount",
                detail="Pods using this SA automatically get a token with cluster-admin. "
                       "Set automountServiceAccountToken: false and mount explicitly.",
            ))

    # No IRSA/Workload Identity — using static secrets for cloud access
    has_irsa = ident.raw.get("irsa_role_arn", "")
    has_wi_gcp = ident.raw.get("workload_identity_gcp", "") or ident.raw.get("workload_identity_email", "")
    has_wi_azure = ident.raw.get("workload_identity_azure", "")
    if ident.raw.get("secret_count", 0) > 0 and not has_irsa and not has_wi_gcp and not has_wi_azure:
        labels = ident.raw.get("labels", {})
        if any(k in str(labels) for k in ("aws", "gcp", "cloud", "s3", "ecr", "azure")):
            ident.risk_flags.append(RiskFlag(
                severity=Severity.MEDIUM,
                code="K8S_NO_WORKLOAD_IDENTITY",
                message="SA has secrets but no IRSA/Workload Identity configured",
                detail="Use IRSA (EKS), Workload Identity (GKE), or Azure WI "
                       "instead of static credentials.",
            ))

    # Deployments using default SA
    default_deploys = ident.raw.get("used_as_default_by_deployments", [])
    if default_deploys:
        ident.risk_flags.append(RiskFlag(
            severity=Severity.MEDIUM,
            code="K8S_DEPLOY_DEFAULT_SA",
            message=f"{len(default_deploys)} deployment(s) using default SA: {', '.join(default_deploys[:5])}",
            detail="Each deployment should use a dedicated ServiceAccount with scoped RBAC.",
        ))


def _check_github_risks(ident: Identity, config: NHInsightConfig) -> None:
    """GitHub-specific risk checks."""

    # PAT with admin scope
    permissions = ident.permissions
    admin_perms = {"admin:org", "admin:repo_hook", "admin:enterprise", "delete_repo"}
    dangerous = set(permissions) & admin_perms
    if dangerous:
        ident.risk_flags.append(RiskFlag(
            severity=Severity.HIGH,
            code="GH_ADMIN_SCOPE",
            message=f"Token has admin scope: {', '.join(dangerous)}",
            detail="Tokens should use the minimum required scopes.",
        ))

    # Write access
    if "repo" in permissions:
        ident.risk_flags.append(RiskFlag(
            severity=Severity.MEDIUM,
            code="GH_REPO_WRITE",
            message="Token has full repo access (read + write + admin)",
            detail="Consider using fine-grained PATs with read-only access where possible.",
        ))

    # Deploy key with write access
    if ident.identity_type == IdentityType.DEPLOY_KEY:
        if "repo:write" in permissions:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.MEDIUM,
                code="GH_DEPLOY_KEY_WRITE",
                message="Deploy key has write access",
                detail="Deploy keys should be read-only unless the workflow requires pushing code.",
            ))

    # GitHub App with write permissions on dangerous scopes
    if ident.identity_type == IdentityType.GITHUB_APP:
        write_perms = [p for p in permissions if p.endswith(":write") or p.endswith(":admin")]
        dangerous_app_perms = [p for p in write_perms if any(
            scope in p for scope in ("administration", "members", "organization", "actions")
        )]
        if dangerous_app_perms:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.HIGH,
                code="GH_APP_DANGEROUS_PERMS",
                message=f"GitHub App has dangerous write permissions: {', '.join(dangerous_app_perms)}",
                detail="Review if this app truly needs admin/write access to org settings or actions.",
            ))

    # Inactive webhook
    if ident.identity_type == IdentityType.WEBHOOK:
        if not ident.raw.get("active", True):
            ident.risk_flags.append(RiskFlag(
                severity=Severity.LOW,
                code="GH_WEBHOOK_INACTIVE",
                message="Webhook is inactive",
                detail="Remove inactive webhooks to reduce attack surface.",
            ))


def _check_k8s_secret_risks(ident: Identity, config: NHInsightConfig) -> None:
    """Risk checks for Kubernetes Secrets."""
    secret_type = ident.raw.get("secret_type", "")
    data_keys = ident.raw.get("data_keys", [])
    managed_by = ident.raw.get("managed_by", "")

    # Opaque secrets with credential-looking keys
    credential_key_patterns = (
        "password", "secret", "token", "key", "credential",
        "api_key", "apikey", "api-key", "private",
        "access_key", "secret_key", "aws_",
    )
    if secret_type == "Opaque":
        suspicious_keys = [
            k for k in data_keys
            if any(p in k.lower() for p in credential_key_patterns)
        ]
        if suspicious_keys:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.MEDIUM,
                code="K8S_SECRET_CREDENTIALS",
                message=f"Opaque secret contains credential-like keys: {', '.join(suspicious_keys[:5])}",
                detail="Consider using external-secrets-operator, Vault, or sealed-secrets "
                       "instead of plain Kubernetes secrets.",
            ))

    # TLS secrets — check if managed by cert-manager
    if secret_type == "kubernetes.io/tls" and not managed_by:
        ident.risk_flags.append(RiskFlag(
            severity=Severity.LOW,
            code="K8S_TLS_UNMANAGED",
            message="TLS secret not managed by cert-manager or similar tool",
            detail="Unmanaged TLS secrets may expire without automatic renewal.",
        ))

    # SA token secrets (legacy pre-1.24 long-lived tokens)
    if secret_type == "kubernetes.io/service-account-token":
        ident.risk_flags.append(RiskFlag(
            severity=Severity.HIGH,
            code="K8S_LEGACY_SA_TOKEN",
            message="Legacy long-lived ServiceAccount token secret",
            detail="Since K8s 1.24, SA tokens should be short-lived (TokenRequest API). "
                   "Delete this secret and migrate to bound tokens.",
        ))


GCP_DANGEROUS_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/resourcemanager.projectIamAdmin",
    "roles/compute.admin",
    "roles/container.admin",
    "roles/storage.admin",
    "roles/secretmanager.admin",
}


def _check_gcp_risks(ident: Identity, config: NHInsightConfig) -> None:
    """GCP-specific risk checks."""

    # SA with dangerous IAM roles
    if ident.identity_type == IdentityType.GCP_SERVICE_ACCOUNT:
        for role in ident.policies:
            if role in GCP_DANGEROUS_ROLES:
                ident.risk_flags.append(RiskFlag(
                    severity=Severity.CRITICAL if role in ("roles/owner", "roles/editor") else Severity.HIGH,
                    code="GCP_SA_DANGEROUS_ROLE",
                    message=f"Service account has {role}",
                    detail=f"The {role} role grants broad access. "
                           "Use a custom role with only the permissions actually needed.",
                ))

        # Disabled SA with role bindings
        if ident.raw.get("disabled", False) and ident.policies:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.MEDIUM,
                code="GCP_SA_DISABLED_WITH_ROLES",
                message="Disabled service account still has IAM role bindings",
                detail="Remove IAM bindings from disabled service accounts.",
            ))

        # GCP-managed SA (system-managed, usually ok but flagged if overprivileged)
        if ident.raw.get("gcp_managed", False):
            dangerous = [r for r in ident.policies if r in GCP_DANGEROUS_ROLES]
            if dangerous:
                ident.risk_flags.append(RiskFlag(
                    severity=Severity.HIGH,
                    code="GCP_MANAGED_SA_OVERPRIVILEGED",
                    message=f"GCP-managed SA has dangerous roles: {', '.join(dangerous)}",
                    detail="GCP-managed service accounts should not have extra "
                           "project-level Owner/Editor bindings.",
                ))

    # SA key risks
    if ident.identity_type == IdentityType.GCP_SA_KEY:
        # Key age check
        age = ident.age_days
        if age is not None and age > config.rotation_max_days:
            ident.risk_flags.append(RiskFlag(
                severity=Severity.HIGH,
                code="GCP_KEY_NOT_ROTATED",
                message=f"SA key is {age} days old (max {config.rotation_max_days})",
                detail="Rotate service account keys regularly. "
                       "Prefer Workload Identity Federation over long-lived keys.",
            ))

        # Key expiry check
        expires_str = ident.raw.get("expires_at")
        if expires_str:
            from datetime import datetime
            from datetime import timezone as tz
            try:
                expires_at = datetime.fromisoformat(expires_str)
                now = datetime.now(tz.utc)
                days_until = (expires_at - now).days
                if days_until < 0:
                    ident.risk_flags.append(RiskFlag(
                        severity=Severity.HIGH,
                        code="GCP_KEY_EXPIRED",
                        message=f"SA key expired {abs(days_until)} days ago",
                        detail="Delete expired keys and rotate to new credentials.",
                    ))
                elif days_until < 30:
                    ident.risk_flags.append(RiskFlag(
                        severity=Severity.MEDIUM,
                        code="GCP_KEY_EXPIRING_SOON",
                        message=f"SA key expires in {days_until} days",
                        detail="Rotate this key before it expires to avoid outages.",
                    ))
            except (ValueError, TypeError):
                pass

        # Disabled key
        if ident.raw.get("disabled", False):
            ident.risk_flags.append(RiskFlag(
                severity=Severity.LOW,
                code="GCP_KEY_DISABLED",
                message="SA key is disabled but not deleted",
                detail="Delete disabled keys to reduce attack surface.",
            ))


def _check_stale(ident: Identity, config: NHInsightConfig) -> None:
    """Check if identity hasn't been used in config.stale_days."""
    days = ident.days_since_last_used
    if days is not None and days > config.stale_days:
        ident.risk_flags.append(RiskFlag(
            severity=Severity.MEDIUM,
            code="STALE_IDENTITY",
            message=f"Not used in {days} days (threshold: {config.stale_days})",
            detail="Unused identities should be deactivated or removed to reduce attack surface.",
        ))


def _check_no_owner(ident: Identity) -> None:
    """Flag identities with no identified owner."""
    if not ident.owner and not ident.created_by:
        ident.risk_flags.append(RiskFlag(
            severity=Severity.LOW,
            code="NO_OWNER",
            message="No owner or creator identified",
            detail="Every NHI should have a documented owner responsible for its lifecycle.",
        ))
