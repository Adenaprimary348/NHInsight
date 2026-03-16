# MIT License — Copyright (c) 2026 cvemula1
# NHI Security Scoring — NIST SP 800-53, IGA Governance, Attack Surface Index

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from nhinsight.core.models import (
    Classification,
    Identity,
    IdentityType,
    Severity,
)

# ── NIST SP 800-53 Control Mapping ──────────────────────────────────────
# Maps each risk flag code to the most relevant NIST control(s).

NIST_CONTROL_MAP: Dict[str, List[str]] = {
    # AWS
    "AWS_ADMIN_ACCESS":         ["AC-6", "AC-6(1)"],   # Least Privilege
    "AWS_KEY_NOT_ROTATED":      ["IA-5(1)"],            # Authenticator Management
    "AWS_KEY_INACTIVE":         ["AC-2(3)"],            # Account Management – Disable Inactive
    "AWS_NO_MFA":               ["IA-2(1)", "IA-2(2)"],  # MFA for Privileged/Non-Privileged
    "AWS_WILDCARD_TRUST":       ["AC-3", "AC-17(1)"],  # Access Enforcement, Remote Access

    # Azure
    "AZURE_SP_DANGEROUS_ROLE":  ["AC-6", "AC-6(1)"],   # Least Privilege
    "AZURE_SP_ELEVATED_ROLE":   ["AC-6(5)"],            # Privileged Accounts
    "AZURE_SP_DISABLED_WITH_ROLES": ["AC-2(3)", "AC-2(4)"],  # Disable/Audit Inactive
    "AZURE_MI_DANGEROUS_ROLE":  ["AC-6", "AC-6(1)"],   # Least Privilege
    "AZURE_CRED_EXPIRED":       ["IA-5(1)"],            # Authenticator Management
    "AZURE_CRED_EXPIRING_SOON": ["IA-5(1)"],            # Authenticator Management
    "AZURE_SECRET_NOT_ROTATED": ["IA-5(1)", "IA-5(6)"],  # Authenticator Rotation

    # Kubernetes
    "K8S_CLUSTER_ADMIN":        ["AC-6", "AC-6(1)"],   # Least Privilege
    "K8S_DEFAULT_SA":           ["AC-2", "CM-6"],       # Account Mgmt, Config Mgmt
    "K8S_ORPHANED_SA":          ["AC-2(3)"],            # Disable Inactive Accounts
    "K8S_AUTOMOUNT_PRIVILEGED": ["AC-6(9)", "CM-7(1)"],  # Restrict Privileged Functions
    "K8S_NO_WORKLOAD_IDENTITY": ["IA-2", "IA-5"],      # Identification, Authenticator Mgmt
    "K8S_DEPLOY_DEFAULT_SA":    ["AC-2", "CM-6"],       # Account Mgmt, Config Mgmt
    "K8S_SECRET_CREDENTIALS":   ["SC-28", "SC-12"],     # Protection at Rest, Key Mgmt
    "K8S_TLS_UNMANAGED":        ["SC-12", "CM-3"],      # Key Mgmt, Config Change Control
    "K8S_LEGACY_SA_TOKEN":      ["IA-5(1)", "IA-5(6)"],  # Token Lifecycle

    # GCP
    "GCP_SA_DANGEROUS_ROLE":    ["AC-6", "AC-6(1)"],   # Least Privilege
    "GCP_SA_DISABLED_WITH_ROLES": ["AC-2(3)", "AC-2(4)"],  # Disable Inactive
    "GCP_MANAGED_SA_OVERPRIVILEGED": ["AC-6", "AC-6(5)"],  # Privileged Accounts
    "GCP_KEY_NOT_ROTATED":      ["IA-5(1)", "IA-5(6)"],  # Authenticator Rotation
    "GCP_KEY_EXPIRED":          ["IA-5(1)"],              # Authenticator Management
    "GCP_KEY_EXPIRING_SOON":    ["IA-5(1)"],              # Authenticator Management
    "GCP_KEY_DISABLED":         ["AC-2(3)"],              # Disable Inactive

    # GitHub
    "GH_ADMIN_SCOPE":           ["AC-6", "AC-6(1)"],   # Least Privilege
    "GH_REPO_WRITE":            ["AC-6(5)"],            # Privileged Accounts
    "GH_DEPLOY_KEY_WRITE":      ["AC-6(5)", "AC-3"],    # Privileged, Enforcement
    "GH_APP_DANGEROUS_PERMS":   ["AC-6", "AC-6(1)"],   # Least Privilege
    "GH_WEBHOOK_INACTIVE":      ["CM-7", "SI-4"],       # Least Functionality, Monitoring

    # Cross-provider
    "STALE_IDENTITY":           ["AC-2(3)"],            # Disable Inactive Accounts
    "NO_OWNER":                 ["AC-2", "AU-3"],       # Account Mgmt, Audit Content
}

# Friendly names for NIST control families
NIST_FAMILY_NAMES: Dict[str, str] = {
    "AC": "Access Control",
    "IA": "Identification & Authentication",
    "AU": "Audit & Accountability",
    "CM": "Configuration Management",
    "SC": "System & Communications Protection",
    "SI": "System & Information Integrity",
}

# Severity weights for risk scoring
SEVERITY_WEIGHT: Dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}

# Identity types that represent credentials (secrets, keys, tokens)
CREDENTIAL_IDENTITY_TYPES = {
    IdentityType.ACCESS_KEY,
    IdentityType.AZURE_APP_SECRET,
    IdentityType.AZURE_APP_CERT,
    IdentityType.K8S_SECRET,
    IdentityType.GITHUB_PAT,
    IdentityType.DEPLOY_KEY,
    IdentityType.GCP_SA_KEY,
}

# Risk codes that indicate admin/dangerous privilege
ADMIN_RISK_CODES = {
    "AWS_ADMIN_ACCESS",
    "AWS_WILDCARD_TRUST",
    "AZURE_SP_DANGEROUS_ROLE",
    "AZURE_MI_DANGEROUS_ROLE",
    "GCP_SA_DANGEROUS_ROLE",
    "GCP_MANAGED_SA_OVERPRIVILEGED",
    "K8S_CLUSTER_ADMIN",
    "GH_ADMIN_SCOPE",
    "GH_APP_DANGEROUS_PERMS",
}

# Risk codes indicating credential rotation issues
ROTATION_RISK_CODES = {
    "AWS_KEY_NOT_ROTATED",
    "AZURE_SECRET_NOT_ROTATED",
    "AZURE_CRED_EXPIRED",
    "AZURE_CRED_EXPIRING_SOON",
    "GCP_KEY_NOT_ROTATED",
    "GCP_KEY_EXPIRED",
    "GCP_KEY_EXPIRING_SOON",
    "K8S_LEGACY_SA_TOKEN",
}


# ── Data Classes ────────────────────────────────────────────────────────

@dataclass
class NistFinding:
    """A single NIST control compliance finding."""
    control_id: str
    control_family: str
    status: str          # FAIL, PARTIAL, PASS
    identities: int      # count of identities violating this control
    total: int           # total identities evaluated
    description: str = ""


@dataclass
class GovernanceScores:
    """IGA governance pillar scores (0.0 – 1.0 each)."""
    ownership_coverage: float = 0.0
    credential_rotation: float = 0.0
    least_privilege: float = 0.0
    lifecycle_hygiene: float = 0.0
    overall: float = 0.0

    def to_dict(self) -> dict:
        return {
            "ownership_coverage": round(self.ownership_coverage, 3),
            "credential_rotation": round(self.credential_rotation, 3),
            "least_privilege": round(self.least_privilege, 3),
            "lifecycle_hygiene": round(self.lifecycle_hygiene, 3),
            "overall": round(self.overall, 3),
        }


@dataclass
class CisoMetrics:
    """The 4 board-level metrics CISOs report."""
    pct_with_owner: float = 0.0
    pct_stale: float = 0.0
    pct_admin: float = 0.0
    pct_long_lived_secrets: float = 0.0

    def to_dict(self) -> dict:
        return {
            "pct_with_owner": round(self.pct_with_owner, 1),
            "pct_stale": round(self.pct_stale, 1),
            "pct_admin": round(self.pct_admin, 1),
            "pct_long_lived_secrets": round(self.pct_long_lived_secrets, 1),
        }


@dataclass
class ScoreCard:
    """Complete NHI security scorecard."""
    total_identities: int = 0
    attack_surface_score: float = 0.0   # 0–100, higher = healthier
    risk_score: int = 0                 # raw weighted risk points
    governance: GovernanceScores = field(default_factory=GovernanceScores)
    ciso_metrics: CisoMetrics = field(default_factory=CisoMetrics)
    nist_controls: Dict[str, NistFinding] = field(default_factory=dict)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    grade: str = "F"                    # A / B / C / D / F

    def to_dict(self) -> dict:
        return {
            "total_identities": self.total_identities,
            "attack_surface_score": round(self.attack_surface_score, 1),
            "risk_score": self.risk_score,
            "grade": self.grade,
            "severity_counts": self.severity_counts,
            "governance": self.governance.to_dict(),
            "ciso_metrics": self.ciso_metrics.to_dict(),
            "nist_controls": {
                ctrl: {
                    "control_id": f.control_id,
                    "family": f.control_family,
                    "status": f.status,
                    "violations": f.identities,
                    "total": f.total,
                }
                for ctrl, f in self.nist_controls.items()
            },
        }


# ── Scoring Engine ──────────────────────────────────────────────────────

def compute_scorecard(identities: List[Identity]) -> ScoreCard:
    """Compute the full NHI security scorecard from scanned identities."""
    # Filter to NHIs only (exclude human identities)
    nhis = [i for i in identities if i.classification != Classification.HUMAN]
    total = len(nhis)

    if total == 0:
        return ScoreCard()

    card = ScoreCard(total_identities=total)

    # ── Severity counts ─────────────────────────────────────────────
    card.severity_counts = _count_severities(nhis)

    # ── Raw risk score ──────────────────────────────────────────────
    card.risk_score = _compute_risk_score(nhis)

    # ── CISO metrics ────────────────────────────────────────────────
    card.ciso_metrics = _compute_ciso_metrics(nhis)

    # ── Governance scores ───────────────────────────────────────────
    card.governance = _compute_governance(nhis, card.ciso_metrics)

    # ── NIST control compliance ─────────────────────────────────────
    card.nist_controls = _compute_nist_compliance(nhis)

    # ── Attack Surface Score (0–100) ────────────────────────────────
    card.attack_surface_score = _compute_attack_surface_score(
        nhis, card.risk_score, card.governance
    )

    # ── Letter grade ────────────────────────────────────────────────
    card.grade = _score_to_grade(card.attack_surface_score)

    return card


# ── Internal helpers ────────────────────────────────────────────────────

def _count_severities(nhis: List[Identity]) -> Dict[str, int]:
    """Count identities by their highest severity."""
    counts = {
        "critical": 0, "high": 0, "medium": 0,
        "low": 0, "info": 0, "healthy": 0,
    }
    for nhi in nhis:
        highest = nhi.highest_severity
        if highest is None:
            counts["healthy"] += 1
        elif highest == Severity.INFO:
            counts["healthy"] += 1
        else:
            counts[highest.value] += 1
    return counts


def _compute_risk_score(nhis: List[Identity]) -> int:
    """Weighted risk score: critical*10 + high*6 + medium*3 + low*1."""
    score = 0
    for nhi in nhis:
        for flag in nhi.risk_flags:
            score += SEVERITY_WEIGHT.get(flag.severity, 0)
    return score


def _compute_ciso_metrics(nhis: List[Identity]) -> CisoMetrics:
    """Compute the 4 board-level NHI metrics."""
    total = len(nhis)
    if total == 0:
        return CisoMetrics()

    # 1. % with owner
    with_owner = sum(1 for n in nhis if n.owner or n.created_by)

    # 2. % stale (> 90 days unused)
    stale = sum(
        1 for n in nhis
        if any(f.code == "STALE_IDENTITY" for f in n.risk_flags)
    )

    # 3. % with admin/dangerous access
    admin = sum(
        1 for n in nhis
        if any(f.code in ADMIN_RISK_CODES for f in n.risk_flags)
    )

    # 4. % with long-lived secrets (not rotated or expired)
    long_lived = sum(
        1 for n in nhis
        if any(f.code in ROTATION_RISK_CODES for f in n.risk_flags)
    )

    return CisoMetrics(
        pct_with_owner=100.0 * with_owner / total,
        pct_stale=100.0 * stale / total,
        pct_admin=100.0 * admin / total,
        pct_long_lived_secrets=100.0 * long_lived / total,
    )


def _compute_governance(
    nhis: List[Identity], ciso: CisoMetrics
) -> GovernanceScores:
    """Compute IGA governance pillar scores (0.0–1.0)."""
    total = len(nhis)
    if total == 0:
        return GovernanceScores()

    # Ownership: % of identities with a known owner
    ownership = ciso.pct_with_owner / 100.0

    # Credential rotation: 1.0 minus fraction with rotation problems
    rotation_issues = sum(
        1 for n in nhis
        if any(f.code in ROTATION_RISK_CODES for f in n.risk_flags)
    )
    cred_rotation = 1.0 - (rotation_issues / total)

    # Least privilege: 1.0 minus fraction with admin/elevated access
    privilege_issues = sum(
        1 for n in nhis
        if any(f.code in ADMIN_RISK_CODES for f in n.risk_flags)
    )
    least_priv = 1.0 - (privilege_issues / total)

    # Lifecycle hygiene: 1.0 minus fraction stale/orphaned/inactive
    lifecycle_codes = {"STALE_IDENTITY", "K8S_ORPHANED_SA", "AWS_KEY_INACTIVE",
                       "AZURE_SP_DISABLED_WITH_ROLES", "GH_WEBHOOK_INACTIVE"}
    lifecycle_issues = sum(
        1 for n in nhis
        if any(f.code in lifecycle_codes for f in n.risk_flags)
    )
    lifecycle = 1.0 - (lifecycle_issues / total)

    # Overall: equal-weighted average of the 4 pillars
    overall = (ownership + cred_rotation + least_priv + lifecycle) / 4.0

    return GovernanceScores(
        ownership_coverage=ownership,
        credential_rotation=cred_rotation,
        least_privilege=least_priv,
        lifecycle_hygiene=lifecycle,
        overall=overall,
    )


def _compute_nist_compliance(nhis: List[Identity]) -> Dict[str, NistFinding]:
    """Evaluate NIST SP 800-53 control compliance across all identities."""
    total = len(nhis)

    # Collect all violated controls
    control_violations: Dict[str, int] = {}
    for nhi in nhis:
        seen_controls = set()
        for flag in nhi.risk_flags:
            controls = NIST_CONTROL_MAP.get(flag.code, [])
            for ctrl in controls:
                if ctrl not in seen_controls:
                    control_violations[ctrl] = control_violations.get(ctrl, 0) + 1
                    seen_controls.add(ctrl)

    # All controls we evaluate
    all_controls = set()
    for controls in NIST_CONTROL_MAP.values():
        all_controls.update(controls)

    findings: Dict[str, NistFinding] = {}
    for ctrl in sorted(all_controls):
        family_code = ctrl.split("-")[0]
        family_name = NIST_FAMILY_NAMES.get(family_code, family_code)
        violations = control_violations.get(ctrl, 0)

        if violations == 0:
            status = "PASS"
        elif violations < total * 0.2:
            status = "PARTIAL"
        else:
            status = "FAIL"

        findings[ctrl] = NistFinding(
            control_id=ctrl,
            control_family=family_name,
            status=status,
            identities=violations,
            total=total,
        )

    return findings


def _compute_attack_surface_score(
    nhis: List[Identity],
    risk_score: int,
    governance: GovernanceScores,
) -> float:
    """
    NHI Attack Surface Score: 0–100 (higher = healthier).

    Formula:
        score = 100 - risk_penalty - governance_penalty

    Risk penalty:   normalized risk score (0–50)
    Governance penalty: (1 - governance_overall) * 50
    """
    total = len(nhis)
    if total == 0:
        return 100.0

    # Max possible risk: every NHI has a critical flag
    max_risk = total * SEVERITY_WEIGHT[Severity.CRITICAL]
    risk_ratio = min(risk_score / max_risk, 1.0) if max_risk > 0 else 0.0
    risk_penalty = risk_ratio * 50.0

    # Governance penalty: inverse of overall governance score
    gov_penalty = (1.0 - governance.overall) * 50.0

    score = 100.0 - risk_penalty - gov_penalty
    return max(0.0, min(100.0, score))


def _score_to_grade(score: float) -> str:
    """Convert attack surface score to letter grade."""
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    return "F"


# ── NIST lookup helpers ─────────────────────────────────────────────────

def get_nist_controls_for_code(code: str) -> List[str]:
    """Return NIST SP 800-53 control IDs for a given risk flag code."""
    return NIST_CONTROL_MAP.get(code, [])


def get_nist_family(control_id: str) -> str:
    """Return the NIST control family name for a control ID."""
    family_code = control_id.split("-")[0]
    return NIST_FAMILY_NAMES.get(family_code, family_code)
