# MIT License — Copyright (c) 2026 cvemula1
# Data models for NHInsight identity discovery

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class IdentityType(str, Enum):
    """Type of non-human identity."""
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    ACCESS_KEY = "access_key"
    GITHUB_APP = "github_app"
    GITHUB_PAT = "github_pat"
    DEPLOY_KEY = "deploy_key"
    SERVICE_ACCOUNT = "service_account"
    K8S_SECRET = "k8s_secret"
    WEBHOOK = "webhook"
    OAUTH_APP = "oauth_app"
    AZURE_SP = "azure_sp"
    AZURE_MANAGED_IDENTITY = "azure_managed_identity"
    AZURE_APP_SECRET = "azure_app_secret"
    AZURE_APP_CERT = "azure_app_cert"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    GCP_SA_KEY = "gcp_sa_key"
    GITHUB_ACTIONS_OIDC = "github_actions_oidc"
    UNKNOWN = "unknown"


class Provider(str, Enum):
    """Cloud or platform provider."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    GITHUB = "github"
    KUBERNETES = "kubernetes"


class Classification(str, Enum):
    """Whether the identity belongs to a human or machine."""
    HUMAN = "human"
    MACHINE = "machine"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Risk severity level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RiskFlag:
    """A single risk finding for an identity."""
    severity: Severity
    code: str
    message: str
    detail: str = ""


@dataclass
class Identity:
    """Represents a single non-human identity discovered in infrastructure."""
    id: str
    name: str
    provider: Provider
    identity_type: IdentityType
    classification: Classification = Classification.UNKNOWN

    # Metadata
    arn: str = ""
    created_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    created_by: str = ""
    owner: str = ""

    # Permissions
    permissions: List[str] = field(default_factory=list)
    policies: List[str] = field(default_factory=list)

    # Risk
    risk_flags: List[RiskFlag] = field(default_factory=list)

    # Raw provider data
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def age_days(self) -> Optional[int]:
        if self.created_at:
            delta = datetime.now(timezone.utc) - self.created_at
            return delta.days
        return None

    @property
    def days_since_last_used(self) -> Optional[int]:
        if self.last_used:
            delta = datetime.now(timezone.utc) - self.last_used
            return delta.days
        return None

    @property
    def highest_severity(self) -> Severity:
        if not self.risk_flags:
            return Severity.INFO
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if any(f.severity == sev for f in self.risk_flags):
                return sev
        return Severity.INFO

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider.value,
            "identity_type": self.identity_type.value,
            "classification": self.classification.value,
            "arn": self.arn,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "created_by": self.created_by,
            "owner": self.owner,
            "age_days": self.age_days,
            "days_since_last_used": self.days_since_last_used,
            "permissions": self.permissions,
            "policies": self.policies,
            "risk_flags": [
                {"severity": f.severity.value, "code": f.code, "message": f.message, "detail": f.detail}
                for f in self.risk_flags
            ],
            "highest_severity": self.highest_severity.value,
        }


@dataclass
class ScanResult:
    """Aggregated results from a scan across one or more providers."""
    identities: List[Identity] = field(default_factory=list)
    providers_scanned: List[str] = field(default_factory=list)
    scan_time: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.identities)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.identities if i.highest_severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.identities if i.highest_severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.identities if i.highest_severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for i in self.identities if i.highest_severity == Severity.LOW)

    @property
    def healthy_count(self) -> int:
        return sum(1 for i in self.identities if i.highest_severity == Severity.INFO)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "healthy": self.healthy_count,
            "providers_scanned": self.providers_scanned,
            "scan_time": self.scan_time.isoformat() if self.scan_time else None,
            "errors": self.errors,
            "identities": [i.to_dict() for i in self.identities],
        }
