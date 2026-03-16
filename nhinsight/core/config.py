# MIT License — Copyright (c) 2026 cvemula1
# Configuration for NHInsight

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class NHInsightConfig:
    """Global configuration for NHInsight scans."""

    # Providers to scan
    providers: List[str] = field(default_factory=lambda: ["aws"])

    # AWS settings
    aws_profile: Optional[str] = None
    aws_region: Optional[str] = None

    # GitHub settings
    github_token: Optional[str] = None
    github_org: Optional[str] = None
    github_base_url: Optional[str] = None

    # Azure settings
    azure_tenant_id: Optional[str] = None
    azure_subscription_id: Optional[str] = None

    # GCP settings
    gcp_project: Optional[str] = None

    # Kubernetes settings
    kubeconfig: Optional[str] = None
    kube_context: Optional[str] = None
    kube_namespace: Optional[str] = None  # None = all namespaces

    # Risk thresholds
    stale_days: int = 90
    rotation_max_days: int = 365

    # LLM settings
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    explain: bool = False

    # Output
    output_format: str = "table"  # table, json, sarif, html

    @classmethod
    def from_env(cls) -> "NHInsightConfig":
        """Load configuration from environment variables."""
        return cls(
            aws_profile=os.environ.get("AWS_PROFILE"),
            aws_region=os.environ.get("AWS_DEFAULT_REGION"),
            github_token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
            github_org=os.environ.get("GITHUB_ORG"),
            github_base_url=os.environ.get("GITHUB_BASE_URL"),
            azure_tenant_id=os.environ.get("AZURE_TENANT_ID"),
            azure_subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID"),
            gcp_project=os.environ.get("GCP_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT"),
            kubeconfig=os.environ.get("KUBECONFIG"),
            kube_context=os.environ.get("KUBE_CONTEXT"),
            kube_namespace=os.environ.get("KUBE_NAMESPACE"),
            openai_api_key=os.environ.get("OPENAI_API_KEY"),
            stale_days=int(os.environ.get("NHINSIGHT_STALE_DAYS", "90")),
            rotation_max_days=int(os.environ.get("NHINSIGHT_ROTATION_MAX_DAYS", "365")),
        )
