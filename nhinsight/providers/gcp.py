# MIT License — Copyright (c) 2026 cvemula1
# GCP provider — discovers GCP Service Accounts, SA keys, and IAM bindings

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional, Set

from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import Identity, IdentityType, Provider
from nhinsight.providers.base import BaseProvider

logger = logging.getLogger(__name__)

# GCP predefined roles that grant dangerous access
DANGEROUS_ROLES = {
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
    "roles/cloudsql.admin",
    "roles/secretmanager.admin",
}


class GCPProvider(BaseProvider):
    """Discover non-human identities in Google Cloud Platform."""

    name = "gcp"

    def __init__(self, config: NHInsightConfig):
        super().__init__(config)
        self._credentials = None
        self._project_id: Optional[str] = None

    def _get_credentials(self):
        """Get default GCP credentials."""
        if self._credentials is None:
            import google.auth

            self._credentials, project = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            if not self._project_id:
                self._project_id = self.config.gcp_project or project
        return self._credentials

    def _get_project_id(self) -> str:
        """Get the active GCP project ID."""
        if not self._project_id:
            self._get_credentials()
        if not self._project_id:
            raise ValueError(
                "GCP project not found. Set GCP_PROJECT or "
                "GOOGLE_CLOUD_PROJECT, or run 'gcloud config set project'."
            )
        return self._project_id

    def is_available(self) -> bool:
        try:
            self._get_credentials()
            self._get_project_id()
            return True
        except Exception:
            return False

    def discover(self) -> List[Identity]:
        """Discover all GCP NHIs: service accounts, SA keys, IAM bindings."""
        identities: List[Identity] = []

        try:
            project_id = self._get_project_id()
            logger.info("Scanning GCP project %s", project_id)

            # 1. Discover service accounts
            service_accounts = self._discover_service_accounts(project_id)

            # 2. Get IAM policy for the project → map roles to SAs
            iam_map = self._get_project_iam_bindings(project_id)

            # 3. Enrich SAs with IAM roles
            for sa in service_accounts:
                email = sa.raw.get("email", "")
                member_key = f"serviceAccount:{email}"
                sa.policies = list(iam_map.get(member_key, []))

            identities.extend(service_accounts)

            # 4. Discover SA keys
            for sa in service_accounts:
                email = sa.raw.get("email", "")
                if email:
                    identities.extend(
                        self._discover_sa_keys(project_id, email)
                    )

        except ImportError:
            logger.error(
                "google-cloud-iam not installed. "
                "Run: pip install google-cloud-iam google-auth"
            )
        except Exception as e:
            logger.error("GCP discovery failed: %s", e)

        return identities

    # ── 1. Service Accounts ─────────────────────────────────────────

    def _discover_service_accounts(
        self, project_id: str
    ) -> List[Identity]:
        """Discover all service accounts in the project."""
        from googleapiclient.discovery import build

        credentials = self._get_credentials()
        service = build("iam", "v1", credentials=credentials)

        identities: List[Identity] = []

        try:
            request = service.projects().serviceAccounts().list(
                name=f"projects/{project_id}",
            )
            while request is not None:
                response = request.execute()
                for sa in response.get("accounts", []):
                    email = sa.get("email", "")
                    display_name = sa.get("displayName", "")
                    unique_id = sa.get("uniqueId", "")
                    disabled = sa.get("disabled", False)

                    # Determine if this is a user-managed or GCP-managed SA
                    is_gcp_managed = email.endswith(
                        ".iam.gserviceaccount.com"
                    ) and any(
                        email.startswith(p) for p in (
                            "service-", "firebase-", "cloud-",
                        )
                    )

                    # Parse creation time from name or description
                    # GCP SA API doesn't return created_at directly;
                    # we'll leave it None unless available from metadata
                    description = sa.get("description", "")

                    ident = Identity(
                        id=f"gcp:sa:{project_id}:{email}",
                        name=email.split("@")[0] if "@" in email else email,
                        provider=Provider.GCP,
                        identity_type=IdentityType.GCP_SERVICE_ACCOUNT,
                        arn=email,  # use email as the "ARN" equivalent
                        owner=display_name or "",
                        raw={
                            "email": email,
                            "display_name": display_name,
                            "unique_id": unique_id,
                            "disabled": disabled,
                            "description": description,
                            "project_id": project_id,
                            "gcp_managed": is_gcp_managed,
                        },
                    )
                    identities.append(ident)

                request = (
                    service.projects()
                    .serviceAccounts()
                    .list_next(previous_request=request, previous_response=response)
                )

        except Exception as e:
            logger.warning("Failed to list service accounts: %s", e)

        logger.info("Found %d GCP service accounts", len(identities))
        return identities

    # ── 2. SA Keys ──────────────────────────────────────────────────

    def _discover_sa_keys(
        self, project_id: str, sa_email: str
    ) -> List[Identity]:
        """Discover user-managed keys for a service account."""
        from googleapiclient.discovery import build

        credentials = self._get_credentials()
        service = build("iam", "v1", credentials=credentials)

        identities: List[Identity] = []

        try:
            sa_resource = (
                f"projects/{project_id}/serviceAccounts/{sa_email}"
            )
            response = (
                service.projects()
                .serviceAccounts()
                .keys()
                .list(
                    name=sa_resource,
                    keyTypes=["USER_MANAGED"],
                )
                .execute()
            )

            for key in response.get("keys", []):
                key_name = key.get("name", "")
                # key_name format: projects/{p}/serviceAccounts/{e}/keys/{id}
                key_id = key_name.split("/")[-1] if "/" in key_name else key_name
                key_type = key.get("keyType", "USER_MANAGED")
                key_origin = key.get("keyOrigin", "GOOGLE_PROVIDED")

                # Parse timestamps
                created_at = _parse_gcp_timestamp(
                    key.get("validAfterTime")
                )
                expires_at = _parse_gcp_timestamp(
                    key.get("validBeforeTime")
                )
                disabled = key.get("disabled", False)

                sa_name = sa_email.split("@")[0] if "@" in sa_email else sa_email

                ident = Identity(
                    id=f"gcp:sa_key:{project_id}:{key_id}",
                    name=f"{sa_name}/key:{key_id[:8]}",
                    provider=Provider.GCP,
                    identity_type=IdentityType.GCP_SA_KEY,
                    arn=sa_email,
                    created_at=created_at,
                    created_by=sa_email,
                    raw={
                        "key_id": key_id,
                        "key_name": key_name,
                        "key_type": key_type,
                        "key_origin": key_origin,
                        "sa_email": sa_email,
                        "project_id": project_id,
                        "disabled": disabled,
                        "expires_at": (
                            expires_at.isoformat() if expires_at else None
                        ),
                    },
                )
                identities.append(ident)

        except Exception as e:
            logger.warning(
                "Failed to list keys for %s: %s", sa_email, e
            )

        return identities

    # ── 3. Project IAM Bindings ─────────────────────────────────────

    def _get_project_iam_bindings(
        self, project_id: str
    ) -> Dict[str, Set[str]]:
        """Get IAM policy for the project → {member: {role, ...}}."""
        from googleapiclient.discovery import build

        credentials = self._get_credentials()
        service = build(
            "cloudresourcemanager", "v1", credentials=credentials
        )

        iam_map: Dict[str, Set[str]] = {}

        try:
            policy = (
                service.projects()
                .getIamPolicy(
                    resource=project_id,
                    body={"options": {"requestedPolicyVersion": 3}},
                )
                .execute()
            )

            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                for member in binding.get("members", []):
                    iam_map.setdefault(member, set()).add(role)

        except Exception as e:
            logger.warning(
                "Failed to get IAM policy for project %s: %s",
                project_id, e,
            )

        return iam_map


# ── Helpers ─────────────────────────────────────────────────────────

def _parse_gcp_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parse a GCP API timestamp string to datetime."""
    if not ts:
        return None
    try:
        # GCP timestamps: "2024-01-15T10:30:00Z"
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None
