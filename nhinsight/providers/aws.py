# MIT License — Copyright (c) 2026 cvemula1
# AWS IAM provider — discovers IAM users, roles, and access keys

from __future__ import annotations

import logging
from datetime import timezone
from typing import List, Optional

from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import Identity, IdentityType, Provider
from nhinsight.providers.base import BaseProvider

logger = logging.getLogger(__name__)


class AWSProvider(BaseProvider):
    """Discover non-human identities in AWS IAM."""

    name = "aws"

    def __init__(self, config: NHInsightConfig):
        super().__init__(config)
        self._iam = None
        self._sts = None
        self._account_id: Optional[str] = None

    def _get_session(self):
        """Create a boto3 session with optional profile."""
        import boto3

        kwargs = {}
        if self.config.aws_profile:
            kwargs["profile_name"] = self.config.aws_profile
        if self.config.aws_region:
            kwargs["region_name"] = self.config.aws_region
        return boto3.Session(**kwargs)

    def _get_iam(self):
        if self._iam is None:
            session = self._get_session()
            self._iam = session.client("iam")
        return self._iam

    def _get_account_id(self) -> str:
        if self._account_id is None:
            session = self._get_session()
            sts = session.client("sts")
            self._account_id = sts.get_caller_identity()["Account"]
        return self._account_id

    def is_available(self) -> bool:
        try:
            self._get_account_id()
            return True
        except Exception:
            return False

    def discover(self) -> List[Identity]:
        """Discover all IAM users and their access keys."""
        identities: List[Identity] = []

        try:
            account_id = self._get_account_id()
            logger.info("Scanning AWS account %s", account_id)

            identities.extend(self._discover_users(account_id))
            identities.extend(self._discover_roles(account_id))
        except ImportError:
            logger.error("boto3 not installed. Run: pip install boto3")
        except Exception as e:
            logger.error("AWS discovery failed: %s", e)

        return identities

    def _discover_users(self, account_id: str) -> List[Identity]:
        """Discover IAM users and their access keys."""
        iam = self._get_iam()
        identities: List[Identity] = []

        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                user_arn = user["Arn"]
                created = user["CreateDate"]

                # Get attached policies
                policies = self._get_user_policies(username)

                # Check console access (login profile)
                has_console = self._has_console_access(username)

                # Check MFA
                has_mfa = self._has_mfa(username)

                # Create identity for the user
                ident = Identity(
                    id=f"aws:iam:user:{account_id}:{username}",
                    name=username,
                    provider=Provider.AWS,
                    identity_type=IdentityType.IAM_USER,
                    arn=user_arn,
                    created_at=created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created,
                    policies=policies,
                    raw={
                        "has_console_access": has_console,
                        "has_mfa": has_mfa,
                        "path": user.get("Path", "/"),
                    },
                )
                identities.append(ident)

                # Discover access keys for this user
                identities.extend(self._discover_access_keys(account_id, username, user_arn))

        logger.info("Found %d IAM users and access keys", len(identities))
        return identities

    def _discover_access_keys(self, account_id: str, username: str, user_arn: str) -> List[Identity]:
        """Discover access keys for a specific IAM user."""
        iam = self._get_iam()
        identities: List[Identity] = []

        try:
            resp = iam.list_access_keys(UserName=username)
            for key in resp.get("AccessKeyMetadata", []):
                key_id = key["AccessKeyId"]
                status = key["Status"]
                created = key["CreateDate"]

                # Get last used info
                last_used_info = iam.get_access_key_last_used(AccessKeyId=key_id)
                last_used_data = last_used_info.get("AccessKeyLastUsed", {})
                last_used = last_used_data.get("LastUsedDate")
                last_service = last_used_data.get("ServiceName", "N/A")
                last_region = last_used_data.get("Region", "N/A")

                ident = Identity(
                    id=f"aws:iam:key:{account_id}:{key_id}",
                    name=f"{username}/{key_id}",
                    provider=Provider.AWS,
                    identity_type=IdentityType.ACCESS_KEY,
                    arn=user_arn,
                    created_at=created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created,
                    last_used=(
                        last_used.replace(tzinfo=timezone.utc)
                        if last_used and last_used.tzinfo is None
                        else last_used
                    ),
                    created_by=username,
                    raw={
                        "key_id": key_id,
                        "status": status,
                        "last_service": last_service,
                        "last_region": last_region,
                        "parent_user": username,
                    },
                )
                identities.append(ident)

        except Exception as e:
            logger.warning("Failed to list access keys for %s: %s", username, e)

        return identities

    def _discover_roles(self, account_id: str) -> List[Identity]:
        """Discover IAM roles (excluding AWS service-linked roles)."""
        iam = self._get_iam()
        identities: List[Identity] = []

        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                role_arn = role["Arn"]
                path = role.get("Path", "/")

                # Skip AWS service-linked roles
                if path.startswith("/aws-service-role/"):
                    continue

                created = role["CreateDate"]
                policies = self._get_role_policies(role_name)

                # Get last used
                last_used = None
                role_last_used = role.get("RoleLastUsed", {})
                if "LastUsedDate" in role_last_used:
                    last_used = role_last_used["LastUsedDate"]
                    if last_used.tzinfo is None:
                        last_used = last_used.replace(tzinfo=timezone.utc)

                # Extract trust policy principals
                trust_policy = role.get("AssumeRolePolicyDocument", {})
                trusted_principals = self._extract_trust_principals(trust_policy)

                ident = Identity(
                    id=f"aws:iam:role:{account_id}:{role_name}",
                    name=role_name,
                    provider=Provider.AWS,
                    identity_type=IdentityType.IAM_ROLE,
                    arn=role_arn,
                    created_at=created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created,
                    last_used=last_used,
                    policies=policies,
                    raw={
                        "path": path,
                        "trusted_principals": trusted_principals,
                        "max_session_duration": role.get("MaxSessionDuration", 3600),
                    },
                )
                identities.append(ident)

        logger.info("Found %d IAM roles", len(identities))
        return identities

    def _get_user_policies(self, username: str) -> List[str]:
        """Get all policy names attached to a user (attached + inline)."""
        iam = self._get_iam()
        policies = []

        try:
            # Attached managed policies
            resp = iam.list_attached_user_policies(UserName=username)
            for p in resp.get("AttachedPolicies", []):
                policies.append(p["PolicyName"])

            # Inline policies
            resp = iam.list_user_policies(UserName=username)
            policies.extend(resp.get("PolicyNames", []))

            # Group policies (users inherit from groups)
            resp = iam.list_groups_for_user(UserName=username)
            for group in resp.get("Groups", []):
                group_resp = iam.list_attached_group_policies(GroupName=group["GroupName"])
                for p in group_resp.get("AttachedPolicies", []):
                    policies.append(f"{group['GroupName']}/{p['PolicyName']}")
        except Exception as e:
            logger.warning("Failed to get policies for user %s: %s", username, e)

        return policies

    def _get_role_policies(self, role_name: str) -> List[str]:
        """Get all policy names attached to a role."""
        iam = self._get_iam()
        policies = []

        try:
            resp = iam.list_attached_role_policies(RoleName=role_name)
            for p in resp.get("AttachedPolicies", []):
                policies.append(p["PolicyName"])

            resp = iam.list_role_policies(RoleName=role_name)
            policies.extend(resp.get("PolicyNames", []))
        except Exception as e:
            logger.warning("Failed to get policies for role %s: %s", role_name, e)

        return policies

    def _has_console_access(self, username: str) -> bool:
        """Check if user has a login profile (console access)."""
        iam = self._get_iam()
        try:
            iam.get_login_profile(UserName=username)
            return True
        except iam.exceptions.NoSuchEntityException:
            return False
        except Exception:
            return False

    def _has_mfa(self, username: str) -> bool:
        """Check if user has MFA devices."""
        iam = self._get_iam()
        try:
            resp = iam.list_mfa_devices(UserName=username)
            return len(resp.get("MFADevices", [])) > 0
        except Exception:
            return False

    @staticmethod
    def _extract_trust_principals(trust_policy: dict) -> List[str]:
        """Extract principal ARNs from a role's trust policy."""
        principals = []
        for statement in trust_policy.get("Statement", []):
            principal = statement.get("Principal", {})
            if isinstance(principal, str):
                principals.append(principal)
            elif isinstance(principal, dict):
                for key in ("AWS", "Service", "Federated"):
                    val = principal.get(key)
                    if isinstance(val, str):
                        principals.append(val)
                    elif isinstance(val, list):
                        principals.extend(val)
        return principals
