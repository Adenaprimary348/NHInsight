# MIT License — Copyright (c) 2026 cvemula1
# GitHub provider — discovers GitHub Apps, deploy keys, webhooks, and org-level identities

from __future__ import annotations

import logging
from datetime import timezone
from typing import List

from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import Identity, IdentityType, Provider
from nhinsight.providers.base import BaseProvider

logger = logging.getLogger(__name__)


class GitHubProvider(BaseProvider):
    """Discover non-human identities in a GitHub organization."""

    name = "github"

    def __init__(self, config: NHInsightConfig):
        super().__init__(config)
        self._github = None

    def _get_client(self):
        """Create a PyGithub client using GITHUB_TOKEN or GH_TOKEN."""
        if self._github is None:
            from github import Github

            token = self.config.github_token
            if not token:
                raise ValueError(
                    "GitHub token is required. Set GITHUB_TOKEN or GH_TOKEN."
                )
            kwargs = {"login_or_token": token}
            if self.config.github_base_url:
                kwargs["base_url"] = self.config.github_base_url
            self._github = Github(**kwargs)
        return self._github

    def is_available(self) -> bool:
        try:
            g = self._get_client()
            g.get_user().login
            return True
        except Exception:
            return False

    def discover(self) -> List[Identity]:
        """Discover all NHIs in a GitHub organization."""
        identities: List[Identity] = []

        try:
            g = self._get_client()
            org_name = self.config.github_org

            if not org_name:
                # Fall back to authenticated user's repos
                logger.info("No GITHUB_ORG set, scanning authenticated user's repos")
                identities.extend(self._discover_user_repos(g))
            else:
                logger.info("Scanning GitHub org: %s", org_name)
                org = g.get_organization(org_name)
                identities.extend(self._discover_org_apps(org))
                identities.extend(self._discover_org_hooks(org))
                identities.extend(self._discover_repo_deploy_keys(org))
                identities.extend(self._discover_repo_hooks(org))

        except ImportError:
            logger.error("PyGithub not installed. Run: pip install PyGithub")
        except Exception as e:
            logger.error("GitHub discovery failed: %s", e)

        return identities

    def _discover_user_repos(self, g) -> List[Identity]:
        """Discover deploy keys and webhooks across the authenticated user's repos."""
        identities: List[Identity] = []
        user = g.get_user()

        for repo in user.get_repos(type="owner"):
            identities.extend(self._get_deploy_keys_for_repo(repo))
            identities.extend(self._get_hooks_for_repo(repo))

        logger.info("Found %d NHIs across user repos", len(identities))
        return identities

    def _discover_org_apps(self, org) -> List[Identity]:
        """Discover GitHub Apps installed on the organization."""
        identities: List[Identity] = []

        try:
            installations = org.get_installations()
            for install in installations:
                app = install.app
                app_name = app.name if hasattr(app, "name") else str(install.id)
                app_slug = app.slug if hasattr(app, "slug") else app_name

                created = install.created_at
                if created and created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)

                permissions = {}
                if hasattr(install, "permissions"):
                    permissions = install.permissions or {}

                # Extract permission names with write/admin access
                dangerous_perms = [
                    f"{k}:{v}" for k, v in permissions.items()
                    if v in ("write", "admin")
                ] if isinstance(permissions, dict) else []

                ident = Identity(
                    id=f"github:app:{org.login}:{install.id}",
                    name=f"{app_slug} (app)",
                    provider=Provider.GITHUB,
                    identity_type=IdentityType.GITHUB_APP,
                    created_at=created,
                    owner=org.login,
                    permissions=dangerous_perms,
                    raw={
                        "app_id": app.id if hasattr(app, "id") else None,
                        "app_slug": app_slug,
                        "installation_id": install.id,
                        "target_type": install.target_type,
                        "all_permissions": dict(permissions) if isinstance(permissions, dict) else {},
                    },
                )
                identities.append(ident)

        except Exception as e:
            logger.warning("Failed to list org apps for %s: %s", org.login, e)

        logger.info("Found %d GitHub Apps", len(identities))
        return identities

    def _discover_org_hooks(self, org) -> List[Identity]:
        """Discover organization-level webhooks."""
        identities: List[Identity] = []

        try:
            for hook in org.get_hooks():
                hook_url = hook.config.get("url", "unknown") if hook.config else "unknown"
                created = hook.created_at
                if created and created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)

                last_response = hook.last_response
                last_status = None
                if last_response and hasattr(last_response, "code"):
                    last_status = last_response.code

                ident = Identity(
                    id=f"github:hook:org:{org.login}:{hook.id}",
                    name=f"org-webhook → {self._mask_url(hook_url)}",
                    provider=Provider.GITHUB,
                    identity_type=IdentityType.WEBHOOK,
                    created_at=created,
                    owner=org.login,
                    raw={
                        "hook_id": hook.id,
                        "url": hook_url,
                        "events": hook.events,
                        "active": hook.active,
                        "last_response_status": last_status,
                        "scope": "organization",
                    },
                )
                identities.append(ident)

        except Exception as e:
            logger.warning("Failed to list org hooks for %s: %s", org.login, e)

        return identities

    def _discover_repo_deploy_keys(self, org) -> List[Identity]:
        """Discover deploy keys across all org repositories."""
        identities: List[Identity] = []

        try:
            for repo in org.get_repos():
                identities.extend(self._get_deploy_keys_for_repo(repo))
        except Exception as e:
            logger.warning("Failed to iterate repos for deploy keys: %s", e)

        logger.info("Found %d deploy keys", len(identities))
        return identities

    def _discover_repo_hooks(self, org) -> List[Identity]:
        """Discover webhooks across all org repositories."""
        identities: List[Identity] = []

        try:
            for repo in org.get_repos():
                identities.extend(self._get_hooks_for_repo(repo))
        except Exception as e:
            logger.warning("Failed to iterate repos for hooks: %s", e)

        return identities

    def _get_deploy_keys_for_repo(self, repo) -> List[Identity]:
        """Get deploy keys for a single repository."""
        identities: List[Identity] = []

        try:
            for key in repo.get_keys():
                created = key.created_at
                if created and created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)

                last_used = key.last_used
                if last_used and hasattr(last_used, "tzinfo") and last_used.tzinfo is None:
                    last_used = last_used.replace(tzinfo=timezone.utc)

                permissions = []
                if getattr(key, "read_only", True) is False:
                    permissions.append("repo:write")
                else:
                    permissions.append("repo:read")

                ident = Identity(
                    id=f"github:deploy_key:{repo.full_name}:{key.id}",
                    name=f"{key.title} → {repo.full_name}",
                    provider=Provider.GITHUB,
                    identity_type=IdentityType.DEPLOY_KEY,
                    created_at=created,
                    last_used=last_used if isinstance(last_used, type(created)) else None,
                    owner=repo.full_name,
                    permissions=permissions,
                    raw={
                        "key_id": key.id,
                        "title": key.title,
                        "read_only": getattr(key, "read_only", True),
                        "repo": repo.full_name,
                        "verified": getattr(key, "verified", None),
                    },
                )
                identities.append(ident)

        except Exception as e:
            logger.debug("Failed to list deploy keys for %s: %s", repo.full_name, e)

        return identities

    def _get_hooks_for_repo(self, repo) -> List[Identity]:
        """Get webhooks for a single repository."""
        identities: List[Identity] = []

        try:
            for hook in repo.get_hooks():
                hook_url = hook.config.get("url", "unknown") if hook.config else "unknown"
                created = hook.created_at
                if created and created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)

                ident = Identity(
                    id=f"github:hook:repo:{repo.full_name}:{hook.id}",
                    name=f"webhook → {self._mask_url(hook_url)} ({repo.name})",
                    provider=Provider.GITHUB,
                    identity_type=IdentityType.WEBHOOK,
                    created_at=created,
                    owner=repo.full_name,
                    raw={
                        "hook_id": hook.id,
                        "url": hook_url,
                        "events": hook.events,
                        "active": hook.active,
                        "repo": repo.full_name,
                        "scope": "repository",
                    },
                )
                identities.append(ident)

        except Exception as e:
            logger.debug("Failed to list hooks for %s: %s", repo.full_name, e)

        return identities

    @staticmethod
    def _mask_url(url: str) -> str:
        """Mask webhook URLs to avoid leaking secrets in output."""
        if not url or url == "unknown":
            return url
        # Show domain only
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}/..."
        except Exception:
            return url[:30] + "..."
