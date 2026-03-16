# MIT License — Copyright (c) 2026 cvemula1

from datetime import datetime, timedelta, timezone

import pytest

from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import (
    Identity,
    IdentityType,
    Provider,
)


@pytest.fixture
def config():
    return NHInsightConfig(
        stale_days=90,
        rotation_max_days=365,
    )


@pytest.fixture
def now():
    return datetime.now(timezone.utc)


@pytest.fixture
def machine_user(now):
    """An IAM user that looks like a machine identity."""
    return Identity(
        id="aws:iam:user:123456789012:deploy-bot",
        name="deploy-bot",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        created_at=now - timedelta(days=500),
        last_used=now - timedelta(hours=2),
        policies=["AdministratorAccess"],
        raw={"has_console_access": False, "has_mfa": False},
    )


@pytest.fixture
def human_user(now):
    """An IAM user that looks like a human identity."""
    return Identity(
        id="aws:iam:user:123456789012:alice.smith",
        name="alice.smith",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        created_at=now - timedelta(days=365),
        last_used=now - timedelta(hours=1),
        policies=["ViewOnlyAccess"],
        raw={"has_console_access": True, "has_mfa": True},
    )


@pytest.fixture
def stale_key(now):
    """An access key that hasn't been used in a long time."""
    return Identity(
        id="aws:iam:key:123456789012:AKIASTALE",
        name="ci-runner/AKIASTALE",
        provider=Provider.AWS,
        identity_type=IdentityType.ACCESS_KEY,
        created_at=now - timedelta(days=600),
        last_used=now - timedelta(days=200),
        created_by="ci-runner",
        raw={"key_id": "AKIASTALE", "status": "Active", "parent_user": "ci-runner"},
    )


@pytest.fixture
def healthy_role(now):
    """A role with reasonable permissions and recent use."""
    return Identity(
        id="aws:iam:role:123456789012:ecs-task-role",
        name="ecs-task-role",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_ROLE,
        created_at=now - timedelta(days=90),
        last_used=now - timedelta(hours=1),
        policies=["AmazonECSTaskExecutionRolePolicy"],
        raw={"trusted_principals": ["ecs-tasks.amazonaws.com"], "path": "/"},
    )


@pytest.fixture
def wildcard_role(now):
    """A role with wildcard trust policy."""
    return Identity(
        id="aws:iam:role:123456789012:escape-hatch",
        name="escape-hatch",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_ROLE,
        created_at=now - timedelta(days=730),
        policies=["AdministratorAccess"],
        raw={"trusted_principals": ["*"], "path": "/"},
    )
