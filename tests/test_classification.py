# MIT License — Copyright (c) 2026 cvemula1
# Tests for identity classification

from nhinsight.analyzers.classification import _classify_single, classify_identities
from nhinsight.core.models import (
    Classification,
    Identity,
    IdentityType,
    Provider,
)


def test_access_key_always_machine():
    ident = Identity(
        id="test", name="anything",
        provider=Provider.AWS,
        identity_type=IdentityType.ACCESS_KEY,
    )
    assert _classify_single(ident) == Classification.MACHINE


def test_iam_role_always_machine():
    ident = Identity(
        id="test", name="my-role",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_ROLE,
    )
    assert _classify_single(ident) == Classification.MACHINE


def test_service_account_always_machine():
    ident = Identity(
        id="test", name="default",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
    )
    assert _classify_single(ident) == Classification.MACHINE


def test_deploy_key_always_machine():
    ident = Identity(
        id="test", name="prod-deploy",
        provider=Provider.GITHUB,
        identity_type=IdentityType.DEPLOY_KEY,
    )
    assert _classify_single(ident) == Classification.MACHINE


def test_machine_name_prefix():
    ident = Identity(
        id="test", name="svc-payment-api",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        raw={"has_console_access": False, "has_mfa": False},
    )
    assert _classify_single(ident) == Classification.MACHINE


def test_bot_name_prefix():
    ident = Identity(
        id="test", name="bot-github-actions",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        raw={"has_console_access": False, "has_mfa": False},
    )
    assert _classify_single(ident) == Classification.MACHINE


def test_human_with_console_and_mfa():
    ident = Identity(
        id="test", name="john.doe",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        raw={"has_console_access": True, "has_mfa": True},
    )
    assert _classify_single(ident) == Classification.HUMAN


def test_human_with_email_pattern():
    ident = Identity(
        id="test", name="alice@company.com",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        raw={"has_console_access": True, "has_mfa": False},
    )
    assert _classify_single(ident) == Classification.HUMAN


def test_unknown_ambiguous():
    ident = Identity(
        id="test", name="dataloader",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        raw={"has_console_access": False, "has_mfa": False},
    )
    # No strong signals either way
    result = _classify_single(ident)
    assert result in (Classification.MACHINE, Classification.UNKNOWN)


def test_classify_identities_batch(machine_user, human_user):
    identities = [machine_user, human_user]
    classify_identities(identities)
    assert machine_user.classification == Classification.MACHINE
    assert human_user.classification == Classification.HUMAN
