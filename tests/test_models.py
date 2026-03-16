# MIT License — Copyright (c) 2026 cvemula1
# Tests for core data models

from datetime import datetime, timedelta, timezone

from nhinsight.core.models import (
    Classification,
    Identity,
    IdentityType,
    Provider,
    RiskFlag,
    ScanResult,
    Severity,
)


def test_identity_age_days():
    now = datetime.now(timezone.utc)
    ident = Identity(
        id="test",
        name="test",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        created_at=now - timedelta(days=100),
    )
    assert ident.age_days == 100


def test_identity_age_days_none():
    ident = Identity(
        id="test",
        name="test",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
    )
    assert ident.age_days is None


def test_identity_days_since_last_used():
    now = datetime.now(timezone.utc)
    ident = Identity(
        id="test",
        name="test",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        last_used=now - timedelta(days=50),
    )
    assert ident.days_since_last_used == 50


def test_identity_highest_severity():
    ident = Identity(
        id="test",
        name="test",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        risk_flags=[
            RiskFlag(Severity.MEDIUM, "TEST_MED", "Medium risk"),
            RiskFlag(Severity.CRITICAL, "TEST_CRIT", "Critical risk"),
            RiskFlag(Severity.LOW, "TEST_LOW", "Low risk"),
        ],
    )
    assert ident.highest_severity == Severity.CRITICAL


def test_identity_highest_severity_no_flags():
    ident = Identity(
        id="test",
        name="test",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
    )
    assert ident.highest_severity == Severity.INFO


def test_identity_to_dict():
    now = datetime.now(timezone.utc)
    ident = Identity(
        id="test-id",
        name="test-name",
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        classification=Classification.MACHINE,
        created_at=now,
        policies=["ViewOnlyAccess"],
        risk_flags=[
            RiskFlag(Severity.HIGH, "TEST", "test message", "test detail"),
        ],
    )
    d = ident.to_dict()
    assert d["id"] == "test-id"
    assert d["name"] == "test-name"
    assert d["provider"] == "aws"
    assert d["classification"] == "machine"
    assert d["highest_severity"] == "high"
    assert len(d["risk_flags"]) == 1
    assert d["risk_flags"][0]["code"] == "TEST"


def test_scan_result_counts():
    result = ScanResult(
        identities=[
            Identity(
                id="1", name="a", provider=Provider.AWS,
                identity_type=IdentityType.IAM_USER,
                risk_flags=[RiskFlag(Severity.CRITICAL, "C", "c")],
            ),
            Identity(
                id="2", name="b", provider=Provider.AWS,
                identity_type=IdentityType.IAM_USER,
                risk_flags=[RiskFlag(Severity.HIGH, "H", "h")],
            ),
            Identity(
                id="3", name="c", provider=Provider.AWS,
                identity_type=IdentityType.IAM_USER,
                risk_flags=[RiskFlag(Severity.MEDIUM, "M", "m")],
            ),
            Identity(
                id="4", name="d", provider=Provider.AWS,
                identity_type=IdentityType.IAM_USER,
            ),
        ],
    )
    assert result.total == 4
    assert result.critical_count == 1
    assert result.high_count == 1
    assert result.medium_count == 1
    assert result.healthy_count == 1
