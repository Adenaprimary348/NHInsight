# MIT License — Copyright (c) 2026 cvemula1
# Tests for output formatting

import io
import json

from nhinsight.core.models import (
    Classification,
    Identity,
    IdentityType,
    Provider,
    RiskFlag,
    ScanResult,
    Severity,
)
from nhinsight.core.output import print_json, print_sarif, print_table


def _make_result():
    return ScanResult(
        identities=[
            Identity(
                id="1", name="deploy-bot",
                provider=Provider.AWS,
                identity_type=IdentityType.IAM_USER,
                classification=Classification.MACHINE,
                policies=["AdministratorAccess"],
                risk_flags=[
                    RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS", "Has admin access"),
                ],
            ),
            Identity(
                id="2", name="alice.smith",
                provider=Provider.AWS,
                identity_type=IdentityType.IAM_USER,
                classification=Classification.HUMAN,
            ),
        ],
        providers_scanned=["aws"],
    )


def test_print_table():
    result = _make_result()
    buf = io.StringIO()
    print_table(result, out=buf)
    output = buf.getvalue()
    assert "NHInsight" in output
    assert "deploy-bot" in output
    assert "CRITICAL" in output


def test_print_json():
    result = _make_result()
    buf = io.StringIO()
    print_json(result, out=buf)
    data = json.loads(buf.getvalue())
    assert data["total"] == 2
    assert data["critical"] == 1
    assert len(data["identities"]) == 2


def test_print_sarif():
    result = _make_result()
    buf = io.StringIO()
    print_sarif(result, out=buf)
    sarif = json.loads(buf.getvalue())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "AWS_ADMIN_ACCESS"
