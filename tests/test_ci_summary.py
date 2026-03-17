# MIT License — Copyright (c) 2026 cvemula1
# Tests for compact CI summary, ASCII-safe output, and improved path wording

from __future__ import annotations

import io
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from nhinsight.analyzers.attack_paths import (
    AttackPath,
    AttackPathResult,
    AttackPathStep,
)
from nhinsight.core.ci_summary import (
    _build_actions,
    _why_it_matters,
    is_ci,
    print_ci_summary,
    sev_badge,
    sev_icon,
)
from nhinsight.core.models import (
    Classification,
    Identity,
    IdentityType,
    Provider,
    RiskFlag,
    ScanResult,
    Severity,
)
from nhinsight.core.output import (
    SEVERITY_ICONS,
    SEVERITY_ICONS_ASCII,
    print_attack_paths,
    print_result,
    print_table,
)

# ── Helpers ────────────────────────────────────────────────────────────

def _make_demo_result() -> ScanResult:
    """Build a small but realistic ScanResult for testing."""
    now = datetime.now(timezone.utc)
    return ScanResult(
        identities=[
            Identity(
                id="aws:iam:user:123:deploy-bot",
                name="deploy-bot",
                provider=Provider.AWS,
                identity_type=IdentityType.IAM_USER,
                classification=Classification.MACHINE,
                created_at=now - timedelta(days=400),
                policies=["AdministratorAccess"],
                risk_flags=[
                    RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS",
                             "Has AdministratorAccess policy attached",
                             "Critical: machine identity with full AWS access."),
                ],
            ),
            Identity(
                id="aws:iam:role:123:escape-hatch",
                name="escape-hatch",
                provider=Provider.AWS,
                identity_type=IdentityType.IAM_ROLE,
                classification=Classification.MACHINE,
                created_at=now - timedelta(days=700),
                policies=["AdministratorAccess"],
                risk_flags=[
                    RiskFlag(Severity.CRITICAL, "AWS_WILDCARD_TRUST",
                             "Role trust allows any AWS principal (*)",
                             "Critical: any AWS account worldwide can assume this role."),
                ],
            ),
            Identity(
                id="k8s:sa:prod:default:default",
                name="default/default",
                provider=Provider.KUBERNETES,
                identity_type=IdentityType.SERVICE_ACCOUNT,
                classification=Classification.MACHINE,
                created_at=now - timedelta(days=300),
                risk_flags=[
                    RiskFlag(Severity.MEDIUM, "K8S_DEFAULT_SA",
                             "Using default ServiceAccount",
                             "Medium: 3 workloads share the default SA."),
                ],
            ),
            Identity(
                id="github:app:acme:renovate",
                name="renovate",
                provider=Provider.GITHUB,
                identity_type=IdentityType.GITHUB_APP,
                classification=Classification.MACHINE,
                created_at=now - timedelta(days=100),
                risk_flags=[],
            ),
            Identity(
                id="aws:iam:user:123:alice",
                name="alice",
                provider=Provider.AWS,
                identity_type=IdentityType.IAM_USER,
                classification=Classification.HUMAN,
                created_at=now - timedelta(days=200),
                risk_flags=[],
            ),
        ],
        providers_scanned=["aws", "kubernetes", "github"],
        scan_time=now,
    )


def _make_ap_result() -> AttackPathResult:
    """Build a small AttackPathResult for testing."""
    return AttackPathResult(
        paths=[
            AttackPath(
                id="AP-001",
                steps=[
                    AttackPathStep(
                        node_id="deploy-bot",
                        node_label="deploy-bot",
                        node_type="iam_user",
                        provider="aws",
                    ),
                    AttackPathStep(
                        node_id="admin-role",
                        node_label="AdministratorAccess",
                        node_type="iam_role",
                        provider="aws",
                        edge_type="assumes_role",
                        edge_label="assumes",
                    ),
                ],
                severity=Severity.CRITICAL,
                blast_radius=85.0,
                cross_system=False,
                description="deploy-bot can reach AdministratorAccess",
                recommendation="Tighten the role trust policy. Use condition keys.",
            ),
            AttackPath(
                id="AP-002",
                steps=[
                    AttackPathStep(
                        node_id="k8s-sa",
                        node_label="payments/checkout-svc",
                        node_type="service_account",
                        provider="kubernetes",
                    ),
                    AttackPathStep(
                        node_id="aws-role",
                        node_label="checkout-role",
                        node_type="iam_role",
                        provider="aws",
                        edge_type="irsa_maps_to",
                        edge_label="IRSA",
                    ),
                ],
                severity=Severity.HIGH,
                blast_radius=55.0,
                cross_system=True,
                description="checkout-svc can reach checkout-role (crosses kubernetes → aws)",
                recommendation="Scope the IRSA role to least-privilege.",
            ),
        ],
        graph_stats={"nodes": 10, "edges": 8, "entry_points": 3, "privileged_nodes": 2},
    )


# ── CI Summary tests ──────────────────────────────────────────────────

class TestCISummary:
    def test_compact_summary_contains_header(self):
        buf = io.StringIO()
        result = _make_demo_result()
        print_ci_summary(result, None, out=buf)
        output = buf.getvalue()
        assert "## NHInsight Scan Summary" in output

    def test_compact_summary_contains_providers(self):
        buf = io.StringIO()
        result = _make_demo_result()
        print_ci_summary(result, None, out=buf)
        output = buf.getvalue()
        assert "aws" in output
        assert "kubernetes" in output

    def test_compact_summary_contains_severity_table(self):
        buf = io.StringIO()
        result = _make_demo_result()
        print_ci_summary(result, None, out=buf)
        output = buf.getvalue()
        assert "| Severity | Count |" in output
        assert "**CRITICAL**" in output

    def test_compact_summary_contains_top_findings(self):
        buf = io.StringIO()
        result = _make_demo_result()
        print_ci_summary(result, None, out=buf)
        output = buf.getvalue()
        assert "### Top Findings" in output
        assert "`deploy-bot`" in output
        assert "AdministratorAccess" in output

    def test_compact_summary_with_attack_paths(self):
        buf = io.StringIO()
        result = _make_demo_result()
        ap = _make_ap_result()
        print_ci_summary(result, ap, out=buf)
        output = buf.getvalue()
        assert "### Privilege Escalation Paths" in output
        assert "AP-001" in output
        assert "AP-002" in output

    def test_compact_summary_contains_immediate_actions(self):
        buf = io.StringIO()
        result = _make_demo_result()
        print_ci_summary(result, None, out=buf)
        output = buf.getvalue()
        assert "### Immediate Actions" in output
        assert "**deploy-bot**" in output

    def test_compact_summary_footer(self):
        buf = io.StringIO()
        result = _make_demo_result()
        print_ci_summary(result, None, out=buf)
        output = buf.getvalue()
        assert "*Generated by [NHInsight]" in output

    def test_compact_summary_critical_path_details(self):
        buf = io.StringIO()
        result = _make_demo_result()
        ap = _make_ap_result()
        print_ci_summary(result, ap, out=buf)
        output = buf.getvalue()
        assert "<details>" in output
        assert "Critical path details" in output
        assert "**Why it matters:**" in output
        assert "**Fix:**" in output

    def test_identity_counts_correct(self):
        buf = io.StringIO()
        result = _make_demo_result()
        print_ci_summary(result, None, out=buf)
        output = buf.getvalue()
        # 4 NHIs + 1 human
        assert "4 NHIs" in output
        assert "1 humans" in output

    def test_ascii_safe_summary(self):
        buf = io.StringIO()
        result = _make_demo_result()
        ap = _make_ap_result()
        print_ci_summary(result, ap, out=buf, ascii_safe=True)
        output = buf.getvalue()
        # Should not contain any emoji
        assert "🔴" not in output
        assert "🟠" not in output
        assert "⚡" not in output
        # Should still have all key sections
        assert "## NHInsight Scan Summary" in output
        assert "AP-001" in output


# ── ASCII-safe output tests ───────────────────────────────────────────

class TestASCIISafe:
    def test_severity_icons_ascii_all_present(self):
        for sev in Severity:
            assert sev in SEVERITY_ICONS_ASCII
            icon = SEVERITY_ICONS_ASCII[sev]
            assert icon.startswith("[") and icon.endswith("]")
            # Should be pure ASCII
            assert all(ord(c) < 128 for c in icon)

    def test_severity_icons_emoji_present(self):
        for sev in Severity:
            assert sev in SEVERITY_ICONS
            # Should contain non-ASCII (emoji)
            icon = SEVERITY_ICONS[sev]
            assert any(ord(c) > 127 for c in icon)

    def test_sev_icon_function(self):
        assert sev_icon(Severity.CRITICAL, ascii_safe=False) == "🔴"
        assert sev_icon(Severity.CRITICAL, ascii_safe=True) == "[CRITICAL]"
        assert sev_icon(Severity.HIGH, ascii_safe=True) == "[HIGH]"

    def test_sev_badge(self):
        assert sev_badge(Severity.CRITICAL) == "**CRITICAL**"
        assert sev_badge(Severity.LOW) == "**LOW**"

    def test_print_table_ascii_safe(self):
        buf = io.StringIO()
        result = _make_demo_result()
        print_table(result, out=buf, ascii_safe=True)
        output = buf.getvalue()
        # Should use ASCII icons
        assert "[CRITICAL]" in output
        # Should NOT contain emoji
        assert "🔴" not in output

    def test_print_attack_paths_ascii_safe(self):
        buf = io.StringIO()
        ap = _make_ap_result()
        print_attack_paths(ap, out=buf, ascii_safe=True)
        output = buf.getvalue()
        # ASCII icons
        assert "[CRITICAL]" in output or "[HIGH]" in output
        # No emoji
        assert "🔴" not in output
        assert "🟠" not in output
        assert "⚡" not in output
        # Cross-system uses text
        assert "(cross-system)" in output

    def test_print_attack_paths_ascii_safe_tip(self):
        buf = io.StringIO()
        ap = _make_ap_result()
        print_attack_paths(ap, out=buf, ascii_safe=True)
        output = buf.getvalue()
        assert "Tip:" in output
        assert "💡" not in output

    def test_print_result_ascii_safe(self):
        buf = io.StringIO()
        result = _make_demo_result()
        print_result(result, fmt="table", out=buf, ascii_safe=True)
        output = buf.getvalue()
        assert "[CRITICAL]" in output

    def test_is_ci_default(self):
        # In a test environment, CI might or might not be set
        # Just verify it returns a bool
        assert isinstance(is_ci(), bool)


# ── Improved path wording tests ───────────────────────────────────────

class TestPathWording:
    def test_why_it_matters_cross_system(self):
        path = _make_ap_result().paths[1]  # cross-system path
        why = _why_it_matters(path)
        assert "crosses system boundaries" in why
        assert "kubernetes" in why or "aws" in why

    def test_why_it_matters_credential_entry(self):
        path = AttackPath(
            id="AP-TEST",
            steps=[
                AttackPathStep("key-1", "deploy-key", "access_key", "aws"),
                AttackPathStep("role-1", "AdministratorAccess", "iam_role", "aws",
                               edge_type="assumes_role", edge_label="assumes"),
            ],
            severity=Severity.CRITICAL,
            blast_radius=90.0,
            description="deploy-key can reach AdministratorAccess",
        )
        why = _why_it_matters(path)
        assert "leaked credential" in why.lower() or "credential" in why.lower()

    def test_why_it_matters_service_account_entry(self):
        path = AttackPath(
            id="AP-TEST",
            steps=[
                AttackPathStep("sa-1", "checkout-svc", "service_account", "kubernetes"),
                AttackPathStep("role-1", "cluster-admin", "rbac", "kubernetes",
                               edge_type="bound_to_rbac", edge_label="bound"),
            ],
            severity=Severity.CRITICAL,
            blast_radius=85.0,
            description="checkout-svc can reach cluster-admin",
        )
        why = _why_it_matters(path)
        assert "service account" in why.lower()

    def test_why_it_matters_admin_target(self):
        path = _make_ap_result().paths[0]
        why = _why_it_matters(path)
        assert "admin" in why.lower()

    def test_why_it_matters_high_risk_score(self):
        path = _make_ap_result().paths[0]  # blast_radius=85
        why = _why_it_matters(path)
        assert "85/100" in why

    def test_build_actions_prioritizes_critical(self):
        result = _make_demo_result()
        nhis = [i for i in result.identities if i.classification != Classification.HUMAN]
        actions = _build_actions(nhis, None)
        assert len(actions) > 0
        assert "deploy-bot" in actions[0] or "escape-hatch" in actions[0]

    def test_build_actions_includes_path_recs(self):
        result = _make_demo_result()
        nhis = [i for i in result.identities if i.classification != Classification.HUMAN]
        ap = _make_ap_result()
        actions = _build_actions(nhis, ap)
        # Should include both finding-based and path-based actions
        assert any("AP-" in a for a in actions)


# ── CLI integration tests ─────────────────────────────────────────────

class TestCLICISummary:
    def test_demo_ci_summary_runs(self):
        result = subprocess.run(
            [sys.executable, "-m", "nhinsight.cli", "demo", "--ci-summary"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "## NHInsight Scan Summary" in result.stdout
        assert "### Top Findings" in result.stdout
        assert "### Privilege Escalation Paths" in result.stdout

    def test_demo_ci_summary_ascii(self):
        result = subprocess.run(
            [sys.executable, "-m", "nhinsight.cli", "demo", "--ci-summary", "--ascii"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "## NHInsight Scan Summary" in result.stdout
        # No emoji in output
        assert "🔴" not in result.stdout
        assert "⚡" not in result.stdout

    def test_demo_ascii_table(self):
        result = subprocess.run(
            [sys.executable, "-m", "nhinsight.cli", "demo", "--attack-paths", "--ascii"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        # Attack path section should use ASCII icons
        assert "[CRITICAL]" in result.stdout or "[HIGH]" in result.stdout

    def test_demo_ci_summary_has_path_details(self):
        result = subprocess.run(
            [sys.executable, "-m", "nhinsight.cli", "demo", "--ci-summary"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "Immediate Actions" in result.stdout
        assert "Generated by" in result.stdout

    def test_demo_ci_summary_to_file(self, tmp_path):
        outfile = tmp_path / "summary.md"
        result = subprocess.run(
            [sys.executable, "-m", "nhinsight.cli", "demo", "--ci-summary",
             "-o", str(outfile)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        content = outfile.read_text()
        assert "## NHInsight Scan Summary" in content
        assert "### Top Findings" in content
