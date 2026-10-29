"""
Evaluation, Benchmarking, and Reporting (Phase 6).

Provides:
- Evaluator: runs experiments and computes Precision, Recall, F1, FPR
- ReportGenerator: produces a structured final report
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import numpy as np

from .ids_engine import IDSEngine, PolicyDecisionPoint, ExplainabilityModule
from .enforcement import PolicyEnforcementPoint, ContainmentManager
from .monitoring import AuditLogger, PerformanceMonitor
from .schemas import (
    DeviceProfile,
    ExperimentResult,
    PolicyAction,
    TelemetryEvent,
)
from .simulation import ScenarioRunner, DEFAULT_DEVICES


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

class Evaluator:
    """Runs detection experiments and computes evaluation metrics."""

    def __init__(
        self,
        ids_engine: IDSEngine,
        pdp: PolicyDecisionPoint,
        explainer: ExplainabilityModule,
    ):
        self.ids = ids_engine
        self.pdp = pdp
        self.explainer = explainer

    def evaluate(
        self,
        test_events: list[TelemetryEvent],
        scenario_name: str = "default",
    ) -> ExperimentResult:
        """
        Run the IDS + PDP pipeline on a test set and compute metrics.

        Ground truth is taken from event.is_attack.
        A detection is counted when the PDP action is RESTRICT or ISOLATE.
        """
        tp = fp = tn = fn = 0
        latencies: list[float] = []

        for event in test_events:
            start = time.perf_counter()
            assessment = self.ids.predict(event)
            decision = self.pdp.decide(assessment)
            latency = (time.perf_counter() - start) * 1000
            latencies.append(latency)

            is_flagged = decision.action in (PolicyAction.RESTRICT, PolicyAction.ISOLATE)
            is_attack = event.is_attack

            if is_attack and is_flagged:
                tp += 1
            elif is_attack and not is_flagged:
                fn += 1
            elif not is_attack and is_flagged:
                fp += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return ExperimentResult(
            scenario_name=scenario_name,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            false_positive_rate=round(fpr, 4),
            detection_latency_ms=round(float(np.mean(latencies)), 3) if latencies else 0.0,
        )


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generates a structured Markdown report from experiment results."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        results: list[ExperimentResult],
        cross_tenant_report: dict | None = None,
        resource_metrics: dict | None = None,
    ) -> str:
        """Generate and save a comprehensive Markdown report."""
        lines = [
            "# Smart City Zero-Trust IDS — Evaluation Report",
            "",
            f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "---",
            "",
            "## 1. Detection Performance",
            "",
            "| Scenario | Precision | Recall | F1 Score | FPR | Latency (ms) |",
            "| --- | --- | --- | --- | --- | --- |",
        ]

        for r in results:
            lines.append(
                f"| {r.scenario_name} | {r.precision:.4f} | {r.recall:.4f} "
                f"| {r.f1_score:.4f} | {r.false_positive_rate:.4f} | {r.detection_latency_ms:.2f} |"
            )

        lines.append("")
        lines.append("## 2. Cross-Tenant Isolation Validation")
        lines.append("")
        if cross_tenant_report:
            lines.append(f"- **Isolated Device**: `{cross_tenant_report.get('isolated_device', 'N/A')}`")
            lines.append(f"- **Isolated Tenant**: `{cross_tenant_report.get('isolated_tenant', 'N/A')}`")
            lines.append(f"- **Cross-Tenant Impact**: `{cross_tenant_report.get('cross_tenant_impact', 'N/A')}`")
            lines.append("")
            per_tenant = cross_tenant_report.get("per_tenant", {})
            lines.append("| Tenant | Total | Passed | Dropped |")
            lines.append("| --- | --- | --- | --- |")
            for t, c in per_tenant.items():
                lines.append(f"| {t} | {c['total']} | {c['passed']} | {c['dropped']} |")
        else:
            lines.append("_No cross-tenant validation data available._")

        lines.append("")
        lines.append("## 3. Resource Cost Analysis")
        lines.append("")
        if resource_metrics:
            lines.append(f"- **Avg CPU**: {resource_metrics.get('cpu_percent', 0):.1f}%")
            lines.append(f"- **Avg RAM**: {resource_metrics.get('ram_mb', 0):.1f} MB")
            lines.append(f"- **Avg Inference Latency**: {resource_metrics.get('inference_latency_ms', 0):.3f} ms")
        else:
            lines.append("_No resource metrics collected._")

        lines.append("")
        lines.append("## 4. Conclusions")
        lines.append("")
        if results:
            best = max(results, key=lambda r: r.f1_score)
            lines.append(f"- Best F1 score: **{best.f1_score:.4f}** (scenario: {best.scenario_name})")
            lines.append(f"- The system {'successfully' if best.f1_score > 0.7 else 'partially'} "
                         f"detects anomalous behaviour in the simulated smart-city environment.")
        if cross_tenant_report and not cross_tenant_report.get("cross_tenant_impact"):
            lines.append("- ✅ Cross-tenant isolation validated: containing a waste device "
                         "does NOT impact traffic or water tenants.")
        lines.append("")
        lines.append("---")
        lines.append("*Report generated automatically by SmartCityZeroTrust evaluation pipeline.*")

        report_text = "\n".join(lines)
        report_path = self.output_dir / "evaluation_report.md"
        report_path.write_text(report_text, encoding="utf-8")

        return report_text
