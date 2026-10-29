"""
Main orchestrator — runs the full Smart City Zero-Trust IDS pipeline.

Usage:
    python -m src.main              # Run full pipeline (train → simulate → evaluate → report)
    python -m src.main --demo       # Quick demo with fewer events
"""

from __future__ import annotations

import argparse
import json
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(legacy_windows=False, force_terminal=True)

from .schemas import (
    DeviceProfile,
    PolicyAction,
    TenantType,
)
from .simulation import ScenarioRunner, DEFAULT_DEVICES
from .ids_engine import IDSEngine, PolicyDecisionPoint, ExplainabilityModule
from .enforcement import PolicyEnforcementPoint, ContainmentManager
from .monitoring import AuditLogger, PerformanceMonitor
from .evaluation import Evaluator, ReportGenerator

console = Console()


def run_pipeline(total_events: int = 2000, demo: bool = False) -> dict:
    """Execute the full IDS pipeline end-to-end."""
    if demo:
        total_events = 500

    results = {}

    # ── Phase 2: Simulation ──────────────────────────────────────────
    console.print(Panel("[bold cyan]Phase 2: Smart City Simulation[/bold cyan]", expand=False))
    scenario = ScenarioRunner(
        devices=list(DEFAULT_DEVICES),
        attack_device_id="wst-002",
        attack_start_pct=0.3,
        attack_type="data_exfiltration",
    )

    console.print("  [cyan]Generating training & test datasets...[/cyan]")
    train_events = scenario.generate_dataset(total_events)
    test_events = scenario.generate_dataset(total_events // 2)
    console.print(f"  [green]✓ Generated {len(train_events)} training events and {len(test_events)} test events[/green]")

    attack_count = sum(1 for e in train_events if e.is_attack)
    normal_count = len(train_events) - attack_count
    console.print(f"  Training set: {normal_count} normal, {attack_count} attack events")

    # ── Phase 3: IDS Engine ──────────────────────────────────────────
    console.print(Panel("[bold cyan]Phase 3: Training IDS Engine[/bold cyan]", expand=False))
    ids = IDSEngine(contamination=0.15, blend_weight=0.6)
    perf_monitor = PerformanceMonitor()

    console.print("  [cyan]Training hybrid ML models (Isolation Forest + Random Forest)...[/cyan]")
    train_metrics = ids.train(train_events)
    console.print(f"  [green]✓ Training complete — accuracy: {train_metrics['train_accuracy']:.4f}[/green]")

    pdp = PolicyDecisionPoint()
    explainer = ExplainabilityModule()
    audit_logger = AuditLogger(log_path="data/audit_log.jsonl")

    # ── Phase 4: Enforcement & Containment ───────────────────────────
    console.print(Panel("[bold cyan]Phase 4: Policy Enforcement[/bold cyan]", expand=False))
    pep = PolicyEnforcementPoint()
    containment = ContainmentManager(devices=list(DEFAULT_DEVICES), pep=pep)

    console.print("  Running IDS on test events...")
    decisions_summary = {a.value: 0 for a in PolicyAction}
    inference_times = []

    for event in test_events:
        start = time.perf_counter()
        assessment = ids.predict(event)
        decision = pdp.decide(assessment)
        decision, audit_entry = explainer.explain(decision, assessment)
        latency_ms = (time.perf_counter() - start) * 1000
        inference_times.append(latency_ms)

        perf_monitor.record_inference(latency_ms)
        audit_logger.log(audit_entry)

        # Enforce
        pep.update_policy(event.device_id, decision.action)
        decisions_summary[decision.action.value] += 1

    # Display decision distribution
    table = Table(title="Policy Decision Distribution")
    table.add_column("Action", style="bold")
    table.add_column("Count", justify="right")
    for action, count in decisions_summary.items():
        style = {"allow": "green", "monitor": "yellow", "restrict": "orange3", "isolate": "red"}
        table.add_row(action.upper(), str(count), style=style.get(action, ""))
    console.print(table)

    # Cross-tenant validation
    console.print("\n  [bold]Cross-Tenant Isolation Validation:[/bold]")
    containment.isolate_device("wst-002")
    cross_report = containment.validate_cross_tenant_isolation("wst-002", test_events)
    
    for tenant, counts in cross_report["per_tenant"].items():
        status = "🔴 DROPPED" if counts["dropped"] > 0 and tenant == cross_report["isolated_tenant"] else "✅ UNAFFECTED"
        if tenant != cross_report["isolated_tenant"] and counts["dropped"] > 0:
            status = "⚠️ IMPACTED"
        console.print(f"    {tenant}: {status} (passed={counts['passed']}, dropped={counts['dropped']})")

    impact = cross_report["cross_tenant_impact"]
    console.print(f"    Cross-tenant impact: {'⚠️  YES' if impact else '✅ NONE'}")

    # ── Phase 5: Monitoring snapshot ─────────────────────────────────
    console.print(Panel("[bold cyan]Phase 5: System Metrics[/bold cyan]", expand=False))
    metrics = perf_monitor.snapshot(
        active_devices=len(DEFAULT_DEVICES),
        events_per_second=len(test_events) / max(sum(inference_times) / 1000, 0.01),
    )
    console.print(f"  CPU: {metrics.cpu_percent:.1f}%  |  RAM: {metrics.ram_mb:.1f} MB  |  "
                  f"Avg Latency: {metrics.inference_latency_ms:.3f} ms")

    # ── Phase 6: Evaluation & Report ─────────────────────────────────
    console.print(Panel("[bold cyan]Phase 6: Evaluation & Reporting[/bold cyan]", expand=False))
    evaluator = Evaluator(ids, pdp, explainer)

    # Reset PDP state for clean evaluation
    pdp_eval = PolicyDecisionPoint()
    evaluator_clean = Evaluator(ids, pdp_eval, explainer)
    exp_result = evaluator_clean.evaluate(test_events, scenario_name="compromised_waste_bin")

    result_table = Table(title="Experiment Results")
    result_table.add_column("Metric", style="bold")
    result_table.add_column("Value", justify="right")
    result_table.add_row("Precision", f"{exp_result.precision:.4f}")
    result_table.add_row("Recall", f"{exp_result.recall:.4f}")
    result_table.add_row("F1 Score", f"{exp_result.f1_score:.4f}")
    result_table.add_row("False Positive Rate", f"{exp_result.false_positive_rate:.4f}")
    result_table.add_row("Avg Detection Latency", f"{exp_result.detection_latency_ms:.2f} ms")
    console.print(result_table)

    # Generate report
    report_gen = ReportGenerator(output_dir="reports")
    resource_avgs = perf_monitor.get_averages()
    report_text = report_gen.generate(
        results=[exp_result],
        cross_tenant_report=cross_report,
        resource_metrics=resource_avgs,
    )
    console.print(f"\n  [green]✓ Report saved to reports/evaluation_report.md[/green]")

    console.print(Panel("[bold green]✅ Pipeline Complete[/bold green]", expand=False))

    return {
        "train_metrics": train_metrics,
        "experiment_result": exp_result.model_dump(),
        "cross_tenant_report": cross_report,
        "resource_metrics": resource_avgs,
        "pep_stats": pep.stats,
        "audit_entries": audit_logger.total_entries,
    }


def main():
    parser = argparse.ArgumentParser(description="Smart City Zero-Trust IDS Pipeline")
    parser.add_argument("--demo", action="store_true", help="Run quick demo with fewer events")
    parser.add_argument("--events", type=int, default=2000, help="Total training events")
    args = parser.parse_args()

    results = run_pipeline(total_events=args.events, demo=args.demo)
    console.print("\n[dim]Final results JSON:[/dim]")
    console.print_json(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
