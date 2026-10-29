"""
Tests for the Smart City Zero-Trust IDS.

Covers:
- Schema validation
- Simulation data generation
- IDS engine training and inference
- Policy decision logic
- Enforcement (PEP) behaviour
- Cross-tenant isolation validation
- Audit logging
- Evaluation metrics
"""

import time
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.schemas import (
    DeviceProfile, TelemetryEvent, TrustAssessment, PolicyDecision,
    AuditLogEntry, PolicyAction, TenantType, DeviceStatus, AlertSeverity,
    DashboardDeviceState, SystemMetrics, ExperimentResult,
)
from src.simulation import (
    DeviceSimulator, ScenarioRunner, TrafficPipeline, DEFAULT_DEVICES,
)
from src.ids_engine import (
    IDSEngine, PolicyDecisionPoint, ExplainabilityModule, extract_features,
)
from src.enforcement import PolicyEnforcementPoint, ContainmentManager
from src.monitoring import AuditLogger, PerformanceMonitor
from src.evaluation import Evaluator, ReportGenerator


# ---------------------------------------------------------------------------
# Schema Tests
# ---------------------------------------------------------------------------

class TestSchemas:
    def test_device_profile_defaults(self):
        dp = DeviceProfile(name="test", tenant=TenantType.TRAFFIC, device_type="sensor")
        assert dp.status == DeviceStatus.NORMAL
        assert dp.normal_packet_rate == 10.0

    def test_telemetry_event_creation(self):
        e = TelemetryEvent(
            device_id="dev-1", tenant=TenantType.WASTE,
            source_ip="10.0.0.1", dest_ip="10.0.0.2",
            packet_rate=15.0, payload_size=200.0, dest_count=3,
        )
        assert e.is_attack is False
        assert e.protocol == "MQTT"

    def test_policy_action_enum(self):
        assert PolicyAction.ISOLATE.value == "isolate"
        assert PolicyAction.ALLOW.value == "allow"

    def test_trust_assessment_bounds(self):
        ta = TrustAssessment(
            event_id="e1", device_id="d1", tenant=TenantType.WATER,
            anomaly_score=0.5, trust_score=0.5,
        )
        assert 0.0 <= ta.anomaly_score <= 1.0
        assert 0.0 <= ta.trust_score <= 1.0


# ---------------------------------------------------------------------------
# Simulation Tests
# ---------------------------------------------------------------------------

class TestSimulation:
    def test_default_devices_count(self):
        assert len(DEFAULT_DEVICES) == 6

    def test_device_simulator_normal(self):
        dp = DeviceProfile(
            device_id="test-001", name="Test",
            tenant=TenantType.TRAFFIC, device_type="sensor",
        )
        sim = DeviceSimulator(dp)
        event = sim.generate_normal_event()
        assert event.device_id == "test-001"
        assert event.is_attack is False

    def test_device_simulator_attack(self):
        dp = DeviceProfile(
            device_id="test-001", name="Test",
            tenant=TenantType.WASTE, device_type="sensor",
        )
        sim = DeviceSimulator(dp)
        event = sim.generate_attack_event("scan")
        assert event.is_attack is True
        assert event.attack_type == "scan"

    def test_scenario_runner_produces_attacks(self):
        runner = ScenarioRunner(attack_device_id="wst-002", attack_start_pct=0.3)
        events = runner.generate_dataset(200)
        attack_events = [e for e in events if e.is_attack]
        assert len(attack_events) > 0

    def test_scenario_runner_normal_devices_clean(self):
        runner = ScenarioRunner(attack_device_id="wst-002")
        events = runner.generate_dataset(200)
        non_target_attacks = [e for e in events if e.is_attack and e.device_id != "wst-002"]
        assert len(non_target_attacks) == 0


# ---------------------------------------------------------------------------
# IDS Engine Tests
# ---------------------------------------------------------------------------

class TestIDSEngine:
    @pytest.fixture
    def trained_ids(self):
        runner = ScenarioRunner(attack_device_id="wst-002", attack_start_pct=0.3)
        events = runner.generate_dataset(500)
        ids = IDSEngine(contamination=0.15)
        ids.train(events)
        return ids, events

    def test_training(self, trained_ids):
        ids, events = trained_ids
        assert ids._is_trained is True

    def test_predict_returns_assessment(self, trained_ids):
        ids, events = trained_ids
        assessment = ids.predict(events[0])
        assert isinstance(assessment, TrustAssessment)
        assert 0.0 <= assessment.anomaly_score <= 1.0

    def test_attack_events_get_higher_anomaly(self, trained_ids):
        ids, events = trained_ids
        normal_events = [e for e in events if not e.is_attack][:20]
        attack_events = [e for e in events if e.is_attack][:20]

        if normal_events and attack_events:
            normal_scores = [ids.predict(e).anomaly_score for e in normal_events]
            attack_scores = [ids.predict(e).anomaly_score for e in attack_events]
            # On average, attacks should score higher
            assert sum(attack_scores) / len(attack_scores) > sum(normal_scores) / len(normal_scores)

    def test_feature_extraction(self):
        e = TelemetryEvent(
            device_id="d1", tenant=TenantType.TRAFFIC,
            source_ip="1.2.3.4", dest_ip="5.6.7.8",
            packet_rate=10.0, payload_size=128.0, dest_count=2,
        )
        features = extract_features(e)
        assert len(features) == 7


# ---------------------------------------------------------------------------
# PDP Tests
# ---------------------------------------------------------------------------

class TestPDP:
    def test_allow_high_trust(self):
        pdp = PolicyDecisionPoint()
        ta = TrustAssessment(
            event_id="e1", device_id="d1", tenant=TenantType.TRAFFIC,
            anomaly_score=0.1, trust_score=0.9,
        )
        decision = pdp.decide(ta)
        assert decision.action == PolicyAction.ALLOW

    def test_isolate_low_trust(self):
        pdp = PolicyDecisionPoint()
        ta = TrustAssessment(
            event_id="e1", device_id="d1", tenant=TenantType.WASTE,
            anomaly_score=0.95, trust_score=0.05,
        )
        decision = pdp.decide(ta)
        assert decision.action == PolicyAction.ISOLATE

    def test_monitor_medium_trust(self):
        pdp = PolicyDecisionPoint()
        ta = TrustAssessment(
            event_id="e1", device_id="d1", tenant=TenantType.WATER,
            anomaly_score=0.3, trust_score=0.7,
        )
        decision = pdp.decide(ta)
        assert decision.action == PolicyAction.MONITOR

    def test_previous_action_tracking(self):
        pdp = PolicyDecisionPoint()
        ta1 = TrustAssessment(
            event_id="e1", device_id="d1", tenant=TenantType.TRAFFIC,
            anomaly_score=0.1, trust_score=0.9,
        )
        pdp.decide(ta1)
        ta2 = TrustAssessment(
            event_id="e2", device_id="d1", tenant=TenantType.TRAFFIC,
            anomaly_score=0.95, trust_score=0.05,
        )
        d2 = pdp.decide(ta2)
        assert d2.previous_action == PolicyAction.ALLOW
        assert d2.action == PolicyAction.ISOLATE


# ---------------------------------------------------------------------------
# PEP Tests
# ---------------------------------------------------------------------------

class TestPEP:
    def test_default_allow(self):
        pep = PolicyEnforcementPoint()
        event = TelemetryEvent(
            device_id="d1", tenant=TenantType.TRAFFIC,
            source_ip="1.2.3.4", dest_ip="5.6.7.8",
            packet_rate=10.0, payload_size=128.0, dest_count=2,
        )
        allowed, reason = pep.enforce(event)
        assert allowed is True

    def test_isolate_drops_traffic(self):
        pep = PolicyEnforcementPoint()
        pep.update_policy("d1", PolicyAction.ISOLATE)
        event = TelemetryEvent(
            device_id="d1", tenant=TenantType.WASTE,
            source_ip="1.2.3.4", dest_ip="5.6.7.8",
            packet_rate=10.0, payload_size=128.0, dest_count=2,
        )
        allowed, reason = pep.enforce(event)
        assert allowed is False
        assert "DROPPED" in reason

    def test_restrict_rate_limits(self):
        pep = PolicyEnforcementPoint(restrict_ratio=3)
        pep.update_policy("d1", PolicyAction.RESTRICT)
        event = TelemetryEvent(
            device_id="d1", tenant=TenantType.WATER,
            source_ip="1.2.3.4", dest_ip="5.6.7.8",
            packet_rate=10.0, payload_size=128.0, dest_count=2,
        )
        results = [pep.enforce(event)[0] for _ in range(6)]
        # With ratio=3, every 3rd packet passes
        assert True in results
        assert False in results


# ---------------------------------------------------------------------------
# Cross-Tenant Isolation Tests
# ---------------------------------------------------------------------------

class TestCrossTenantIsolation:
    def test_isolation_does_not_affect_other_tenants(self):
        pep = PolicyEnforcementPoint()
        containment = ContainmentManager(devices=list(DEFAULT_DEVICES), pep=pep)

        # Generate test events
        runner = ScenarioRunner()
        test_events = runner.generate_dataset(100)

        # Isolate waste device
        containment.isolate_device("wst-002")

        report = containment.validate_cross_tenant_isolation("wst-002", test_events)
        assert report["cross_tenant_impact"] is False

    def test_isolated_device_traffic_dropped(self):
        pep = PolicyEnforcementPoint()
        containment = ContainmentManager(devices=list(DEFAULT_DEVICES), pep=pep)
        containment.isolate_device("wst-002")

        event = TelemetryEvent(
            device_id="wst-002", tenant=TenantType.WASTE,
            source_ip="10.2.1.2", dest_ip="10.2.1.1",
            packet_rate=50.0, payload_size=500.0, dest_count=10,
        )
        allowed, _ = pep.enforce(event)
        assert allowed is False


# ---------------------------------------------------------------------------
# Explainability Tests
# ---------------------------------------------------------------------------

class TestExplainability:
    def test_explanation_generated(self):
        explainer = ExplainabilityModule()
        ta = TrustAssessment(
            event_id="e1", device_id="wst-002", tenant=TenantType.WASTE,
            anomaly_score=0.9, trust_score=0.1,
            feature_contributions={"packet_rate": 0.4, "payload_size": 0.3, "dest_count": 0.2},
        )
        decision = PolicyDecision(
            device_id="wst-002", tenant=TenantType.WASTE, event_id="e1",
            action=PolicyAction.ISOLATE, trust_score=0.1, anomaly_score=0.9,
        )
        decision, audit = explainer.explain(decision, ta)
        assert len(decision.explanation) > 0
        assert "ISOLATED" in decision.explanation
        assert audit.severity == AlertSeverity.CRITICAL


# ---------------------------------------------------------------------------
# Evaluation Tests
# ---------------------------------------------------------------------------

class TestEvaluation:
    def test_evaluator_returns_result(self):
        runner = ScenarioRunner(attack_device_id="wst-002")
        train_events = runner.generate_dataset(500)
        test_events = runner.generate_dataset(200)

        ids = IDSEngine()
        ids.train(train_events)
        pdp = PolicyDecisionPoint()
        explainer = ExplainabilityModule()
        evaluator = Evaluator(ids, pdp, explainer)

        result = evaluator.evaluate(test_events, "test_scenario")
        assert isinstance(result, ExperimentResult)
        assert 0.0 <= result.precision <= 1.0
        assert 0.0 <= result.recall <= 1.0
        assert 0.0 <= result.f1_score <= 1.0

    def test_report_generation(self, tmp_path):
        result = ExperimentResult(
            scenario_name="test",
            precision=0.85,
            recall=0.90,
            f1_score=0.87,
            false_positive_rate=0.05,
        )
        gen = ReportGenerator(output_dir=str(tmp_path))
        report = gen.generate([result])
        assert "Precision" in report
        assert "0.8500" in report
        report_file = tmp_path / "evaluation_report.md"
        assert report_file.exists()
