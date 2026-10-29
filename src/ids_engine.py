"""
Explainable Adaptive Zero-Trust IDS Engine (Phase 3).

Provides:
- IDSEngine: ML-based anomaly detection (Isolation Forest + Random Forest)
- PolicyDecisionPoint: converts ML scores into discrete policy actions
- ExplainabilityModule: human-readable, evidence-backed explanations
"""

from __future__ import annotations

import time
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from .schemas import (
    AlertSeverity,
    AuditLogEntry,
    PolicyAction,
    PolicyDecision,
    TelemetryEvent,
    TrustAssessment,
)


# ---------------------------------------------------------------------------
# Feature Extraction
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "packet_rate",
    "payload_size",
    "dest_count",
    "is_encrypted",
    "protocol_mqtt",
    "protocol_http",
    "protocol_raw",
]


def extract_features(event: TelemetryEvent) -> np.ndarray:
    """Convert a telemetry event into a numeric feature vector."""
    return np.array([
        event.packet_rate,
        event.payload_size,
        event.dest_count,
        1.0 if event.is_encrypted else 0.0,
        1.0 if event.protocol == "MQTT" else 0.0,
        1.0 if event.protocol == "HTTP" else 0.0,
        1.0 if event.protocol == "RAW_TCP" else 0.0,
    ])


def events_to_matrix(events: list[TelemetryEvent]) -> np.ndarray:
    """Convert a list of telemetry events to a feature matrix."""
    return np.vstack([extract_features(e) for e in events])


# ---------------------------------------------------------------------------
# IDS Engine
# ---------------------------------------------------------------------------

class IDSEngine:
    """
    Hybrid ML-based Intrusion Detection System.

    Uses an Isolation Forest for unsupervised anomaly scoring and a
    Random Forest classifier trained on labelled scenarios for supervised
    classification.  Both outputs are blended into a single anomaly score.
    """

    def __init__(self, contamination: float = 0.15, blend_weight: float = 0.6):
        self.scaler = StandardScaler()
        self.iso_forest = IsolationForest(
            contamination=contamination,
            n_estimators=150,
            random_state=42,
        )
        self.rf_classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=8,
            random_state=42,
        )
        self.blend_weight = blend_weight  # weight for supervised vs unsupervised
        self._is_trained = False

    # ----- Training -----

    def train(self, events: list[TelemetryEvent]) -> dict[str, float]:
        """Train both models on a labelled dataset."""
        X = events_to_matrix(events)
        y = np.array([1 if e.is_attack else 0 for e in events])

        X_scaled = self.scaler.fit_transform(X)

        # Unsupervised — Isolation Forest
        self.iso_forest.fit(X_scaled)

        # Supervised — Random Forest
        self.rf_classifier.fit(X_scaled, y)
        train_acc = float(self.rf_classifier.score(X_scaled, y))

        self._is_trained = True
        return {"train_accuracy": train_acc, "samples": len(events)}

    # ----- Inference -----

    def predict(self, event: TelemetryEvent) -> TrustAssessment:
        """Score a single telemetry event and return a TrustAssessment."""
        if not self._is_trained:
            raise RuntimeError("IDS engine has not been trained yet.")

        start = time.perf_counter()
        x = extract_features(event).reshape(1, -1)
        x_scaled = self.scaler.transform(x)

        # Isolation Forest: decision_function returns negative for anomalies
        iso_raw = self.iso_forest.decision_function(x_scaled)[0]
        iso_score = float(np.clip(1.0 - (iso_raw + 0.5), 0.0, 1.0))

        # Random Forest: probability of attack class
        rf_proba = float(self.rf_classifier.predict_proba(x_scaled)[0][1])

        # Blended anomaly score
        anomaly_score = float(np.clip(
            self.blend_weight * rf_proba + (1 - self.blend_weight) * iso_score,
            0.0, 1.0,
        ))
        trust_score = 1.0 - anomaly_score

        # Feature contributions (from RF feature importances)
        importances = self.rf_classifier.feature_importances_
        contributions = {
            FEATURE_NAMES[i]: round(float(importances[i] * anomaly_score), 4)
            for i in range(len(FEATURE_NAMES))
        }

        latency_ms = (time.perf_counter() - start) * 1000

        return TrustAssessment(
            event_id=event.event_id,
            device_id=event.device_id,
            tenant=event.tenant,
            anomaly_score=round(anomaly_score, 4),
            trust_score=round(trust_score, 4),
            feature_contributions=contributions,
        )


# ---------------------------------------------------------------------------
# Policy Decision Point (PDP)
# ---------------------------------------------------------------------------

class PolicyDecisionPoint:
    """
    Converts ML trust scores into discrete, enforceable policy actions.

    Thresholds are tunable per-deployment:
      trust ≥ 0.80 → Allow
      0.60 ≤ trust < 0.80 → Monitor
      0.35 ≤ trust < 0.60 → Restrict
      trust < 0.35 → Isolate
    """

    def __init__(
        self,
        allow_threshold: float = 0.80,
        monitor_threshold: float = 0.60,
        restrict_threshold: float = 0.35,
    ):
        self.allow_threshold = allow_threshold
        self.monitor_threshold = monitor_threshold
        self.restrict_threshold = restrict_threshold
        self._device_actions: dict[str, PolicyAction] = {}

    def decide(self, assessment: TrustAssessment) -> PolicyDecision:
        """Map a trust assessment to a policy decision."""
        ts = assessment.trust_score
        if ts >= self.allow_threshold:
            action = PolicyAction.ALLOW
        elif ts >= self.monitor_threshold:
            action = PolicyAction.MONITOR
        elif ts >= self.restrict_threshold:
            action = PolicyAction.RESTRICT
        else:
            action = PolicyAction.ISOLATE

        previous = self._device_actions.get(assessment.device_id)
        self._device_actions[assessment.device_id] = action

        return PolicyDecision(
            device_id=assessment.device_id,
            tenant=assessment.tenant,
            event_id=assessment.event_id,
            action=action,
            previous_action=previous,
            trust_score=assessment.trust_score,
            anomaly_score=assessment.anomaly_score,
        )

    def get_current_action(self, device_id: str) -> PolicyAction:
        return self._device_actions.get(device_id, PolicyAction.ALLOW)


# ---------------------------------------------------------------------------
# Explainability Module
# ---------------------------------------------------------------------------

class ExplainabilityModule:
    """Generates human-readable explanations for policy decisions."""

    _ACTION_TEMPLATES = {
        PolicyAction.ALLOW: (
            "Device {device_id} ({tenant}) is operating within normal parameters. "
            "Trust score: {trust:.2f}. No action required."
        ),
        PolicyAction.MONITOR: (
            "⚠️ Device {device_id} ({tenant}) shows slightly elevated anomaly signals "
            "(anomaly: {anomaly:.2f}, trust: {trust:.2f}). Increased monitoring activated. "
            "Key factors: {factors}."
        ),
        PolicyAction.RESTRICT: (
            "🔶 Device {device_id} ({tenant}) exhibits suspicious behaviour "
            "(anomaly: {anomaly:.2f}, trust: {trust:.2f}). Traffic is being rate-limited. "
            "Top contributing factors: {factors}."
        ),
        PolicyAction.ISOLATE: (
            "🔴 CRITICAL — Device {device_id} ({tenant}) is highly anomalous "
            "(anomaly: {anomaly:.2f}, trust: {trust:.2f}). Device has been ISOLATED. "
            "All traffic from this device is dropped. Evidence: {factors}."
        ),
    }

    _SEVERITY_MAP = {
        PolicyAction.ALLOW: AlertSeverity.INFO,
        PolicyAction.MONITOR: AlertSeverity.WARNING,
        PolicyAction.RESTRICT: AlertSeverity.WARNING,
        PolicyAction.ISOLATE: AlertSeverity.CRITICAL,
    }

    def explain(
        self,
        decision: PolicyDecision,
        assessment: TrustAssessment,
    ) -> tuple[PolicyDecision, AuditLogEntry]:
        """Attach an explanation to a decision and produce an audit log entry."""
        # Top-3 contributing features
        sorted_feats = sorted(
            assessment.feature_contributions.items(),
            key=lambda kv: abs(kv[1]),
            reverse=True,
        )
        top_factors = ", ".join(f"{k}={v:.4f}" for k, v in sorted_feats[:3])

        explanation = self._ACTION_TEMPLATES[decision.action].format(
            device_id=decision.device_id,
            tenant=decision.tenant.value,
            trust=decision.trust_score,
            anomaly=decision.anomaly_score,
            factors=top_factors,
        )

        evidence = {
            "trust_score": decision.trust_score,
            "anomaly_score": decision.anomaly_score,
            "feature_contributions": assessment.feature_contributions,
            "action": decision.action.value,
        }

        decision.explanation = explanation
        decision.evidence = evidence

        severity = self._SEVERITY_MAP[decision.action]
        audit = AuditLogEntry(
            event_type="policy_decision",
            severity=severity,
            tenant=decision.tenant,
            device_id=decision.device_id,
            action=decision.action,
            explanation=explanation,
            evidence=evidence,
            who="PDP-AutoPolicy",
            what=f"Action changed to {decision.action.value}",
            why=f"Anomaly score {decision.anomaly_score:.4f} triggered threshold",
        )

        return decision, audit
