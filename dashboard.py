"""
Smart City Zero-Trust IDS — Real-Time Monitoring Dashboard (Phase 5).

Launch with:
    streamlit run dashboard.py
"""

from __future__ import annotations

import json
import time
import random
from pathlib import Path

import streamlit as st
import pandas as pd
import numpy as np

# Must be first Streamlit command
st.set_page_config(
    page_title="Smart City Zero-Trust IDS",
    page_icon="🏙️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Imports from our project
# ---------------------------------------------------------------------------
import sys
sys.path.insert(0, str(Path(__file__).parent))

from src.schemas import (
    PolicyAction,
    TenantType,
    AlertSeverity,
    DeviceStatus,
    DashboardDeviceState,
)
from src.simulation import ScenarioRunner, DEFAULT_DEVICES
from src.ids_engine import IDSEngine, PolicyDecisionPoint, ExplainabilityModule
from src.enforcement import PolicyEnforcementPoint, ContainmentManager
from src.monitoring import AuditLogger, PerformanceMonitor
from src.evaluation import Evaluator


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Global styles */
    .stApp {
        font-family: 'Inter', sans-serif;
    }
    
    /* Header */
    .main-header {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
        padding: 1.5rem 2rem;
        border-radius: 16px;
        margin-bottom: 1.5rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    }
    .main-header h1 {
        color: #ffffff;
        font-size: 1.8rem;
        font-weight: 700;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .main-header p {
        color: #a0aec0;
        font-size: 0.9rem;
        margin: 0.3rem 0 0 0;
    }
    
    /* Metric cards */
    .metric-card {
        background: linear-gradient(145deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid rgba(99, 102, 241, 0.2);
        border-radius: 12px;
        padding: 1.2rem;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
        transition: transform 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        margin: 0.3rem 0;
    }
    .metric-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #a0aec0;
    }
    
    /* Status badges */
    .badge-allow { 
        background: linear-gradient(135deg, #10b981, #059669); 
        color: white; padding: 4px 12px; border-radius: 20px; 
        font-size: 0.75rem; font-weight: 600; display: inline-block; 
    }
    .badge-monitor { 
        background: linear-gradient(135deg, #f59e0b, #d97706); 
        color: white; padding: 4px 12px; border-radius: 20px; 
        font-size: 0.75rem; font-weight: 600; display: inline-block; 
    }
    .badge-restrict { 
        background: linear-gradient(135deg, #f97316, #ea580c); 
        color: white; padding: 4px 12px; border-radius: 20px; 
        font-size: 0.75rem; font-weight: 600; display: inline-block; 
    }
    .badge-isolate { 
        background: linear-gradient(135deg, #ef4444, #dc2626); 
        color: white; padding: 4px 12px; border-radius: 20px; 
        font-size: 0.75rem; font-weight: 600; display: inline-block; 
    }
    
    /* Tenant colors */
    .tenant-traffic { border-left: 4px solid #3b82f6; }
    .tenant-waste { border-left: 4px solid #f59e0b; }
    .tenant-water { border-left: 4px solid #06b6d4; }
    
    /* Alert panel */
    .alert-critical {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(220, 38, 38, 0.05));
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .alert-warning {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.1), rgba(217, 119, 6, 0.05));
        border: 1px solid rgba(245, 158, 11, 0.3);
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .alert-info {
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(37, 99, 235, 0.05));
        border: 1px solid rgba(59, 130, 246, 0.3);
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }

    /* Section headers */
    .section-header {
        font-size: 1.1rem;
        font-weight: 600;
        color: #e2e8f0;
        margin: 1.5rem 0 0.8rem 0;
        padding-bottom: 0.4rem;
        border-bottom: 2px solid rgba(99, 102, 241, 0.3);
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
def init_session():
    """Initialize all session state on first run."""
    if "initialized" not in st.session_state:
        st.session_state.initialized = False
        st.session_state.ids = None
        st.session_state.pdp = None
        st.session_state.explainer = None
        st.session_state.pep = None
        st.session_state.containment = None
        st.session_state.audit_logger = None
        st.session_state.perf_monitor = None
        st.session_state.device_states = {}
        st.session_state.trust_history = {d.device_id: [] for d in DEFAULT_DEVICES}
        st.session_state.alert_feed = []
        st.session_state.events_processed = 0
        st.session_state.train_metrics = {}
        st.session_state.eval_result = None
        st.session_state.cross_tenant_report = None

init_session()


def initialize_system():
    """Train the IDS and set up all components."""
    # Generate training data
    scenario = ScenarioRunner(
        devices=list(DEFAULT_DEVICES),
        attack_device_id="wst-002",
        attack_start_pct=0.3,
    )
    train_events = scenario.generate_dataset(1500)
    test_events = scenario.generate_dataset(500)

    # Train IDS
    ids = IDSEngine(contamination=0.15, blend_weight=0.6)
    train_result = ids.train(train_events)

    # Setup components
    pdp = PolicyDecisionPoint()
    explainer = ExplainabilityModule()
    pep = PolicyEnforcementPoint()
    containment = ContainmentManager(devices=list(DEFAULT_DEVICES), pep=pep)
    audit_logger = AuditLogger(log_path="data/audit_log.jsonl")
    perf_monitor = PerformanceMonitor()

    # Process test events for dashboard state
    device_states = {}
    trust_history = {d.device_id: [] for d in DEFAULT_DEVICES}
    alert_feed = []
    decisions_count = {a.value: 0 for a in PolicyAction}

    for event in test_events:
        start_t = time.perf_counter()
        assessment = ids.predict(event)
        decision = pdp.decide(assessment)
        decision, audit_entry = explainer.explain(decision, assessment)
        latency = (time.perf_counter() - start_t) * 1000

        pep.update_policy(event.device_id, decision.action)
        audit_logger.log(audit_entry)
        perf_monitor.record_inference(latency)
        decisions_count[decision.action.value] += 1

        # Update device state
        dev_profile = next((d for d in DEFAULT_DEVICES if d.device_id == event.device_id), None)
        device_states[event.device_id] = DashboardDeviceState(
            device_id=event.device_id,
            name=dev_profile.name if dev_profile else event.device_id,
            tenant=event.tenant,
            status=DeviceStatus.ISOLATED if decision.action == PolicyAction.ISOLATE else DeviceStatus.NORMAL,
            trust_score=assessment.trust_score,
            current_action=decision.action,
            last_event_time=event.timestamp,
            anomaly_score=assessment.anomaly_score,
        )

        trust_history[event.device_id].append({
            "trust": assessment.trust_score,
            "anomaly": assessment.anomaly_score,
            "action": decision.action.value,
        })

        if decision.action in (PolicyAction.RESTRICT, PolicyAction.ISOLATE):
            alert_feed.append({
                "time": time.strftime("%H:%M:%S"),
                "severity": "CRITICAL" if decision.action == PolicyAction.ISOLATE else "WARNING",
                "device": event.device_id,
                "tenant": event.tenant.value,
                "action": decision.action.value,
                "explanation": decision.explanation[:120],
                "trust": assessment.trust_score,
                "anomaly": assessment.anomaly_score,
            })

    # Cross-tenant validation
    containment.isolate_device("wst-002")
    cross_report = containment.validate_cross_tenant_isolation("wst-002", test_events)

    # Evaluate
    pdp_eval = PolicyDecisionPoint()
    evaluator = Evaluator(ids, pdp_eval, explainer)
    eval_result = evaluator.evaluate(test_events, "compromised_waste_bin")

    # Store in session
    st.session_state.ids = ids
    st.session_state.pdp = pdp
    st.session_state.explainer = explainer
    st.session_state.pep = pep
    st.session_state.containment = containment
    st.session_state.audit_logger = audit_logger
    st.session_state.perf_monitor = perf_monitor
    st.session_state.device_states = device_states
    st.session_state.trust_history = trust_history
    st.session_state.alert_feed = alert_feed
    st.session_state.events_processed = len(test_events)
    st.session_state.train_metrics = train_result
    st.session_state.eval_result = eval_result
    st.session_state.cross_tenant_report = cross_report
    st.session_state.decisions_count = decisions_count
    st.session_state.initialized = True


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Control Panel")
    
    if not st.session_state.initialized:
        if st.button("🚀 Initialize & Run Simulation", type="primary", use_container_width=True):
            with st.spinner("Training IDS models & processing events..."):
                initialize_system()
            st.rerun()
        st.info("Click above to initialize the IDS and run the simulation.")
    else:
        st.success(f"✅ System Online — {st.session_state.events_processed} events processed")
        
        if st.button("🔄 Re-run Simulation", use_container_width=True):
            st.session_state.initialized = False
            st.rerun()
    
    st.markdown("---")
    st.markdown("### 📊 Quick Stats")
    if st.session_state.initialized:
        tm = st.session_state.train_metrics
        st.metric("Training Accuracy", f"{tm.get('train_accuracy', 0):.2%}")
        st.metric("Training Samples", tm.get("samples", 0))
        st.metric("Active Devices", len(DEFAULT_DEVICES))
        st.metric("Audit Entries", st.session_state.audit_logger.total_entries if st.session_state.audit_logger else 0)


# ---------------------------------------------------------------------------
# Main Dashboard Content
# ---------------------------------------------------------------------------

# Header
st.markdown("""
<div class="main-header">
    <h1>🏙️ Smart City Zero-Trust IDS</h1>
    <p>Explainable Adaptive Intrusion Detection System for Multi-Tenant Edge Networks</p>
</div>
""", unsafe_allow_html=True)

if not st.session_state.initialized:
    st.markdown("### 👈 Click **Initialize & Run Simulation** in the sidebar to start")
    st.stop()


# ── Top KPI Row ──────────────────────────────────────────────────────────────
eval_r = st.session_state.eval_result
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)

with kpi1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Precision</div>
        <div class="metric-value" style="color: #10b981;">{eval_r.precision:.2%}</div>
    </div>
    """, unsafe_allow_html=True)

with kpi2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Recall</div>
        <div class="metric-value" style="color: #3b82f6;">{eval_r.recall:.2%}</div>
    </div>
    """, unsafe_allow_html=True)

with kpi3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">F1 Score</div>
        <div class="metric-value" style="color: #8b5cf6;">{eval_r.f1_score:.2%}</div>
    </div>
    """, unsafe_allow_html=True)

with kpi4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">False Positive Rate</div>
        <div class="metric-value" style="color: #f59e0b;">{eval_r.false_positive_rate:.2%}</div>
    </div>
    """, unsafe_allow_html=True)

with kpi5:
    avg_lat = st.session_state.perf_monitor.get_averages().get("inference_latency_ms", 0)
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Avg Latency</div>
        <div class="metric-value" style="color: #06b6d4;">{avg_lat:.2f}ms</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("")

# ── Device Status Grid ───────────────────────────────────────────────────────
st.markdown('<div class="section-header">🖥️ Device Fleet Status</div>', unsafe_allow_html=True)

tenant_cols = st.columns(3)
tenant_order = [TenantType.TRAFFIC, TenantType.WASTE, TenantType.WATER]
tenant_icons = {"traffic": "🚦", "waste": "🗑️", "water": "💧"}
tenant_colors = {"traffic": "#3b82f6", "waste": "#f59e0b", "water": "#06b6d4"}

for i, tenant in enumerate(tenant_order):
    with tenant_cols[i]:
        st.markdown(f"#### {tenant_icons[tenant.value]} {tenant.value.title()} Tenant")
        devices = [ds for ds in st.session_state.device_states.values() if ds.tenant == tenant]
        for ds in devices:
            badge_class = f"badge-{ds.current_action.value}"
            trust_pct = ds.trust_score * 100
            trust_color = "#10b981" if trust_pct > 70 else "#f59e0b" if trust_pct > 40 else "#ef4444"
            st.markdown(f"""
            <div style="background: rgba(30,30,50,0.5); border-radius:10px; padding:0.8rem; 
                        margin-bottom:0.5rem; border-left: 3px solid {tenant_colors[tenant.value]}">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-weight:600; font-size:0.85rem;">{ds.name}</span>
                    <span class="{badge_class}">{ds.current_action.value.upper()}</span>
                </div>
                <div style="margin-top:0.4rem; font-size:0.75rem; color:#a0aec0;">
                    Trust: <span style="color:{trust_color}; font-weight:600;">{trust_pct:.1f}%</span>
                    &nbsp;|&nbsp; Anomaly: {ds.anomaly_score:.3f}
                    &nbsp;|&nbsp; ID: <code>{ds.device_id}</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

st.markdown("")

# ── Charts Row ───────────────────────────────────────────────────────────────
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown('<div class="section-header">📈 Trust Score Trends</div>', unsafe_allow_html=True)
    chart_data = {}
    for dev_id, history in st.session_state.trust_history.items():
        if history:
            chart_data[dev_id] = [h["trust"] for h in history[-50:]]

    if chart_data:
        max_len = max(len(v) for v in chart_data.values())
        padded = {k: v + [None] * (max_len - len(v)) for k, v in chart_data.items()}
        df = pd.DataFrame(padded)
        st.line_chart(df, height=300)

with chart_col2:
    st.markdown('<div class="section-header">📊 Policy Action Distribution</div>', unsafe_allow_html=True)
    dc = st.session_state.decisions_count
    action_df = pd.DataFrame({
        "Action": [a.upper() for a in dc.keys()],
        "Count": list(dc.values()),
    })
    st.bar_chart(action_df.set_index("Action"), height=300)

st.markdown("")

# ── Cross-Tenant Isolation ───────────────────────────────────────────────────
st.markdown('<div class="section-header">🛡️ Cross-Tenant Isolation Validation</div>', unsafe_allow_html=True)

cr = st.session_state.cross_tenant_report
if cr:
    iso_col1, iso_col2 = st.columns([1, 2])
    with iso_col1:
        impact = cr.get("cross_tenant_impact", False)
        if not impact:
            st.success("✅ No cross-tenant impact detected!")
        else:
            st.error("⚠️ Cross-tenant impact detected!")
        st.markdown(f"**Isolated Device:** `{cr['isolated_device']}`")
        st.markdown(f"**Isolated Tenant:** `{cr['isolated_tenant']}`")

    with iso_col2:
        per_tenant = cr.get("per_tenant", {})
        ct_df = pd.DataFrame([
            {"Tenant": t, "Total": c["total"], "Passed": c["passed"], "Dropped": c["dropped"]}
            for t, c in per_tenant.items()
        ])
        st.dataframe(ct_df, use_container_width=True, hide_index=True)

st.markdown("")

# ── Alert Feed ───────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">🚨 Recent Alerts</div>', unsafe_allow_html=True)

alerts = st.session_state.alert_feed[-20:]  # Show last 20
if alerts:
    for alert in reversed(alerts):
        sev = alert["severity"]
        css_class = "alert-critical" if sev == "CRITICAL" else "alert-warning"
        icon = "🔴" if sev == "CRITICAL" else "🟡"
        st.markdown(f"""
        <div class="{css_class}">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:600;">{icon} {sev} — {alert['device']} ({alert['tenant']})</span>
                <span style="font-size:0.75rem; color:#a0aec0;">{alert['time']}</span>
            </div>
            <div style="font-size:0.8rem; margin-top:0.3rem; color:#cbd5e1;">
                Action: <strong>{alert['action'].upper()}</strong> | 
                Trust: {alert['trust']:.3f} | 
                Anomaly: {alert['anomaly']:.3f}
            </div>
            <div style="font-size:0.75rem; margin-top:0.2rem; color:#94a3b8;">
                {alert['explanation']}
            </div>
        </div>
        """, unsafe_allow_html=True)
else:
    st.info("No alerts to display. All devices operating normally.")

st.markdown("")

# ── Resource Metrics ─────────────────────────────────────────────────────────
st.markdown('<div class="section-header">⚡ Edge Resource Usage</div>', unsafe_allow_html=True)
res = st.session_state.perf_monitor.get_averages()
res_col1, res_col2, res_col3 = st.columns(3)
with res_col1:
    st.metric("Avg CPU", f"{res['cpu_percent']:.1f}%")
with res_col2:
    st.metric("Avg RAM", f"{res['ram_mb']:.1f} MB")
with res_col3:
    st.metric("Avg Inference Latency", f"{res['inference_latency_ms']:.3f} ms")

# ── Audit Log Table ──────────────────────────────────────────────────────────
st.markdown('<div class="section-header">📋 Audit Log (Latest 50)</div>', unsafe_allow_html=True)

if st.session_state.audit_logger:
    recent = st.session_state.audit_logger.get_recent(50)
    if recent:
        log_records = []
        for entry in recent:
            log_records.append({
                "Severity": entry.severity.value.upper(),
                "Device": entry.device_id,
                "Tenant": entry.tenant.value,
                "Action": entry.action.value.upper(),
                "Event": entry.event_type,
                "Explanation": entry.explanation[:80] + "..." if len(entry.explanation) > 80 else entry.explanation,
            })
        st.dataframe(pd.DataFrame(log_records), use_container_width=True, hide_index=True)

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align:center; color:#64748b; font-size:0.75rem;'>"
    "Smart City Zero-Trust IDS v1.0 — Explainable Adaptive Security for Multi-Tenant Edge Networks"
    "</div>",
    unsafe_allow_html=True,
)
