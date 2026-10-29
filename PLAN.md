# Smart City Zero-Trust IDS Project Plan

This document outlines the step-by-step implementation plan for the **Explainable Adaptive Zero-Trust IDS for Multi-Tenant Smart-City Edge Simulation**.

## Phase 1: Foundation and Environment Setup
- [x] **Initialize Project**: Set up the Python project structure, virtual environment, and dependency management (`requirements.txt`).
- [x] **Select Tech Stack**: 
  - **Simulation & Backend**: Python (FastAPI / AsyncIO).
  - **ML Model**: Scikit-Learn (Isolation Forest + Random Forest hybrid).
  - **Dashboard**: Streamlit real-time monitoring web interface.
- [x] **Define Data Schema**: Design structured event schemas for device traffic, audit logs, and incident explanations.

## Phase 2: Smart City Multi-Tenant Simulation
- [x] **Implement Tenant Framework**: Create logical isolation for three distinct tenants: **Traffic**, **Waste**, and **Water**.
- [x] **Device Simulation**: Build simulated IoT devices for each tenant generating normal telemetry data.
- [x] **Scenario Runner**: Implement a scenario generation script that injects abnormal behavior (e.g., the specific "compromised Waste device" attack scenario).
- [x] **Traffic Pipeline**: Funnel simulated traffic into a central aggregation queue for the IDS.

## Phase 3: Explainable Adaptive Zero-Trust IDS Engine
- [x] **ML Baseline IDS**: Train and deploy a lightweight ML model (Isolation Forest + Random Forest) to evaluate device traffic and assign trust scores.
- [x] **Policy Decision Point (PDP)**: Implement the dynamic trust logic that converts ML scores and behavior into discrete policy actions: `Allow`, `Monitor`, `Restrict`, or `Isolate`.
- [x] **Explainability Module**: Build a template-based explainer that ties policy decisions to actual identity, behavior, IDS signals, and policy evidence.

## Phase 4: Tenant-Aware Micro-segmentation and Containment
- [x] **Policy Enforcement Point (PEP)**: Enforce the PDP's decisions on the simulated network layer.
- [x] **Containment Logic**: Ensure that an `Isolate` action drops traffic from the compromised device.
- [x] **Cross-Tenant Validation**: Write tests to prove that containing a Waste device does not impact the availability or performance of Traffic and Water tenants.

## Phase 5: Monitoring Dashboard and Auditing
- [x] **Real-Time Dashboard**: Create a visualization interface showing active devices, real-time trust scores, and automated policy actions (`dashboard.py`).
- [x] **Audit Logging**: Write structured incident records and state changes to a secure log file (`data/audit_log.jsonl`).
- [x] **Performance Metrics**: Add monitoring for CPU, RAM, and inference latency on the simulated edge.

## Phase 6: Evaluation, Benchmarking, and Reporting
- [x] **Run Core Experiments**: Execute the scenarios and measure Precision, Recall, F1-Score, and False Positives.
- [x] **Resource Cost Analysis**: Evaluate the trade-off between detection quality and resource usage (CPU/RAM/Latency).
- [x] **Final Report generation**: Document assumptions, limitations, reproducible steps, and conclusions (`reports/evaluation_report.md`).

---

### Definition of Done (MVP)
- [x] A working Python simulation of all 3 tenants.
- [x] A repeatable compromised-waste-device scenario.
- [x] Policy engine correctly applies `Isolate` to the threat.
- [x] Clean dashboard showing alerts and evidence.
- [x] Captured metrics (Detection rates, Latency, CPU/RAM).
