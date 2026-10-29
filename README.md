# 🏙️ Smart City Zero-Trust IDS

**Explainable Adaptive Zero-Trust Intrusion Detection System for Multi-Tenant Smart-City Edge Simulation**

---

## Overview

This project implements a complete **Zero-Trust security architecture** for smart city IoT networks, featuring:

- 🔍 **ML-based Anomaly Detection** — Hybrid Isolation Forest + Random Forest IDS
- 🛡️ **Adaptive Policy Engine** — Dynamic trust scoring with explainable decisions
- 🏘️ **Multi-Tenant Isolation** — Three tenants (Traffic, Waste, Water) with cross-tenant containment validation
- 📊 **Real-Time Dashboard** — Streamlit-powered monitoring with live alerts and metrics
- 📈 **Evaluation Pipeline** — Automated benchmarking (Precision, Recall, F1, FPR)

## Project Structure

```
SmartCityZeroTrust/
├── src/
│   ├── __init__.py          # Package root
│   ├── __main__.py          # Entry point (python -m src)
│   ├── schemas.py           # Pydantic data models
│   ├── simulation.py        # IoT device simulation & scenarios
│   ├── ids_engine.py        # ML IDS + PDP + Explainability
│   ├── enforcement.py       # PEP + Containment Manager
│   ├── monitoring.py        # Audit logging + Performance metrics
│   ├── evaluation.py        # Benchmarking + Report generation
│   └── main.py              # Pipeline orchestrator
├── tests/
│   └── test_ids.py          # Comprehensive test suite
├── dashboard.py             # Streamlit monitoring dashboard
├── requirements.txt         # Python dependencies
├── PLAN.md                  # Development plan
└── ARCHITECTURE.md          # System architecture
```

## Quick Start

```bash
# 1. Create virtual environment
python -m venv venv
.\venv\Scripts\activate     # Windows
source venv/bin/activate    # Linux/Mac

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the full pipeline (demo mode)
python -m src --demo

# 4. Run the full pipeline (2000 events)
python -m src --events 2000

# 5. Launch the dashboard
streamlit run dashboard.py

# 6. Run tests
pytest tests/ -v
```

## Architecture

The system follows a **Zero-Trust security model** with these layers:

1. **IoT Device Simulation** — 6 devices across 3 tenants generating synthetic telemetry
2. **Policy Enforcement Point (PEP)** — Gateway that enforces Allow/Monitor/Restrict/Isolate
3. **ML IDS Engine** — Hybrid anomaly detection with feature-based explainability
4. **Policy Decision Point (PDP)** — Trust score → policy action mapping
5. **Explainability Module** — Human-readable evidence for every decision
6. **Audit & Monitoring** — JSONL logging + real-time resource tracking

## Attack Scenario

The default scenario simulates a **compromised waste management bin** (`wst-002`) that:
- Starts normal, then begins data exfiltration at ~30% through the simulation
- Shows elevated packet rates (3-8× normal)
- Exhibits unusual payload sizes (4-10× normal)
- Contacts cross-tenant destinations
- Uses mixed protocols and drops encryption

The IDS detects this anomaly, the PDP escalates to ISOLATE, and the system validates that containing this device does **not** impact Traffic or Water tenants.

## License

MIT
