# Smart City Zero-Trust IDS — Evaluation Report

**Generated**: 2026-10-14 06:42:49

---

## 1. Detection Performance

| Scenario | Precision | Recall | F1 Score | FPR | Latency (ms) |
| --- | --- | --- | --- | --- | --- |
| compromised_waste_bin | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 31.65 |

## 2. Cross-Tenant Isolation Validation

- **Isolated Device**: `wst-002`
- **Isolated Tenant**: `waste`
- **Cross-Tenant Impact**: `False`

| Tenant | Total | Passed | Dropped |
| --- | --- | --- | --- |
| traffic | 334 | 334 | 0 |
| waste | 334 | 167 | 167 |
| water | 332 | 332 | 0 |

## 3. Resource Cost Analysis

- **Avg CPU**: 0.0%
- **Avg RAM**: 185.7 MB
- **Avg Inference Latency**: 19.913 ms

## 4. Conclusions

- Best F1 score: **1.0000** (scenario: compromised_waste_bin)
- The system successfully detects anomalous behaviour in the simulated smart-city environment.
- ✅ Cross-tenant isolation validated: containing a waste device does NOT impact traffic or water tenants.

---
*Report generated automatically by SmartCityZeroTrust evaluation pipeline.*