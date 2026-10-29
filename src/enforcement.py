"""
Tenant-Aware Micro-segmentation and Containment (Phase 4).

Provides:
- PolicyEnforcementPoint (PEP): enforces PDP decisions on the simulated network
- ContainmentManager: handles device isolation and cross-tenant validation
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional

from .schemas import (
    AuditLogEntry,
    AlertSeverity,
    DeviceProfile,
    DeviceStatus,
    PolicyAction,
    PolicyDecision,
    TelemetryEvent,
    TenantType,
)


# ---------------------------------------------------------------------------
# Policy Enforcement Point (PEP)
# ---------------------------------------------------------------------------

class PolicyEnforcementPoint:
    """
    Gateway/firewall that enforces PDP decisions on the simulated network.

    - ALLOW:    pass traffic unmodified
    - MONITOR:  pass traffic but flag for logging
    - RESTRICT: rate-limit (pass only 1 in N packets)
    - ISOLATE:  drop all traffic from the device
    """

    def __init__(self, restrict_ratio: int = 3):
        self._policies: dict[str, PolicyAction] = {}
        self._restrict_ratio = restrict_ratio
        self._restrict_counters: dict[str, int] = defaultdict(int)
        self._stats = {
            "passed": 0,
            "dropped": 0,
            "rate_limited": 0,
            "monitored": 0,
        }

    def update_policy(self, device_id: str, action: PolicyAction) -> None:
        """Apply a new policy for a device."""
        self._policies[device_id] = action
        if action != PolicyAction.RESTRICT:
            self._restrict_counters.pop(device_id, None)

    def enforce(self, event: TelemetryEvent) -> tuple[bool, str]:
        """
        Enforce the current policy for an incoming event.

        Returns (allowed: bool, reason: str).
        """
        action = self._policies.get(event.device_id, PolicyAction.ALLOW)

        if action == PolicyAction.ISOLATE:
            self._stats["dropped"] += 1
            return False, "DROPPED — device is isolated"

        if action == PolicyAction.RESTRICT:
            self._restrict_counters[event.device_id] += 1
            if self._restrict_counters[event.device_id] % self._restrict_ratio != 0:
                self._stats["rate_limited"] += 1
                return False, "RATE-LIMITED — restricted traffic"
            self._stats["passed"] += 1
            return True, "PASSED (restricted, within rate limit)"

        if action == PolicyAction.MONITOR:
            self._stats["monitored"] += 1
            self._stats["passed"] += 1
            return True, "PASSED (monitored)"

        self._stats["passed"] += 1
        return True, "PASSED"

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def get_device_policy(self, device_id: str) -> PolicyAction:
        return self._policies.get(device_id, PolicyAction.ALLOW)


# ---------------------------------------------------------------------------
# Containment Manager
# ---------------------------------------------------------------------------

class ContainmentManager:
    """
    Manages device isolation and validates cross-tenant segmentation.

    Ensures that isolating a device in one tenant does not affect devices
    in other tenants.
    """

    def __init__(self, devices: list[DeviceProfile], pep: PolicyEnforcementPoint):
        self.devices = {d.device_id: d for d in devices}
        self.pep = pep
        self._isolation_log: list[dict] = []

    def isolate_device(self, device_id: str) -> AuditLogEntry:
        """Isolate a device: update PEP and mark device status."""
        device = self.devices.get(device_id)
        if device is None:
            raise ValueError(f"Unknown device: {device_id}")

        device.status = DeviceStatus.ISOLATED
        self.pep.update_policy(device_id, PolicyAction.ISOLATE)

        entry = {
            "device_id": device_id,
            "tenant": device.tenant.value,
            "timestamp": time.time(),
            "action": "isolated",
        }
        self._isolation_log.append(entry)

        return AuditLogEntry(
            event_type="device_isolated",
            severity=AlertSeverity.CRITICAL,
            tenant=device.tenant,
            device_id=device_id,
            action=PolicyAction.ISOLATE,
            explanation=f"Device {device_id} has been fully isolated from the network.",
            who="ContainmentManager",
            what=f"Isolated device {device_id}",
            why="Policy engine determined device is a threat",
        )

    def release_device(self, device_id: str) -> AuditLogEntry:
        """Release a device back to ALLOW status."""
        device = self.devices.get(device_id)
        if device is None:
            raise ValueError(f"Unknown device: {device_id}")

        device.status = DeviceStatus.NORMAL
        self.pep.update_policy(device_id, PolicyAction.ALLOW)

        return AuditLogEntry(
            event_type="device_released",
            severity=AlertSeverity.INFO,
            tenant=device.tenant,
            device_id=device_id,
            action=PolicyAction.ALLOW,
            explanation=f"Device {device_id} released from isolation.",
            who="ContainmentManager",
            what=f"Released device {device_id}",
            why="Operator or policy cleared the device",
        )

    def validate_cross_tenant_isolation(
        self,
        isolated_device_id: str,
        test_events: list[TelemetryEvent],
    ) -> dict:
        """
        Validate that isolating one device does not impact other tenants.

        Returns a report with per-tenant pass/drop counts.
        """
        isolated_dev = self.devices.get(isolated_device_id)
        if not isolated_dev:
            raise ValueError(f"Unknown device: {isolated_device_id}")

        results: dict[str, dict[str, int]] = {}
        for tenant in TenantType:
            results[tenant.value] = {"passed": 0, "dropped": 0, "total": 0}

        for event in test_events:
            allowed, _ = self.pep.enforce(event)
            bucket = results[event.tenant.value]
            bucket["total"] += 1
            if allowed:
                bucket["passed"] += 1
            else:
                bucket["dropped"] += 1

        # Determine correctness
        iso_tenant = isolated_dev.tenant.value
        report = {
            "isolated_device": isolated_device_id,
            "isolated_tenant": iso_tenant,
            "per_tenant": results,
            "cross_tenant_impact": False,
        }

        # Check: non-isolated tenants should have 0 drops
        for tenant_name, counts in results.items():
            if tenant_name != iso_tenant and counts["dropped"] > 0:
                report["cross_tenant_impact"] = True
                break

        return report

    @property
    def isolation_log(self) -> list[dict]:
        return list(self._isolation_log)
