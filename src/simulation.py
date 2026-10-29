"""
Smart City Multi-Tenant IoT Device Simulation (Phase 2).

Provides:
- DeviceSimulator: generates normal telemetry for each tenant's devices
- ScenarioRunner: injects attack scenarios (e.g., compromised waste bin)
- TrafficPipeline: central async queue aggregating all device events
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Optional

from .schemas import (
    DeviceProfile,
    DeviceStatus,
    PolicyAction,
    TelemetryEvent,
    TenantType,
)


# ---------------------------------------------------------------------------
# Default Device Fleet
# ---------------------------------------------------------------------------

DEFAULT_DEVICES: list[DeviceProfile] = [
    # Traffic tenant
    DeviceProfile(
        device_id="traf-001", name="Traffic Sensor Alpha",
        tenant=TenantType.TRAFFIC, device_type="traffic_sensor",
        normal_packet_rate=12.0, normal_payload_size=150.0, normal_dest_count=2,
    ),
    DeviceProfile(
        device_id="traf-002", name="Traffic Camera Beta",
        tenant=TenantType.TRAFFIC, device_type="traffic_camera",
        normal_packet_rate=20.0, normal_payload_size=512.0, normal_dest_count=3,
    ),
    # Waste tenant
    DeviceProfile(
        device_id="wst-001", name="Smart Bin 1",
        tenant=TenantType.WASTE, device_type="smart_bin",
        normal_packet_rate=5.0, normal_payload_size=64.0, normal_dest_count=1,
    ),
    DeviceProfile(
        device_id="wst-002", name="Smart Bin 2 (Target)",
        tenant=TenantType.WASTE, device_type="smart_bin",
        normal_packet_rate=5.0, normal_payload_size=64.0, normal_dest_count=1,
    ),
    # Water tenant
    DeviceProfile(
        device_id="wtr-001", name="Pressure Sensor 1",
        tenant=TenantType.WATER, device_type="pressure_sensor",
        normal_packet_rate=8.0, normal_payload_size=96.0, normal_dest_count=2,
    ),
    DeviceProfile(
        device_id="wtr-002", name="Quality Monitor 2",
        tenant=TenantType.WATER, device_type="quality_monitor",
        normal_packet_rate=10.0, normal_payload_size=128.0, normal_dest_count=2,
    ),
]

# Subnet mapping for realistic IPs
_TENANT_SUBNETS = {
    TenantType.TRAFFIC: "10.1.1",
    TenantType.WASTE: "10.2.1",
    TenantType.WATER: "10.3.1",
}


def _random_ip(tenant: TenantType, last_octet: Optional[int] = None) -> str:
    subnet = _TENANT_SUBNETS[tenant]
    octet = last_octet if last_octet is not None else random.randint(1, 254)
    return f"{subnet}.{octet}"


# ---------------------------------------------------------------------------
# Device Simulator
# ---------------------------------------------------------------------------

class DeviceSimulator:
    """Generates telemetry events for a single device."""

    def __init__(self, profile: DeviceProfile):
        self.profile = profile
        self._source_ip = _random_ip(profile.tenant, int(profile.device_id.split("-")[1]))

    def generate_normal_event(self) -> TelemetryEvent:
        """Produce a normal-behaviour telemetry event."""
        p = self.profile
        return TelemetryEvent(
            device_id=p.device_id,
            tenant=p.tenant,
            source_ip=self._source_ip,
            dest_ip=_random_ip(p.tenant),
            packet_rate=p.normal_packet_rate * random.uniform(0.8, 1.2),
            payload_size=p.normal_payload_size * random.uniform(0.85, 1.15),
            dest_count=p.normal_dest_count + random.choice([0, 0, 0, 1]),
            protocol="MQTT",
            is_encrypted=True,
            is_attack=False,
        )

    def generate_attack_event(self, attack_type: str = "data_exfiltration") -> TelemetryEvent:
        """Produce an anomalous telemetry event simulating an attack."""
        p = self.profile
        return TelemetryEvent(
            device_id=p.device_id,
            tenant=p.tenant,
            source_ip=self._source_ip,
            dest_ip=_random_ip(TenantType.TRAFFIC),  # cross-tenant probing
            packet_rate=p.normal_packet_rate * random.uniform(3.0, 8.0),
            payload_size=p.normal_payload_size * random.uniform(4.0, 10.0),
            dest_count=p.normal_dest_count + random.randint(5, 15),
            protocol=random.choice(["MQTT", "HTTP", "RAW_TCP"]),
            is_encrypted=random.choice([True, False]),
            is_attack=True,
            attack_type=attack_type,
        )


# ---------------------------------------------------------------------------
# Scenario Runner
# ---------------------------------------------------------------------------

class ScenarioRunner:
    """Orchestrates attack injection into the telemetry stream."""

    def __init__(
        self,
        devices: list[DeviceProfile] | None = None,
        attack_device_id: str = "wst-002",
        attack_start_pct: float = 0.3,
        attack_type: str = "data_exfiltration",
    ):
        self.devices = devices or list(DEFAULT_DEVICES)
        self.simulators = {d.device_id: DeviceSimulator(d) for d in self.devices}
        self.attack_device_id = attack_device_id
        self.attack_start_pct = attack_start_pct
        self.attack_type = attack_type

    def generate_dataset(self, total_events: int = 1000) -> list[TelemetryEvent]:
        """Generate a mixed normal + attack dataset for training / evaluation."""
        events: list[TelemetryEvent] = []
        attack_start = int(total_events * self.attack_start_pct)

        for i in range(total_events):
            # Cycle through devices
            device_id = list(self.simulators.keys())[i % len(self.simulators)]
            sim = self.simulators[device_id]

            if device_id == self.attack_device_id and i >= attack_start:
                # 70 % chance of attack event after attack_start for this device
                if random.random() < 0.7:
                    events.append(sim.generate_attack_event(self.attack_type))
                else:
                    events.append(sim.generate_normal_event())
            else:
                events.append(sim.generate_normal_event())

        return events


# ---------------------------------------------------------------------------
# Traffic Pipeline (async queue)
# ---------------------------------------------------------------------------

class TrafficPipeline:
    """Central aggregation queue funnelling all device traffic to the IDS."""

    def __init__(self, maxsize: int = 5000):
        self.queue: asyncio.Queue[TelemetryEvent] = asyncio.Queue(maxsize=maxsize)
        self._running = False

    async def ingest(self, event: TelemetryEvent) -> None:
        """Push a telemetry event into the pipeline."""
        await self.queue.put(event)

    async def consume(self) -> TelemetryEvent:
        """Consume the next event from the pipeline."""
        return await self.queue.get()

    async def run_simulation(
        self,
        scenario: ScenarioRunner,
        events_per_second: float = 50.0,
        total_events: int = 1000,
    ) -> None:
        """Stream simulated events into the queue at a controlled rate."""
        self._running = True
        dataset = scenario.generate_dataset(total_events)
        delay = 1.0 / events_per_second

        for event in dataset:
            if not self._running:
                break
            event.timestamp = time.time()
            await self.ingest(event)
            await asyncio.sleep(delay)

    def stop(self) -> None:
        self._running = False

    @property
    def pending(self) -> int:
        return self.queue.qsize()
