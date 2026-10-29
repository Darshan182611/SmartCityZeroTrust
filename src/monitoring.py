"""
Audit Logging and Performance Monitoring (Phase 5 — backend).

Provides:
- AuditLogger: structured JSON audit log writer
- PerformanceMonitor: CPU, RAM, latency tracking
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

import psutil

from .schemas import AuditLogEntry, SystemMetrics


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Writes structured audit log entries to a JSONL file."""

    def __init__(self, log_path: str = "audit_log.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: list[AuditLogEntry] = []

    def log(self, entry: AuditLogEntry) -> None:
        """Append an audit entry to the in-memory buffer and disk."""
        self._entries.append(entry)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(entry.model_dump_json() + "\n")

    def get_recent(self, n: int = 50) -> list[AuditLogEntry]:
        """Return the most recent N audit entries."""
        return self._entries[-n:]

    def get_by_device(self, device_id: str) -> list[AuditLogEntry]:
        """Return all entries for a specific device."""
        return [e for e in self._entries if e.device_id == device_id]

    def get_critical(self) -> list[AuditLogEntry]:
        """Return all CRITICAL severity entries."""
        return [e for e in self._entries if e.severity.value == "critical"]

    @property
    def total_entries(self) -> int:
        return len(self._entries)

    def load_from_disk(self) -> None:
        """Load previously written entries from the log file."""
        if not self.log_path.exists():
            return
        self._entries.clear()
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self._entries.append(AuditLogEntry.model_validate_json(line))


# ---------------------------------------------------------------------------
# Performance Monitor
# ---------------------------------------------------------------------------

class PerformanceMonitor:
    """Tracks system resource usage and inference latency."""

    def __init__(self):
        self._process = psutil.Process(os.getpid())
        self._history: list[SystemMetrics] = []
        self._inference_times: list[float] = []

    def record_inference(self, latency_ms: float) -> None:
        """Record a single inference latency measurement."""
        self._inference_times.append(latency_ms)

    def snapshot(self, active_devices: int = 0, events_per_second: float = 0.0) -> SystemMetrics:
        """Take a snapshot of current system resource usage."""
        mem_info = self._process.memory_info()
        avg_latency = (
            sum(self._inference_times[-100:]) / len(self._inference_times[-100:])
            if self._inference_times else 0.0
        )

        metrics = SystemMetrics(
            cpu_percent=self._process.cpu_percent(interval=0.1),
            ram_mb=mem_info.rss / (1024 * 1024),
            inference_latency_ms=round(avg_latency, 3),
            events_per_second=events_per_second,
            active_devices=active_devices,
        )
        self._history.append(metrics)
        return metrics

    def get_history(self, n: int = 100) -> list[SystemMetrics]:
        """Return the most recent N metric snapshots."""
        return self._history[-n:]

    def get_averages(self) -> dict[str, float]:
        """Return average resource usage across all snapshots."""
        if not self._history:
            return {"cpu_percent": 0, "ram_mb": 0, "inference_latency_ms": 0}
        return {
            "cpu_percent": sum(m.cpu_percent for m in self._history) / len(self._history),
            "ram_mb": sum(m.ram_mb for m in self._history) / len(self._history),
            "inference_latency_ms": sum(m.inference_latency_ms for m in self._history) / len(self._history),
        }
