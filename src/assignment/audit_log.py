"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None) -> str:
        """Store input + start timestamp keyed by request_id/user_id."""
        req_id = request_id or f"req_{user_id}_{len(self.logs)+len(self._open)+1}_{int(time.time()*1000)}"
        self._open[req_id] = {
            "user_id": user_id,
            "input_text": text,
            "start_time": time.time(),
            "start_iso": utc_now_iso(),
        }
        return req_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        req_id = request_id or f"req_{user_id}_{len(self.logs)+1}"
        open_rec = self._open.pop(req_id, {})
        start_time = open_rec.get("start_time", time.time())
        latency_ms = (time.time() - start_time) * 1000

        log_entry = {
            "request_id": req_id,
            "user_id": user_id,
            "input_text": open_rec.get("input_text", ""),
            "output_text": text,
            "blocked": blocked,
            "layer": layer,
            "start_time": open_rec.get("start_iso", utc_now_iso()),
            "end_time": utc_now_iso(),
            "latency_ms": round(latency_ms, 2),
        }
        self.logs.append(log_entry)

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        dirname = os.path.dirname(filepath)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
