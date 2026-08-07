"""
Assignment 11 — Defense-in-depth pipeline assembly (TODO).

Wire rate limiter + lab guardrails + judge + audit + monitoring.
You may use Google ADK plugins, LangGraph, NeMo, or pure Python.
"""
from __future__ import annotations

import re
import urllib.parse

from assignment.rate_limiter import RateLimitPlugin
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert


def is_egress_allowed(destination: str, payload: str) -> bool:
    """TODO 8A: Enforce a destination allowlist before any data leaves the agent.

    Return ``True`` only for an approved VinBank HTTPS endpoint and ordinary
    banking payload. Return ``False`` for unknown domains and payloads that
    contain a password, API key, database host, phone number or email address.
    Do not let the LLM's prose decide this policy.
    """
    if not destination or not payload:
        return False

    try:
        parsed = urllib.parse.urlparse(destination)
    except Exception:
        return False

    # 1. Check scheme and exact hostname
    if parsed.scheme != "https":
        return False
    if parsed.hostname != "api.vinbank.example":
        return False

    # 2. Check payload for sensitive data / secrets
    BLOCKED_PATTERNS = [
        r"admin123",
        r"sk-[a-zA-Z0-9-]+",
        r"db\.vinbank\.internal",
        r"0\d{9,10}",
        r"[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}",
        r"password\s*[:=]\s*\S+",
    ]

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return False

    return True


def build_production_plugins(
    *,
    max_requests: int = 10,
    window_seconds: int = 60,
    use_llm_judge: bool = True,
) -> list:
    """
    TODO 8: Return an ordered list of plugins / layers:

    1. RateLimitPlugin
    2. InputGuardrailPlugin  (from guardrails.input_guardrails)
    3. OutputGuardrailPlugin / LlmJudge  (from guardrails.output_guardrails)
    4. (optional) NeMo wrapper

    Audit/monitoring can be plugins or side observers — document your choice.
    The action gateway calls ``is_egress_allowed`` separately before any sink.
    """
    raise NotImplementedError("Implement build_production_plugins")


def build_observability():
    """TODO: return (AuditLogPlugin(), MonitoringAlert())."""
    raise NotImplementedError("Implement build_observability")


async def run_assignment_suite(pipeline, student_id: str) -> dict:
    """
    TODO: Run Tests 1–4 from assignment11.md and
    return a dict matching schemas/results.schema.json.

    Write:
      outputs/results.json
      outputs/audit_log.json
      outputs/metrics.json
    """
    raise NotImplementedError("Implement run_assignment_suite")
