"""Prometheus metrics."""

from __future__ import annotations

from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

registry = CollectorRegistry()

# --- HTTP -------------------------------------------------------------------
http_requests = Counter(
    "kavachx_http_requests_total",
    "HTTP requests",
    ["method", "path", "status"],
    registry=registry,
)
http_latency = Histogram(
    "kavachx_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
    buckets=(0.005, 0.025, 0.1, 0.25, 1.0, 2.5, 10.0, 30.0),
    registry=registry,
)

# --- runs -------------------------------------------------------------------
runs_started = Counter("kavachx_runs_started_total", "Runs started", registry=registry)
runs_finished = Counter(
    "kavachx_runs_finished_total", "Runs finished", ["status"], registry=registry
)
run_duration = Histogram(
    "kavachx_run_duration_seconds",
    "Run wall-clock duration",
    buckets=(5, 15, 30, 60, 120, 300, 600, 1800, 3600),
    registry=registry,
)
runs_active = Gauge("kavachx_runs_active", "Runs currently executing", registry=registry)

phase_duration = Histogram(
    "kavachx_phase_duration_seconds",
    "Per-phase duration",
    ["phase"],
    buckets=(0.1, 0.5, 1, 5, 15, 60, 300),
    registry=registry,
)

# --- model --------------------------------------------------------------------
model_calls = Counter(
    "kavachx_model_calls_total", "Model calls", ["provider", "task", "outcome"], registry=registry
)
model_tokens = Counter(
    "kavachx_model_tokens_total", "Model tokens", ["provider", "direction"], registry=registry
)
model_latency = Histogram(
    "kavachx_model_latency_seconds",
    "Model call latency",
    ["provider", "task"],
    buckets=(0.05, 0.25, 1, 5, 15, 60, 120),
    registry=registry,
)
schema_violations = Counter(
    "kavachx_model_schema_violations_total",
    "Model responses rejected by strict schema validation",
    ["task"],
    registry=registry,
)

# --- sandbox ------------------------------------------------------------------
sandbox_executions = Counter(
    "kavachx_sandbox_executions_total",
    "Sandbox executions",
    ["adapter", "outcome"],
    registry=registry,
)
sandbox_duration = Histogram(
    "kavachx_sandbox_execution_duration_seconds",
    "Sandbox execution duration",
    ["adapter"],
    buckets=(0.05, 0.25, 1, 5, 15, 60, 120),
    registry=registry,
)
sandbox_egress = Counter(
    "kavachx_sandbox_egress_bytes_total",
    "Bytes that left the sandbox (expected to remain zero)",
    ["adapter"],
    registry=registry,
)
sandbox_network_attempts = Counter(
    "kavachx_sandbox_network_attempts_total",
    "Outbound connection attempts blocked inside the sandbox",
    ["adapter"],
    registry=registry,
)

# --- analysis -----------------------------------------------------------------
coverage_percent = Gauge(
    "kavachx_coverage_percent", "Line coverage achieved", ["run"], registry=registry
)
findings_total = Counter(
    "kavachx_findings_total", "Findings by state", ["state", "severity"], registry=registry
)
clauses_total = Counter(
    "kavachx_samhita_clauses_total", "SAMHITA clauses by status", ["status"], registry=registry
)
patch_iterations = Histogram(
    "kavachx_patch_iterations",
    "Patch iterations needed per finding",
    buckets=(1, 2, 3, 4),
    registry=registry,
)
gauntlet_stage_results = Counter(
    "kavachx_gauntlet_stage_results_total",
    "Gauntlet stage verdicts",
    ["stage", "verdict"],
    registry=registry,
)
gauntlet_failures = Counter(
    "kavachx_gauntlet_failures_total",
    "Patches refuted, by the stage that refuted them",
    ["stage"],
    registry=registry,
)
certificates_issued = Counter(
    "kavachx_certificates_issued_total",
    "Certificates issued by assurance level",
    ["level"],
    registry=registry,
)
certificate_generation = Histogram(
    "kavachx_certificate_generation_seconds",
    "Certificate generation time",
    buckets=(0.01, 0.05, 0.25, 1, 5),
    registry=registry,
)
publish_results = Counter(
    "kavachx_publish_results_total", "Publish outcomes", ["outcome"], registry=registry
)


def render() -> tuple[bytes, str]:
    return generate_latest(registry), CONTENT_TYPE_LATEST


def normalise_path(path: str) -> str:
    """Collapse ids so the label set stays bounded."""
    parts = []
    for segment in path.split("/"):
        if not segment:
            continue
        if len(segment) >= 32 and "-" in segment:
            parts.append("{id}")
        elif segment.isdigit():
            parts.append("{n}")
        else:
            parts.append(segment)
    return "/" + "/".join(parts)


def observe_model_call(payload: dict[str, Any]) -> None:
    provider = str(payload.get("provider", "unknown"))
    task = str(payload.get("task", "unknown"))
    model_calls.labels(provider=provider, task=task, outcome="ok").inc()
    model_tokens.labels(provider=provider, direction="in").inc(int(payload.get("tokens_in", 0)))
    model_tokens.labels(provider=provider, direction="out").inc(int(payload.get("tokens_out", 0)))
    model_latency.labels(provider=provider, task=task).observe(
        int(payload.get("latency_ms", 0)) / 1000.0
    )
