"""HTTP API for the gateway.

/v1/scan        check a piece of text (any app or the red-team harness can call it)
/dashboard      live view of decisions as they happen
/v1/events      new decisions since a given id (what the dashboard polls)
/v1/stats       running totals and latency
v0.4 adds an OpenAI-compatible /v1/chat/completions proxy on top of this.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from gateway import __version__
from gateway.config import build_detectors
from gateway.detectors import Source
from gateway.events import EventLog
from gateway.policy import Action, Policy

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("gateway")

app = FastAPI(title="LLM Security Gateway", version=__version__)
policy = Policy(detectors=build_detectors())   # rules, plus the classifier if GW_CLASSIFIER=1
events = EventLog()
STATIC = Path(__file__).parent / "static"


class ScanRequest(BaseModel):
    text: str = Field(..., max_length=100_000)
    source: Source = Source.USER


class FindingOut(BaseModel):
    detector: str
    category: str
    evidence: str


class ScanResponse(BaseModel):
    action: Action
    score: float
    source: Source
    findings: list[FindingOut]
    latency_ms: float


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "detectors": ",".join(d.name for d in policy.detectors)}


@app.post("/v1/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    start = time.perf_counter()
    decision = policy.evaluate(req.text, req.source)
    latency_ms = round((time.perf_counter() - start) * 1000, 3)

    findings = [
        FindingOut(detector=v.detector, category=f.category, evidence=f.evidence)
        for v in decision.verdicts
        for f in v.findings
    ]
    if decision.action != Action.ALLOW:
        # Log the decision and categories, never the full text: prompts can hold PII.
        log.warning(
            "action=%s source=%s score=%.3f categories=%s",
            decision.action.value, req.source.value, decision.score,
            sorted({f.category for f in findings}),
        )
    events.record(
        action=decision.action.value, score=decision.score, source=req.source.value,
        categories=sorted({f.category for f in findings}), latency_ms=latency_ms, text=req.text,
    )
    return ScanResponse(
        action=decision.action, score=decision.score, source=req.source,
        findings=findings, latency_ms=latency_ms,
    )


@app.get("/v1/events")
def get_events(after: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=500)) -> list[dict]:
    return events.since(after, limit)


@app.get("/v1/stats")
def get_stats() -> dict:
    return events.stats()


@app.get("/dashboard", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC / "dashboard.html")
