"""Argos demo — FastAPI app serving the public UI.

This is the same code a bank would deploy for the investigation engine,
wrapped in a minimal HTTP layer so people can click alerts in a browser and
watch the graph run. It is deliberately small — everything interesting lives
in the argos package; this file is glue.

Endpoints
---------
GET  /                          → serve index.html
GET  /static/<file>             → serve CSS and JS
GET  /api/alerts                → list synthetic sample alerts
POST /api/investigate/{alert_id}→ run the investigation graph, return full state
GET  /api/audit/verify          → verify the audit log chain integrity
GET  /api/health                → basic liveness + mode info

Security posture for the public demo
------------------------------------
This service runs with ARGOS_MODE=demo and binds to localhost only (via the
docker-compose port mapping). The synthetic dataset contains no real
customer data. The reasoning node runs against a local Ollama model. If
Ollama is unavailable, the FallbackBackend engages and every alert is
force-escalated with a "fallback mode" banner — the demo NEVER silently
uses a hosted model for production data.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from argos import __version__
from argos.audit import load_audit_log_from_env
from argos.connectors import StdoutConnector
from argos.graph import build_graph
from argos.privacy import load_pseudonymizer_from_env
from argos.reasoning import FallbackBackend, load_backend_from_env
from argos.schemas import Alert, ArgosState
from argos.synthetic import generate_demo_dataset

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

demo_state: "DemoState | None" = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build the demo graph once when the app starts, tear down on shutdown.

    Uses the FastAPI lifespan pattern (the successor to the deprecated
    @app.on_event("startup") decorator). The DemoState holds the compiled
    LangGraph and all injected dependencies; it is constructed once and
    reused across every HTTP request.
    """
    global demo_state
    demo_state = DemoState()
    yield
    demo_state = None


app = FastAPI(
    title="Argos Demo",
    version=__version__,
    description=(
        "Open-source Alert Investigation Copilot. This demo runs against "
        "synthetic data only. Never use with real customer data."
    ),
    lifespan=lifespan,
)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Global state — built once at startup
# ---------------------------------------------------------------------------


class DemoState:
    def __init__(self) -> None:
        self.data_source, self.alerts = generate_demo_dataset()
        self.reasoning_backend = load_backend_from_env()
        self.pseudonymizer = load_pseudonymizer_from_env()
        self.audit_log = load_audit_log_from_env()
        self.case_connector = StdoutConnector()
        self.graph = build_graph(
            data_source=self.data_source,
            reasoning_backend=self.reasoning_backend,
            pseudonymizer=self.pseudonymizer,
            audit_log=self.audit_log,
            case_connector=self.case_connector,
        )
        self.alerts_by_id: dict[str, Alert] = {a.alert_id: a for a in self.alerts}

    @property
    def in_fallback_mode(self) -> bool:
        return isinstance(self.reasoning_backend, FallbackBackend)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> JSONResponse:
    assert demo_state is not None
    return JSONResponse(
        {
            "status": "ok",
            "version": __version__,
            "mode": os.environ.get("ARGOS_MODE", "demo"),
            "fallback_mode": demo_state.in_fallback_mode,
            "alert_count": len(demo_state.alerts),
        }
    )


@app.get("/api/alerts")
async def list_alerts() -> JSONResponse:
    """Return summaries of the sample alerts for the left pane."""
    assert demo_state is not None
    summaries = [
        {
            "alert_id": a.alert_id,
            "rule_id": a.rule_id,
            "score": a.score,
            "fired_at": a.fired_at.isoformat(),
            "customer_id": a.customer_id,
            "amount": str(a.transaction.amount),
            "currency": a.transaction.currency,
        }
        for a in demo_state.alerts
    ]
    return JSONResponse({"alerts": summaries})


@app.post("/api/investigate/{alert_id}")
async def investigate(alert_id: str) -> JSONResponse:
    """Run the full investigation graph on one alert and return the result.

    Returns the complete final state: the evidence package, the
    recommendation with citations, any errors, and an indication of whether
    the hard-sanctions override fired.
    """
    assert demo_state is not None

    alert = demo_state.alerts_by_id.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Unknown alert: {alert_id}")

    initial_state = ArgosState(alert=alert)
    final_state_dict = await demo_state.graph.ainvoke(initial_state)

    # LangGraph returns a dict; re-wrap for clean serialization.
    final_state = ArgosState.model_validate(final_state_dict)

    return JSONResponse(
        {
            "alert_id": alert_id,
            "evidence_package": (
                json.loads(final_state.evidence_package.model_dump_json())
                if final_state.evidence_package
                else None
            ),
            "recommendation": (
                json.loads(final_state.recommendation.model_dump_json())
                if final_state.recommendation
                else None
            ),
            "hard_sanctions_override": final_state.hard_sanctions_override,
            "errors": final_state.errors,
            "fallback_mode": demo_state.in_fallback_mode,
        }
    )


@app.get("/api/audit/verify")
async def verify_audit() -> JSONResponse:
    """Verify the hash-chain integrity of the audit log."""
    assert demo_state is not None
    ok, error = demo_state.audit_log.verify()
    return JSONResponse({"verified": ok, "error": error})


# ---------------------------------------------------------------------------
# Local dev entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    import uvicorn

    uvicorn.run(
        "demo.app:app",
        host=os.environ.get("ARGOS_HTTP_HOST", "0.0.0.0"),
        port=int(os.environ.get("ARGOS_HTTP_PORT", "8080")),
        reload=False,
    )


if __name__ == "__main__":
    main()
