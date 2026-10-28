"""
AI Protector — FastAPI backend entry point.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import select, Session
from pathlib import Path
import json

from .db import engine, init_db
from .models import Scan, Event, Finding, Remediation
from . import scan as scan_mod
from . import remediation as rem_mod
from . import report as report_mod
from . import nebius_integration as nebius

app = FastAPI(
    title="AI Protector API",
    description="AI security testing, attack-chain investigation & verified remediation.",
    version="0.1.0",
)

# Allow all origins in dev — tighten for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


# ── Health ─────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "nebius_configured": nebius.is_configured()}


# ── Scan ────────────────────────────────────────────────────────────────
@app.post("/scan/run")
def run_scan(
    background: BackgroundTasks,
    description: str = Query(default="Manual scan"),
    mode: str = Query(default="baseline", pattern="^(baseline|protected)$"),
):
    """
    Start a scan against the mock target agent.
    mode: 'baseline' (vulnerable) or 'protected' (with auth controls).
    Returns scan_id immediately; scan runs in the background.
    """
    scan_id = scan_mod.create_scan(description, mode)
    background.add_task(scan_mod.run_scan, scan_id, mode)
    return {"scan_id": scan_id, "mode": mode, "status": "running"}


@app.get("/scan")
def list_scans():
    with Session(engine) as session:
        scans = session.exec(select(Scan).order_by(Scan.id.desc())).all()
        return scans


@app.get("/scan/{scan_id}")
def get_scan(scan_id: int):
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan


@app.get("/scan/{scan_id}/events")
def get_events(scan_id: int):
    with Session(engine) as session:
        events = session.exec(
            select(Event).where(Event.scan_id == scan_id).order_by(Event.id)
        ).all()
        return [
            {
                "id": ev.id,
                "type": ev.type,
                "timestamp": ev.timestamp,
                "payload": json.loads(ev.payload),
            }
            for ev in events
        ]


@app.get("/scan/{scan_id}/findings")
def get_findings(scan_id: int):
    with Session(engine) as session:
        findings = session.exec(
            select(Finding).where(Finding.scan_id == scan_id)
        ).all()
        return findings


# ── Attack Library ──────────────────────────────────────────────────────
@app.get("/attacks")
def list_attacks():
    from .attack_library import get_all_attacks
    return get_all_attacks()


# ── Remediation ─────────────────────────────────────────────────────────
@app.get("/findings/{finding_id}/proposal")
def get_proposal(finding_id: int):
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        proposal = rem_mod.get_remediation_proposal(finding)
        return {"finding_id": finding_id, "proposal": proposal}


@app.post("/findings/{finding_id}/remediate")
def remediate(finding_id: int):
    try:
        result = rem_mod.apply_remediation(finding_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── Report ──────────────────────────────────────────────────────────────
@app.get("/report/{scan_id}", response_class=PlainTextResponse)
def get_report(scan_id: int):
    md = report_mod.build_report(scan_id)
    return PlainTextResponse(content=md, media_type="text/markdown")


# ── Nebius / NVIDIA AI Analysis ─────────────────────────────────────────
@app.get("/scan/{scan_id}/ai-analysis")
def ai_analysis(scan_id: int):
    """Use the NVIDIA Nemotron model (via Nebius) to analyze the scan events."""
    with Session(engine) as session:
        events = session.exec(
            select(Event).where(Event.scan_id == scan_id).order_by(Event.id)
        ).all()
        if not events:
            raise HTTPException(status_code=404, detail="No events found for scan")

        # Build a concise chain summary for the model
        lines = []
        for ev in events:
            payload = json.loads(ev.payload)
            lines.append(f"[{ev.type.upper()}] attack={payload.get('attack_id','?')} "
                         f"| {_summarize_payload(ev.type, payload)}")
        summary = "\n".join(lines)

    result = nebius.analyze_attack_trace(summary)
    return result


def _summarize_payload(ev_type: str, payload: dict) -> str:
    if ev_type == "prompt":
        return f"input: {payload.get('input','')[:80]}"
    if ev_type == "model_response":
        ar = payload.get("agent_result", {})
        return f"type={ar.get('type')} content={ar.get('content','')[:60]} tool={ar.get('tool','')}"
    if ev_type == "auth_decision":
        return f"tool={payload.get('tool')} allowed={payload.get('allowed')} reason={payload.get('reason','')}"
    if ev_type == "tool_result":
        return f"executed={payload.get('executed')} result={str(payload.get('result',''))[:60]}"
    return str(payload)[:80]


# ── Static frontend ──────────────────────────────────────────────────────
@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    build_dir = Path(__file__).parent.parent / "frontend" / "build"
    file_path = build_dir / full_path
    if file_path.is_file():
        return FileResponse(file_path)
    index = build_dir / "index.html"
    if index.is_file():
        return FileResponse(index)
    raise HTTPException(status_code=404, detail="Frontend not built. Run: cd frontend && npm run build")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
