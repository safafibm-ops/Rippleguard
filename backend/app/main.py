"""
RippleGuard API.

Serves the JSON API and the zero-build frontend from one process:
    uvicorn backend.app.main:app --reload
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .clients.base import fetcher
from .config import FIXTURES, FRONTEND, settings
from .evaluation.validate import evaluate_ranking, load_iocs
from .explain import llm, templates
from .graph.builder import PACKAGE
from .pipeline import JOBS, _new_job, graph_payload, run_scan
from .simulate.propagation import simulate
from .simulate.remediation import ACTIONS, evaluate as evaluate_remediation

app = FastAPI(
    title="RippleGuard",
    version="0.1.0",
    description="Dual-channel software supply-chain ecosystem risk analysis.",
)


@app.on_event("shutdown")
async def _shutdown() -> None:
    await fetcher.aclose()


# --------------------------------------------------------------- schemas ---

class ScanRequest(BaseModel):
    repo_url: str = Field("", description="https://github.com/owner/repo")
    files: dict[str, str] = Field(
        default_factory=dict,
        description="Manifest/SBOM contents keyed by filename",
    )
    source_files: dict[str, str] = Field(
        default_factory=dict,
        description="First-party source for the reachability proxy",
    )


class SimulateRequest(BaseModel):
    node_id: str
    max_depth: int = 8


class RemediateRequest(BaseModel):
    node_id: str
    actions: list[str] | None = None


class ExplainRequest(BaseModel):
    node_id: str
    use_llm: bool = True


# ------------------------------------------------------------------ meta ---

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "offline_mode": settings.offline,
        "llm_enabled": llm.available(),
        "sources": fetcher.health_report(),
        "limits": {
            "max_packages": settings.max_packages,
            "max_depth": settings.max_depth,
            "include_dev_dependencies": settings.include_dev_dependencies,
        },
    }


@app.get("/api/model")
async def model_card():
    """The exact risk model in force. Rendered verbatim in the UI."""
    return settings.model_card()


@app.get("/api/samples")
async def samples():
    out = []
    for p in sorted(FIXTURES.glob("sample-*")):
        if p.is_dir():
            files = {f.name: f.read_text() for f in p.iterdir() if f.is_file()}
            meta = json.loads((p / "_meta.json").read_text()) if (p / "_meta.json").exists() else {}
            files.pop("_meta.json", None)
            out.append({"id": p.name, "files": files, **meta})
    return {"samples": out}


# ------------------------------------------------------------------ scan ---

@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    """Kick the scan off on the running loop and return immediately.

    We schedule with asyncio.create_task rather than BackgroundTasks because
    BackgroundTasks runs sync callables in a worker thread, where there is no
    event loop for the async pipeline to attach to. A reference is kept so the
    task is not garbage collected mid-scan.
    """
    if not req.repo_url and not req.files:
        raise HTTPException(400, "Provide either repo_url or files.")
    jid = _new_job()
    task = asyncio.create_task(
        run_scan(jid, repo_url=req.repo_url, files=req.files,
                 source_files=req.source_files)
    )
    JOBS[jid]["_task"] = task
    return {"scan_id": jid, "status": "queued"}


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    job = JOBS.get(scan_id)
    if not job:
        raise HTTPException(404, "Unknown scan id.")
    return {"scan_id": scan_id, "status": job["status"], "stages": job["stages"],
            "error": job["error"]}


@app.get("/api/scan/{scan_id}")
async def scan_result(scan_id: str):
    job = _job(scan_id, require_complete=True)
    return job["result"]


@app.get("/api/scan/{scan_id}/graph")
async def scan_graph(scan_id: str, limit: int = 260):
    job = _job(scan_id, require_complete=True)
    return graph_payload(job["graph"], job["result"]["findings"], limit)


@app.get("/api/scan/{scan_id}/package/{node_id:path}")
async def package_detail(scan_id: str, node_id: str):
    job = _job(scan_id, require_complete=True)
    for f in job["result"]["findings"]:
        if f["id"] == node_id:
            return f
    raise HTTPException(404, f"No package {node_id} in this scan.")


# -------------------------------------------------------------- simulate ---

@app.post("/api/scan/{scan_id}/simulate")
async def simulate_compromise(scan_id: str, req: SimulateRequest):
    job = _job(scan_id, require_complete=True)
    g = job["graph"]
    if req.node_id not in g:
        raise HTTPException(404, f"No node {req.node_id} in this scan.")
    if g.nodes[req.node_id].get("kind") != PACKAGE:
        raise HTTPException(400, "Compromise simulation runs on package nodes.")
    try:
        return await asyncio.to_thread(simulate, g, req.node_id,
                                       max_depth=req.max_depth)
    except Exception as exc:
        raise HTTPException(500, f"Simulation failed: {exc}")


@app.post("/api/scan/{scan_id}/remediate")
async def remediate(scan_id: str, req: RemediateRequest):
    job = _job(scan_id, require_complete=True)
    g, rescore = job["graph"], job["rescore"]
    if req.node_id not in g:
        raise HTTPException(404, f"No node {req.node_id} in this scan.")
    bad = set(req.actions or []) - set(ACTIONS)
    if bad:
        raise HTTPException(400, f"Unknown action(s): {sorted(bad)}")
    try:
        return await asyncio.to_thread(
            evaluate_remediation, g, req.node_id, rescore, req.actions
        )
    except Exception as exc:
        raise HTTPException(500, f"Remediation modelling failed: {exc}")


# --------------------------------------------------------------- explain ---

@app.post("/api/scan/{scan_id}/explain")
async def explain(scan_id: str, req: ExplainRequest):
    job = _job(scan_id, require_complete=True)
    finding = next((f for f in job["result"]["findings"] if f["id"] == req.node_id),
                   None)
    if not finding:
        raise HTTPException(404, f"No package {req.node_id} in this scan.")

    sim = None
    try:
        sim = await asyncio.to_thread(simulate, job["graph"], req.node_id, max_depth=6)
    except Exception:
        pass

    deterministic = templates.explain_finding(finding, sim)
    bundle = templates.evidence_bundle(finding, sim)
    narrative = None
    if req.use_llm and llm.available():
        narrative = await llm.explain(bundle)

    return {
        "deterministic": deterministic,
        "evidence_bundle": bundle,
        "llm": narrative,
        "llm_enabled": llm.available(),
        "llm_policy": (
            "The model receives only the evidence bundle shown here, has no "
            "tools, and its output is rejected if it names any package or "
            "advisory not present in that bundle. It never produces a score."
        ),
    }


# -------------------------------------------------------------- evaluate ---

@app.get("/api/scan/{scan_id}/evaluate")
async def evaluate_scan(scan_id: str):
    job = _job(scan_id, require_complete=True)
    return evaluate_ranking(job["result"]["findings"], load_iocs())


# ------------------------------------------------------------------ misc ---

def _job(scan_id: str, require_complete: bool = False) -> dict:
    job = JOBS.get(scan_id)
    if not job:
        raise HTTPException(404, "Unknown scan id.")
    if require_complete:
        if job["status"] == "error":
            raise HTTPException(500, job["error"] or "Scan failed.")
        if job["status"] != "complete":
            raise HTTPException(409, f"Scan is {job['status']}; poll /status first.")
    return job


@app.get("/")
async def index():
    path = FRONTEND / "index.html"
    if not path.exists():
        return JSONResponse({"error": "frontend not built"}, status_code=500)
    return FileResponse(path)


if FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
