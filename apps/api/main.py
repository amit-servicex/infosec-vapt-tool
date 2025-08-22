from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uuid

app = FastAPI(title="VAPT Orchestrator API", version="0.1.0")
RUNS: Dict[str, Dict[str, Any]] = {}  # in-memory; swap with DB later

class JobRequest(BaseModel):
    pipeline_id: str
    inputs: Dict[str, Any] = {}
    allowlist: Optional[list[str]] = None
    blocklist: Optional[list[str]] = None
    active: bool = False

@app.post("/jobs")
def create_job(job: JobRequest):
    run_id = str(uuid.uuid4())
    RUNS[run_id] = {"status": "queued", "job": job.model_dump()}
    # TODO: enqueue for apps/worker
    return {"run_id": run_id, "status": "queued"}

@app.get("/runs/{run_id}")
def get_run(run_id: str):
    if run_id not in RUNS:
        raise HTTPException(404, "run not found")
    return RUNS[run_id]
