"""
Simple sequential engine placeholder.
Later: DAG, retries, parallel stages, budgets.
"""
from __future__ import annotations
import json, subprocess, sys, pathlib
from typing import List, Dict, Any
from .contracts import RunConfig, ModuleResult

def run_module(module_dir: str, payload: dict) -> ModuleResult:
    entry = pathlib.Path(module_dir) / "main.py"
    if not entry.exists():
        raise FileNotFoundError(f"main.py missing in {module_dir}")
    proc = subprocess.run([sys.executable, str(entry), "--stdin"],
                          input=json.dumps(payload).encode("utf-8"),
                          capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", errors="ignore"))
    out = json.loads(proc.stdout.decode("utf-8"))
    return ModuleResult.model_validate(out)

def run_pipeline(config: RunConfig, modules: List[str]) -> Dict[str, Any]:
    workdir = pathlib.Path(config.workdir); workdir.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": config.run_id,
        "workdir": config.workdir,
        "inputs": config.inputs,
        "env": config.env,
    }
    all_findings, all_artifacts = [], []
    for m in modules:
        res = run_module(m, payload)
        all_findings.extend([f if isinstance(f, dict) else f.model_dump() for f in res.findings])
        all_artifacts.extend([a if isinstance(a, dict) else a.model_dump() for a in res.artifacts])
    (workdir / "findings.json").write_text(json.dumps({"findings": all_findings}, indent=2), encoding="utf-8")
    return {"findings": all_findings, "artifacts": all_artifacts}
