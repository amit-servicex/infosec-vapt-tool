# core/pipeline/engine.py
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

# ---------- JSON helpers -----------------------------------------------------

def _json_default(o: Any):
    if isinstance(o, Path):
        return str(o)
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, Enum):
        return o.value
    return str(o)

# ---------- Config helpers ---------------------------------------------------

def _cfg_get(cfg: Any, *names: str, default=None):
    """Fetch first present value among names from either object attrs or dict keys."""
    for n in names:
        v = getattr(cfg, n, None)
        if v is not None:
            return v
        if isinstance(cfg, dict):
            v = cfg.get(n, None)
            if v is not None:
                return v
    return default

def _ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

# ---------- Module resolution & execution ------------------------------------

def _resolve_entrypoint(mod_path: Union[str, Path]) -> Path:
    p = Path(mod_path)
    if p.is_dir():
        p = p / "main.py"
    return p.resolve()

def run_module(entrypoint: Union[str, Path],
               payload: Dict[str, Any],
               timeout_sec: int | None = None) -> Dict[str, Any]:
    ep = _resolve_entrypoint(entrypoint)
    started = datetime.utcnow()

    if not ep.exists():
        return {
            "status": "error",
            "error": f"Entrypoint not found: {ep}",
            "started_at": started.isoformat(),
            "ended_at": datetime.utcnow().isoformat(),
        }

    try:
        proc = subprocess.run(
            [sys.executable, str(ep)],
            input=json.dumps(payload, default=_json_default).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(ep.parent),
            timeout=timeout_sec or payload.get("config", {}).get("timeout_sec", 1800),
        )
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")

        if proc.returncode != 0:
            return {
                "status": "error",
                "error": f"Module exited with code {proc.returncode}",
                "stdout": stdout[-4000:],
                "stderr": stderr[-4000:],
                "started_at": started.isoformat(),
                "ended_at": datetime.utcnow().isoformat(),
                "module_entrypoint": str(ep),
            }

        try:
            data = json.loads(stdout or "{}")
        except Exception as e:
            return {
                "status": "error",
                "error": f"Module returned non-JSON stdout: {e}",
                "stdout": stdout[-4000:],
                "stderr": stderr[-4000:],
                "started_at": started.isoformat(),
                "ended_at": datetime.utcnow().isoformat(),
                "module_entrypoint": str(ep),
            }

        data.setdefault("status", "ok")
        data.setdefault("findings", [])
        data.setdefault("artifacts", [])
        data.update({
            "started_at": started.isoformat(),
            "ended_at": datetime.utcnow().isoformat(),
            "module_entrypoint": str(ep),
        })
        if stderr.strip():
            data["stderr"] = stderr[-4000:]
        return data

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "Module timed out",
            "started_at": started.isoformat(),
            "ended_at": datetime.utcnow().isoformat(),
            "module_entrypoint": str(ep),
        }
    except Exception as e:
        return {
            "status": "error",
            "error": f"Exception: {e}",
            "started_at": started.isoformat(),
            "ended_at": datetime.utcnow().isoformat(),
            "module_entrypoint": str(ep),
        }

# ---------- Pipeline orchestration -------------------------------------------

def run_pipeline(cfg: Any, module_paths: List[str]) -> Dict[str, Any]:
    """
    Supports both legacy and new config keys:
      - workspace_dir OR workdir
      - pipeline_name OR pipeline_id
      - derives inputs/artifacts/reports if missing: data/runs/<run_id>/*
    """
    run_id        = _cfg_get(cfg, "run_id", "id")
    target        = _cfg_get(cfg, "target")
    pipeline_name = _cfg_get(cfg, "pipeline_name", "pipeline_id", default="pipeline")

    # Base directory for derived paths
    # Prefer explicit run_base/run_dir/base_dir if provided; else CWD/data/runs/<run_id>
    explicit_base = _cfg_get(cfg, "run_base", "run_dir", "base_dir")
    default_base  = Path.cwd() / "data" / "runs" / (run_id or "run")
    base_dir      = Path(explicit_base) if explicit_base else default_base

    # Accept workspace_dir OR workdir; default to base_dir/workspace
    workspace_dir = _cfg_get(cfg, "workspace_dir", "workdir")
    workspace_dir = Path(workspace_dir) if workspace_dir else (base_dir / "workspace")

    # Others: accept explicit, else derive under base_dir
    inputs_dir    = _cfg_get(cfg, "inputs_dir")
    inputs_dir    = Path(inputs_dir) if inputs_dir else (base_dir / "inputs")

    artifacts_dir = _cfg_get(cfg, "artifacts_dir")
    artifacts_dir = Path(artifacts_dir) if artifacts_dir else (base_dir / "artifacts")

    reports_dir   = _cfg_get(cfg, "reports_dir")
    reports_dir   = Path(reports_dir) if reports_dir else (base_dir / "reports")

    # Ensure dirs exist
    for p in (workspace_dir, artifacts_dir, inputs_dir, reports_dir):
        _ensure_dir(p)

    modules_ids   = list(_cfg_get(cfg, "modules", default=[]))
    extra_cfg     = dict(_cfg_get(cfg, "extra", default={}))
    started       = datetime.utcnow()
    results: List[Dict[str, Any]] = []
    previous_outputs: Dict[str, Any] = {}

    # Pair ids with paths
    pairs: List[Tuple[str, str]] = list(zip(modules_ids, module_paths))

    for module_id, module_path in pairs:
        m_config = extra_cfg.get(module_id, {})
        payload = {
            "run_id": run_id,
            "target": target,
            "workspace_dir": workspace_dir,
            "artifacts_dir": artifacts_dir,
            "inputs_dir": inputs_dir,
            "reports_dir": reports_dir,
            "previous_outputs": previous_outputs,
            "config": m_config,
        }

        res = run_module(module_path, payload, timeout_sec=m_config.get("timeout_sec"))
        previous_outputs[module_id] = res
        res.setdefault("module_id", module_id)
        results.append(res)

        if res.get("status") == "error" and m_config.get("fail_fast", False):
            break

    ended = datetime.utcnow()
    return {
        "run_id": run_id,
        "pipeline_name": pipeline_name,
        "started_at": started.isoformat(),
        "ended_at": ended.isoformat(),
        "results": results,
    }
