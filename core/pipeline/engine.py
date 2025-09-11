from __future__ import annotations

import json, subprocess, sys, shlex, os
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union
from .registry import ModuleSpec, resolve_ids, load_index

def _json_default(o: Any):
    if isinstance(o, Path): return str(o)
    if isinstance(o, datetime): return o.isoformat()
    if isinstance(o, Enum): return o.value
    return str(o)

def _ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def _resolve_entrypoint(path_or_dir: Union[str, Path]) -> Path:
    p = Path(path_or_dir)
    if p.is_dir(): p = p / "main.py"
    return p.resolve()

# -------- Docker runner ------------------------------------------------------

def _host_path_for_volume(name: str, m_input: Dict[str, Any], spec: ModuleSpec) -> Path:
    # Standard names map to the run's dirs; cache maps to data/cache/<module-id>
    base = Path.cwd()
    if name == "artifacts": return Path(m_input["artifacts_dir"])
    if name == "workspace": return Path(m_input["workspace_dir"])
    if name == "inputs":    return Path(m_input["inputs_dir"])
    if name == "reports":   return Path(m_input["reports_dir"])
    if name == "cache":     return base / "data" / "cache" / spec.id.replace(".", "_")
    # Fallback: nested under workspace
    return Path(m_input["workspace_dir"]) / name




def _run_module_docker(spec: ModuleSpec, m_input: Dict[str, Any]) -> Dict[str, Any]:
    from copy import deepcopy
    started = datetime.utcnow()
    if not spec.image:
        return {"status":"error","error":"docker runtime requires 'image' in manifest",
                "started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat(),
                "module_entrypoint":"<docker>"}

    #cmd = ["docker","run","--rm","-i","--cap-drop","ALL","--security-opt","no-new-privileges"]
    cmd = ["docker","run","--rm","-i"]
    if spec.id == "web.nuclei.basic":
    # Hardened but functional for this binary:
        cmd += ["--cap-drop","ALL"]  # keep caps dropped
        # NOTE: do NOT add "no-new-privileges" here
    else:
        # default hardened path for the rest
        cmd += ["--cap-drop","ALL","--security-opt","no-new-privileges"]

    # Resources
    if spec.resources and spec.resources.cpu:    cmd += ["--cpus",  spec.resources.cpu]
    if spec.resources and spec.resources.memory: cmd += ["--memory", spec.resources.memory]
    if spec.user:    cmd += ["--user", spec.user]
    if spec.network: cmd += ["--network", spec.network]
    if spec.workdir: cmd += ["-w", spec.workdir]

    # Volumes: build mounts and a container-path map
    vols = spec.volumes or []
    container_paths: dict[str, str] = {}  # logical name -> container path
    for v in vols:
        # Map host path by logical name
        if v.name == "artifacts":
            host = Path(m_input["artifacts_dir"])
        elif v.name == "workspace":
            host = Path(m_input["workspace_dir"])
        elif v.name == "inputs":
            host = Path(m_input["inputs_dir"])
        elif v.name == "reports":
            host = Path(m_input["reports_dir"])
        elif v.name == "cache":
            host = Path.cwd() / "data" / "cache" / spec.id.replace(".", "_")
        else:
            # generic: workspace/<name>
            host = Path(m_input["workspace_dir"]) / v.name

        _ensure_dir(host)
        cmd += ["-v", f"{str(host)}:{v.mountPath}"]
        container_paths[v.name] = v.mountPath

        # Special case: ZAP wants /zap/wrk mounted; reuse artifacts host dir
        if v.mountPath == "/zap/wrk":
            container_paths["artifacts"] = "/zap/wrk"

    # Env
    if spec.env:
        for e in spec.env: cmd += ["-e", e]
    cmd += ["-e", f"RUN_ID={m_input['run_id']}","-e", f"TARGET={m_input['target']}"]

    # Image + command
    cmd += [spec.image]
    if spec.cmd: cmd += spec.cmd

    # --- REWRITE PATHS for container ---
    c_input = deepcopy(m_input)
    # prefer explicit mounts; fall back to original if not present
    c_input["artifacts_dir"] = container_paths.get("artifacts", c_input["artifacts_dir"])
    c_input["workspace_dir"] = container_paths.get("workspace", c_input["workspace_dir"])
    c_input["inputs_dir"]    = container_paths.get("inputs",    c_input["inputs_dir"])
    c_input["reports_dir"]   = container_paths.get("reports",   c_input["reports_dir"])

    try:
        proc = subprocess.run(
            cmd,
            input=json.dumps(c_input, default=_json_default).encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=m_input.get("config", {}).get("timeout_sec", 1800)
        )
        stdout = proc.stdout.decode("utf-8","replace")
        stderr = proc.stderr.decode("utf-8","replace")

        if proc.returncode != 0:
            return {"status":"error","error":f"docker exited {proc.returncode}",
                    "stdout":stdout[-4000:],"stderr":stderr[-4000:],
                    "started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat(),
                    "module_entrypoint":f"docker://{spec.image}"}

        data = json.loads(stdout or "{}")
        data.setdefault("status","ok"); data.setdefault("findings",[]); data.setdefault("artifacts",[])
        data.update({"started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat(),
                     "module_entrypoint":f"docker://{spec.image}"})
        if stderr.strip(): data["stderr"] = stderr[-4000:]
        return data
    except subprocess.TimeoutExpired:
        return {"status":"error","error":"docker module timed out",
                "started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat(),
                "module_entrypoint":f"docker://{spec.image}"}
    except Exception as e:
        return {"status":"error","error":f"docker exception: {e}",
                "started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat(),
                "module_entrypoint":f"docker://{spec.image}"}



# -------- Process runner -----------------------------------------------------

def _run_module_process(spec: ModuleSpec, m_input: Dict[str, Any]) -> Dict[str, Any]:
    started = datetime.utcnow()
    ep = _resolve_entrypoint(spec.entrypoint) if spec.entrypoint else None
    if not ep or not ep.exists():
        return {"status":"error","error":f"Entrypoint not found: {ep}",
                "started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat()}
    try:
        proc = subprocess.run(
            [sys.executable, str(ep)],
            input=json.dumps(m_input, default=_json_default).encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(ep.parent),
            timeout=m_input.get("config", {}).get("timeout_sec", 1800),
        )
        stdout = proc.stdout.decode("utf-8","replace")
        stderr = proc.stderr.decode("utf-8","replace")
        if proc.returncode != 0:
            return {"status":"error","error":f"Module exited {proc.returncode}",
                    "stdout":stdout[-4000:], "stderr":stderr[-4000:],
                    "started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat(),
                    "module_entrypoint":str(ep)}
        try:
            data = json.loads(stdout or "{}")
        except Exception as e:
            return {"status":"error","error":f"Non-JSON stdout: {e}",
                    "stdout":stdout[-4000:], "stderr":stderr[-4000:],
                    "started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat(),
                    "module_entrypoint":str(ep)}
        data.setdefault("status","ok"); data.setdefault("findings",[]); data.setdefault("artifacts",[])
        data.update({"started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat(),
                     "module_entrypoint":str(ep)})
        if stderr.strip(): data["stderr"] = stderr[-4000:]
        return data
    except subprocess.TimeoutExpired:
        return {"status":"error","error":"Module timed out",
                "started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat(),
                "module_entrypoint":str(ep)}
    except Exception as e:
        return {"status":"error","error":f"Exception: {e}",
                "started_at":started.isoformat(),"ended_at":datetime.utcnow().isoformat(),
                "module_entrypoint":str(ep)}

# -------- Orchestrator -------------------------------------------------------

def run_pipeline(cfg: Any, module_specs_or_paths: List[Union[str, ModuleSpec]]) -> Dict[str, Any]:
    def _get(k, d=None): return getattr(cfg,k, cfg.get(k,d) if isinstance(cfg,dict) else d)

    run_id        = _get("run_id")
    target        = _get("target")
    pipeline_name = _get("pipeline_name", _get("pipeline_id","pipeline"))
    base_dir      = Path.cwd() / "data" / "runs" / (run_id or "run")

    workspace_dir = Path(_get("workspace_dir", _get("workdir", base_dir / "workspace")))
    artifacts_dir = Path(_get("artifacts_dir", base_dir / "artifacts"))
    inputs_dir    = Path(_get("inputs_dir", base_dir / "inputs"))
    reports_dir   = Path(_get("reports_dir", base_dir / "reports"))
    for p in (workspace_dir, artifacts_dir, inputs_dir, reports_dir): _ensure_dir(p)

    started = datetime.utcnow()
    results: List[Dict[str, Any]] = []
    prev: Dict[str, Any] = {}

    # Normalize to ModuleSpec list
    specs: List[ModuleSpec] = []
    for item in module_specs_or_paths:
        if isinstance(item, ModuleSpec):
            specs.append(item); continue
        # If a string, try ID first, else treat as path (process)
        try:
            specs.append(resolve_ids([item])[0])
        except Exception:
            specs.append(ModuleSpec(
                id=item, name=item, entrypoint=str(_resolve_entrypoint(item)), runtime="process"
            ))

    job_overrides = (_get("extra", {}) or {}).get("__runtime__", {})
    for spec in specs:
        override = job_overrides.get(spec.id, job_overrides.get("*"))
        runtime = _decide_runtime(spec, override)
        m_input = {
            "run_id": run_id, "target": target,
            "workspace_dir": workspace_dir, "artifacts_dir": artifacts_dir,
            "inputs_dir": inputs_dir, "reports_dir": reports_dir,
            "previous_outputs": prev, "config": {},
        }
        res = _run_module_docker(spec, m_input) if runtime == "docker" else _run_module_process(spec, m_input)
        res.setdefault("module_id", spec.id)
        prev[spec.id] = res
        results.append(res)
        if res.get("status") == "error" and m_input["config"].get("fail_fast"):
            break

    ended = datetime.utcnow()
    return {"run_id": run_id, "pipeline_name": pipeline_name,
            "started_at": started.isoformat(), "ended_at": ended.isoformat(),
            "results": results}


def _decide_runtime(spec, job_override: str | None = None) -> str:
    # precedence: job override > manifest.runtime > AUTO
    if job_override:
        return job_override.lower()
    if (spec.runtime or "").lower() in ("docker", "process"):
        return spec.runtime.lower()
    return "docker" if spec.image else "process"
