import json, subprocess, sys, time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from .contracts import RunConfig, ModuleInput, ModuleResult, PipelineResult
from .registry import discover_modules, ModuleSpec


def _run_module(spec: ModuleSpec, m_input: ModuleInput) -> ModuleResult:
    started = datetime.utcnow()
    try:
        proc = subprocess.run(
            [sys.executable, spec.entrypoint],
            input=m_input.model_dump_json().encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(Path(spec.entrypoint).parent),
            timeout=m_input.config.get("timeout_sec", 1800),
        )
        if proc.returncode != 0:
            return ModuleResult(
                module_id=spec.id,
                started_at=started,
                ended_at=datetime.utcnow(),
                status="error",
                error=proc.stderr.decode("utf-8")[:8000],
                findings=[],
                artifacts=[],
                raw_output=proc.stdout.decode("utf-8")[:4000],
            )
        payload = json.loads(proc.stdout.decode("utf-8") or "{}")
        return ModuleResult(
            module_id=spec.id,
            started_at=started,
            ended_at=datetime.utcnow(),
            status=payload.get("status","ok"),
            error=payload.get("error"),
            findings=payload.get("findings",[]),
            artifacts=payload.get("artifacts",[]),
            raw_output=payload.get("raw_output"),
        )
    except Exception as e:
        return ModuleResult(
            module_id=spec.id,
            started_at=started,
            ended_at=datetime.utcnow(),
            status="error",
            error=str(e),
            findings=[],
            artifacts=[],
        )


def run_pipeline(cfg: RunConfig) -> PipelineResult:
    mods = discover_modules()
    id2spec = {m.id: m for m in mods}
    res = PipelineResult(
        run_id=cfg.run_id,
        pipeline_name=cfg.pipeline_name,
        started_at=datetime.utcnow(),
        results=[],
    )

    previous_outputs: Dict[str, Any] = {}
    for module_id in cfg.modules:
        spec = id2spec.get(module_id)
        if not spec:
            res.results.append(ModuleResult(
                module_id=module_id,
                started_at=datetime.utcnow(),
                ended_at=datetime.utcnow(),
                status="skipped",
                error="Module not found",
            ))
            continue

        m_input = ModuleInput(
            run_id=cfg.run_id,
            target=cfg.target,
            workspace_dir=cfg.workspace_dir,
            artifacts_dir=cfg.artifacts_dir,
            previous_outputs=previous_outputs,
            config=cfg.extra.get(module_id, {}),
        )
        m_res = _run_module(spec, m_input)
        res.results.append(m_res)
        previous_outputs[spec.id] = m_res.model_dump()

    res.ended_at = datetime.utcnow()
    return res
