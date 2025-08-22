# apps/worker/worker.py
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from queue import Queue, Empty
from pydantic import BaseModel, Field, ConfigDict
import json
import time
import traceback

# Import your pipeline engine
from core.pipeline.engine import run_pipeline


# --------------------------------------------------------------------
# Global in-memory queue (replace with Redis/SQS adapter in production)
# --------------------------------------------------------------------
QUEUE: "Queue[Dict[str, Any]]" = Queue()


def submit_job(payload: Dict[str, Any]) -> None:
    """Enqueue a job dict for processing by worker_loop()."""
    QUEUE.put(payload)


def _get_next_job(timeout: float = 0.2) -> Optional[Dict[str, Any]]:
    try:
        return QUEUE.get(timeout=timeout)
    except Empty:
        return None


# --------------------------------------------------------------------
# RunConfig with field aliases and compatibility shims
# --------------------------------------------------------------------

class RunConfig(BaseModel):
    pipeline_id: str = Field(alias="pipeline_name")
    workdir: Path = Field(alias="workspace_dir")

    run_id: str
    target: str

    module_specs: List[Dict[str, Any]] = Field(alias="modules")

    artifacts_dir: Path
    inputs_dir: Path
    reports_dir: Path

    # NEW: environment bag for engine.py
    env: Dict[str, Any] = Field(default_factory=dict)

    extra: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    # Properties kept as-is…
    @property
    def inputs(self) -> Path:
        return self.inputs_dir

    @property
    def artifacts(self) -> Path:
        return self.artifacts_dir

    @property
    def reports(self) -> Path:
        return self.reports_dir

    @property
    def workspace(self) -> Path:
        return self.workdir


# --------------------------------------------------------------------
# Worker loop
# --------------------------------------------------------------------
def worker_loop(drain: bool = True) -> None:
    """
    Process jobs from the in-memory queue.
    - If drain=True, consume until queue is empty, then return.
    - If drain=False, keep running forever (daemon mode).
    """
    print(f"[worker] starting loop (drain={drain})")
    while True:
        job = _get_next_job()
        if job is None:
            if drain:
                print("[worker] no more jobs; exiting loop.")
                return
            else:
                time.sleep(0.2)
                continue

        print("[worker] received job keys:", list(job.keys()))
        try:
            cfg = RunConfig(**job)
        except Exception as e:
            print("[worker] ❌ failed to parse RunConfig:", e)
            traceback.print_exc()
            continue

        print("[worker] parsed RunConfig:", {
            "run_id": cfg.run_id,
            "pipeline_id": cfg.pipeline_id,
            "workdir": str(cfg.workdir),
            "modules": [m.get("id") if isinstance(m, dict) else m for m in cfg.module_specs],
        })

        try:
            # Normalize to list[str] for engine
            module_paths = []
            for i, m in enumerate(cfg.module_specs):
                if isinstance(m, dict):
                    uses = m.get("uses")
                    if not isinstance(uses, str) or not uses.strip():
                        raise ValueError(f"modules[{i}] missing valid 'uses' string: {m!r}")
                    module_paths.append(uses)
                elif isinstance(m, str):
                    module_paths.append(m)
                else:
                    raise TypeError(f"modules[{i}] must be str or dict, got {type(m).__name__}")

            print("[worker] module_paths:", module_paths)

            # Engine expects (cfg, modules)
            result = run_pipeline(cfg, module_paths)

            _persist_results(cfg, result)
            print(f"[worker] ✅ job {cfg.run_id} completed")

        except Exception as e:
            print(f"[worker] ❌ job {cfg.run_id} failed:", e)
            traceback.print_exc()
        finally:
            QUEUE.task_done()



def _persist_results(cfg: RunConfig, result: Any) -> None:
    """Write results.json under the run directory so local_run.py can aggregate."""
    try:
        run_base = Path(cfg.reports_dir).parent
        run_base.mkdir(parents=True, exist_ok=True)
        results_path = run_base / "results.json"

        if result is not None:
            try:
                with results_path.open("w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
                print(f"[worker] wrote results to {results_path}")
            except TypeError:
                if not results_path.exists():
                    results_path.write_text("{}", encoding="utf-8")
        else:
            if not results_path.exists():
                results_path.write_text("{}", encoding="utf-8")
    except Exception as e:
        print("[worker] warning: could not persist results.json:", e)


# --------------------------------------------------------------------
# Dev mode
# --------------------------------------------------------------------
if __name__ == "__main__":
    # Simple test run
    submit_job({
        "run_id": "dev123",
        "target": "https://example.com",
        "pipeline_name": "web_default",
        "workspace_dir": "./.vapt/dev123/workspace",
        "artifacts_dir": "./.vapt/dev123/artifacts",
        "inputs_dir": "./.vapt/dev123/inputs",
        "reports_dir": "./.vapt/dev123/reports",
        "modules": [
            {"id": "noop", "uses": "core.pipeline.builtins:NoOp", "with": {}}
        ],
        "extra": {},
    })
    worker_loop(drain=True)
