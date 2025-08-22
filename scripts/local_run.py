#!/usr/bin/env python3
import argparse, json, uuid, sys
from pathlib import Path
from datetime import datetime
from core.reporting.aggregate import merge_results
from core.reporting.writers.html_writer import write_html


def load_pipeline(repo_root: Path, pipeline_name: str) -> dict:
    """
    Load and normalize a pipeline YAML:
      - Path: <repo_root>/pipelines/<pipeline_name>.yaml
      - Accepts:
          • modules: [ "pkg.mod", {uses: "pkg.mod", with: {...}}, {"pkg.mod": {...}} ]
          • stages:  [ {stage_name: ["pkg.mod", {"pkg.mod": {...}} , ...]}, ... ]
      - Normalizes to: modules = [ {id, uses, with} ... ]
    """
    import yaml
    p = repo_root / "pipelines" / f"{pipeline_name}.yaml"
    if not p.exists():
        raise FileNotFoundError(
            f"Pipeline file not found: {p}\nTip: run from repo root or pass a valid --pipeline."
        )

    try:
        print(f"[DEBUG] Loading pipeline from: {p}")
        data = yaml.safe_load(p.read_text()) or {}
    except Exception as e:
        raise RuntimeError(f"Failed to parse YAML {p}: {e}")

    if not isinstance(data, dict) or not data:
        raise ValueError(f"Pipeline YAML {p} is empty or not a mapping. Got: {type(data).__name__}")

    data.setdefault("name", pipeline_name)

    # Prefer 'modules'; if absent, accept legacy 'stages'
    modules = data.get("modules")
    stages = data.get("stages") if modules is None else None

    normalized = []

    def to_mod(mod_like, idx: int, stage_name: str | None = None) -> dict:
        """Convert one item (str/dict/single-key-dict) to {id, uses, with}."""
        if isinstance(mod_like, str):
            uses = mod_like
            mod_id = (uses.split(":")[-1].replace("/", ".").split(".")[-1]) or f"mod{idx}"
            if stage_name:
                mod_id = f"{stage_name}_{mod_id}"
            return {"id": mod_id, "uses": uses, "with": {}}

        if isinstance(mod_like, dict):
            # Case A: explicit dict with uses/id/with
            if "uses" in mod_like or "id" in mod_like or "with" in mod_like:
                uses = mod_like.get("uses")
                if not isinstance(uses, str):
                    # Try single-key merge form inside explicit dict: {id:.., with:.., "pkg.mod": {...}}
                    other_keys = [k for k in mod_like.keys() if k not in {"id", "uses", "with"}]
                    if len(other_keys) == 1 and isinstance(other_keys[0], str):
                        uses = other_keys[0]
                        payload = mod_like[other_keys[0]] or {}
                        if not isinstance(payload, dict):
                            raise TypeError(f"modules[{idx}] shorthand payload must be a dict")
                        w = mod_like.get("with") or {}
                        if not isinstance(w, dict):
                            raise TypeError(f"modules[{idx}].with must be a dict")
                        merged_with = {**payload, **w}
                        mid = mod_like.get("id") or (uses.split(":")[-1].replace("/", ".").split(".")[-1]) or f"mod{idx}"
                        if stage_name:
                            mid = f"{stage_name}_{mid}"
                        return {"id": mid, "uses": uses, "with": merged_with}
                    raise KeyError(f"modules[{idx}] is missing a valid 'uses' string")
                w = mod_like.get("with") or {}
                if not isinstance(w, dict):
                    raise TypeError(f"modules[{idx}].with must be a dict")
                mid = mod_like.get("id") or (uses.split(":")[-1].replace("/", ".").split(".")[-1]) or f"mod{idx}"
                if stage_name:
                    mid = f"{stage_name}_{mid}"
                return {"id": mid, "uses": uses, "with": w}

            # Case B: single-key dict shorthand: {"pkg.mod": {...}}
            if len(mod_like) == 1:
                uses, payload = next(iter(mod_like.items()))
                if not isinstance(uses, str):
                    raise TypeError(f"modules[{idx}] key must be a string")
                if payload is None:
                    payload = {}
                if not isinstance(payload, dict):
                    raise TypeError(f"modules[{idx}] payload must be a dict")
                mod_id = (uses.split(":")[-1].replace("/", ".").split(".")[-1]) or f"mod{idx}"
                if stage_name:
                    mod_id = f"{stage_name}_{mod_id}"
                return {"id": mod_id, "uses": uses, "with": payload}

            raise KeyError(f"modules[{idx}] dict is not in a supported form. Keys: {list(mod_like.keys())}")

        if mod_like is None:
            raise ValueError(f"modules[{idx}] is null/None. Did YAML have an empty '-' item?")

        raise TypeError(f"modules[{idx}] must be str or dict, got {type(mod_like).__name__}")

    if modules is not None:
        if not isinstance(modules, list) or not modules:
            raise ValueError(f"'modules' must be a non-empty list in {p}")
        for i, m in enumerate(modules):
            print(f"[DEBUG] modules[{i}] type={type(m).__name__} value={repr(m)}")
            normalized.append(to_mod(m, i, None))
    else:
        # Handle legacy 'stages' as list of {stage_name: [items...]}
        if not isinstance(stages, list) or not stages:
            raise ValueError(f"'stages' must be a non-empty list in {p}")
        idx = 0
        for block in stages:
            if not isinstance(block, dict) or len(block) != 1:
                raise ValueError(f"Each item in 'stages' must be a single-key dict. Got: {repr(block)}")
            stage_name, items = next(iter(block.items()))
            if items is None:
                items = []
            if not isinstance(items, list):
                raise TypeError(f"Stage '{stage_name}' value must be a list")
            for item in items:
                print(f"[DEBUG] stage='{stage_name}' item type={type(item).__name__} value={repr(item)}")
                normalized.append(to_mod(item, idx, stage_name))
                idx += 1

    data["modules"] = normalized
    print("[DEBUG] pipeline.name =", data["name"])
    print("[DEBUG] modules =", [f"{m['id']}:{m['uses']}" for m in normalized])
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--pipeline", default="web_default", help="Pipeline name (without .yaml)")
    ap.add_argument("--data-dir", default="data/runs")
    args = ap.parse_args()

    # Resolve repo root relative to this file (works no matter your CWD)
    repo_root = Path(__file__).resolve().parents[1]

    # Load pipeline safely
    pipe = load_pipeline(repo_root, args.pipeline)
    modules = pipe["modules"]

    # Prepare run directories
    rid = uuid.uuid4().hex[:12]
    run_base = (repo_root / args.data_dir) / rid
    inputs_dir   = run_base / "inputs"
    workspace_dir= run_base / "workspace"
    artifacts_dir= run_base / "artifacts"
    reports_dir  = run_base / "reports"
    for p in (inputs_dir, workspace_dir, artifacts_dir, reports_dir):
        p.mkdir(parents=True, exist_ok=True)

    # Submit job to in-memory worker
    from apps.worker.worker import submit_job, worker_loop
    job = {
        "run_id": rid,
        "target": args.target,
        "pipeline_name": pipe["name"],
        "modules": modules,
        "workspace_dir": str(workspace_dir),
        "artifacts_dir": str(artifacts_dir),
        "inputs_dir": str(inputs_dir),
        "reports_dir": str(reports_dir),
        "extra": {}
    }

    # 🔧 add these two lines to satisfy RunConfig:
    job["pipeline_id"] = job["pipeline_name"]
    job["workdir"] = job["workspace_dir"]

    submit_job(job)
    worker_loop()  # dev: run immediately and exit when queue empty

    # Aggregate results and write HTML
    results_path = run_base / "results.json"
    if not results_path.exists():
        print(f"❌ results.json not found at {results_path}. Check worker logs.", file=sys.stderr)
        sys.exit(2)

    findings = merge_results(results_path)
    tpl_dir = repo_root / "core" / "reporting" / "templates"
    out_html = reports_dir / "report.html"
    write_html(findings, tpl_dir, out_html)
    print(f"\n✅ Run {rid} complete.")
    print(f"• Results JSON: {results_path}")
    print(f"• HTML report : {out_html}")

if __name__ == "__main__":
    main()
