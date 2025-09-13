#!/usr/bin/env python3
# scripts/local_run.py
import argparse
import json
import os
import sys
import time
from pathlib import Path
from core.pipeline.contracts import RunConfig

# ---- Imports from your codebase
try:
    from core.pipeline.engine import run_pipeline
    from core.pipeline.contracts import RunConfig
except Exception as e:
    print("❌ Could not import engine/RunConfig. Check PYTHONPATH.", file=sys.stderr)
    raise

try:
    from core.reporting.aggregate import merge_results  # <- replace with the OAST-aware version you added
except Exception as e:
    print("❌ Could not import core.reporting.aggregate.merge_results", file=sys.stderr)
    raise

# HTML writer (prefer core/, else fallback to top-level reporting/)
from core.reporting.writers.html_writer import write_html

def _load_pipeline_yaml(pipeline_name: str, repo_root: Path) -> dict:
    """
    Load a pipeline YAML by name:
      - tries pipelines/<name>.yaml, then <name>.yml
      - if file not found, error out with a helpful message
    """
    import yaml  # requires PyYAML
    candidates = [
        repo_root / "pipelines" / f"{pipeline_name}.yaml",
        repo_root / "pipelines" / f"{pipeline_name}.yml",
    ]
    for p in candidates:
        if p.exists():
            return yaml.safe_load(p.read_text())
    print(f"❌ Pipeline file not found for '{pipeline_name}'. "
          f"Tried: {', '.join(str(p) for p in candidates)}", file=sys.stderr)
    sys.exit(2)


def _normalize_modules_and_extra(pcfg: dict) -> tuple[list[str], dict]:
    """
    Returns (modules, extra) for RunConfig:
      - modules: ordered list of module IDs (strings)
      - extra: dict keyed by module id -> module config (flatten 'with'/'args' if present)
    Supports both {stages:[{module: id}]} and {modules:[id1,id2,...]} styles.
    """
    modules: list[str] = []
    extra: dict = {}

    if "modules" in pcfg and isinstance(pcfg["modules"], list):
        # New style: modules: ["oast.interactsh", "web.zap", ...]
        modules = [m for m in pcfg["modules"] if isinstance(m, str)]
    elif "stages" in pcfg and isinstance(pcfg["stages"], list):
        # Legacy style: stages: - { id: x, module: web.zap, inputs: {...} }
        for st in pcfg["stages"]:
            mid = st.get("module")
            if mid:
                modules.append(mid)
                if "inputs" in st and isinstance(st["inputs"], dict):
                    extra[mid] = st["inputs"]

    # Flatten 'extra' section keyed by module id
    # Your YAML uses:
    # extra:
    #   web.zap:
    #     with: {...}
    #   web.nuclei.basic:
    #     args: "..."
    if isinstance(pcfg.get("extra"), dict):
        for mid, conf in pcfg["extra"].items():
            if not isinstance(conf, dict):
                extra[mid] = conf
                continue
            if "with" in conf:
                extra[mid] = conf.get("with") or {}
            elif "args" in conf:
                # Keep args under 'args' key so the plugin can read it
                extra[mid] = {"args": conf["args"]}
            else:
                extra[mid] = conf

    # Make sure every module has a config dict
    for mid in modules:
        extra.setdefault(mid, {})

    return modules, extra


def _serialize_pipeline_result(res) -> str:
    """
    Convert PipelineResult (pydantic/dataclass/dict) to JSON string safely.
    """
    # pydantic v2
    if hasattr(res, "model_dump_json"):
        return res.model_dump_json()
    # pydantic v1
    if hasattr(res, "json"):
        return res.json()
    # dataclass or generic object with dict-like fields
    try:
        return json.dumps(res, default=lambda o: getattr(o, "__dict__", str(o)))
    except Exception:
        # assume it's already a dict-like
        return json.dumps(res)


def main():
    ap = argparse.ArgumentParser(description="Run a VAPT pipeline locally and render report.html")
    ap.add_argument("--target", required=True, help="Target URL (e.g., http://testphp.vulnweb.com/)")
    ap.add_argument("--pipeline", required=True, help="Pipeline name (e.g., web_active_plus_oast or web_default)")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]  # project root
    pipelines_dir = repo_root / "pipelines"
    import sys
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    # ✅ import the right engine module explicitly
    from core.pipeline import engine as pl_engine
    # Load pipeline YAML
    pcfg = _load_pipeline_yaml(args.pipeline, repo_root)
    pipeline_name = pcfg.get("id") or args.pipeline

    # Normalize modules + extra configs
    modules, extra = _normalize_modules_and_extra(pcfg)
    if not modules:
        print("❌ No modules found in pipeline YAML.", file=sys.stderr)
        sys.exit(2)

    # Prepare run directories
    rid = f"{int(time.time())}"
    runs_dir = repo_root / "data" / "runs"
    run_base = runs_dir / rid
    workspace_dir = run_base / "workspace"
    artifacts_dir = run_base / "artifacts"
    reports_dir = workspace_dir / "reports"
    for d in (workspace_dir, artifacts_dir, reports_dir):
        d.mkdir(parents=True, exist_ok=True)

    print(f"▶️  Running pipeline '{pipeline_name}' on target: {args.target}")
    print(f"    Run ID: {rid}")
    print(f"    Modules: {modules}")
    import inspect, os
    print("[DEBUG] run_pipeline from:", pl_engine.run_pipeline.__module__)
    print("[DEBUG] file:", os.path.abspath(pl_engine.run_pipeline.__code__.co_filename))
    print("[DEBUG] signature:", inspect.signature(pl_engine.run_pipeline))

    # Execute pipeline locally via engine
    run_cfg = RunConfig(
    run_id=rid,
    pipeline_id=pipeline_name,
    pipeline_name=pipeline_name,
    workdir=str(workspace_dir),                 # required by your engine
    workspace_dir=str(workspace_dir),
    artifacts_dir=str(artifacts_dir),

    # ✅ add these two so _get() won’t return None
    inputs_dir=str(run_base / "inputs"),
    reports_dir=str(run_base / "reports"),

    target=args.target,
    modules=modules,
    extra=extra,
)



    # if your engine signature is run_pipeline(cfg, modules):
    from core.pipeline import engine as pl_engine
    result = pl_engine.run_pipeline(run_cfg, modules)
    # Persist raw results.json for debugging / later consumption
    results_path = run_base / "results.json"
    results_path.write_text(_serialize_pipeline_result(result))

    # Merge → enrich (OAST) → dedupe
    try:
        findings = merge_results(results_path, workdir=workspace_dir)
    except TypeError:
        # Backward-compat: some merge_results accept only (path)
        findings = merge_results(results_path)

    findings_path = workspace_dir / "findings.json"
    findings_path.write_text(json.dumps(findings, ensure_ascii=False, indent=2))

    # Pick a template dir (core first, then fallback)
    tpl_core = repo_root / "core" / "reporting" / "templates"
    tpl_top = repo_root / "reporting" / "templates"
    template_dir = tpl_core if tpl_core.exists() else tpl_top

    # Render final HTML report
    out_html = reports_dir / "report.html"
    write_html(findings, template_dir=template_dir, out_path=out_html, context={
        "title": "VAPT Attack Report",
        "run_id": rid,
        "pipeline": pipeline_name,
        "target": args.target,
    })

    print("\n✅ Done.")
    print(f"   results.json:   {results_path}")
    print(f"   findings.json:  {findings_path}")
    print(f"   report.html:    {out_html}")
    print(f"   workspace:      {workspace_dir}")


if __name__ == "__main__":
    main()
