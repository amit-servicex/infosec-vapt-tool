#!/usr/bin/env python3
# core/plugins/web/zap/main.py
import json
import sys
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# ------------------------------
# Severity helpers
# ------------------------------
SEV_ORDER = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3}

def _sev_map(v: str) -> str:
    v = (v or "").lower()
    return {
        "informational": "info",
        "info": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
    }.get(v, "info")

# ------------------------------
# Filesystem & logging
# ------------------------------
def _ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def _dbg(log_path: Path, msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    _ensure_dir(log_path.parent)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")

# ------------------------------
# Config loading (YAML or JSON)
# ------------------------------
def _load_config_file(path: Optional[str], log_path: Optional[Path]) -> Dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        if log_path: _dbg(log_path, f"[config] file not found: {p}")
        return {}
    txt = p.read_text(encoding="utf-8")
    # Try YAML first if available or file extension looks like YAML, else JSON fallback
    data = {}
    tried_yaml = False
    if p.suffix.lower() in (".yml", ".yaml"):
        tried_yaml = True
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(txt) or {}
            if log_path: _dbg(log_path, f"[config] loaded YAML: {p}")
            return data
        except Exception as e:
            if log_path: _dbg(log_path, f"[config] YAML parse failed ({e}); trying JSON")
    try:
        data = json.loads(txt) or {}
        if log_path: _dbg(log_path, f"[config] loaded JSON: {p}")
        return data
    except Exception as e:
        if log_path:
            fmt = "YAML" if tried_yaml else "JSON"
            _dbg(log_path, f"[config] {fmt} parse failed: {e}; returning empty config")
        return {}

def _load_lines_file(path: Optional[str], log_path: Optional[Path]) -> List[str]:
    """
    Read a file with one option per line (comments with # and blanks ignored).
    Useful for extra ZAP -z options.
    """
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        if log_path: _dbg(log_path, f"[config] extra_zap_file not found: {p}")
        return []
    opts: List[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        opts.append(s)
    if log_path: _dbg(log_path, f"[config] loaded {len(opts)} extra_zap options from {p}")
    return opts

# ------------------------------
# Parse ZAP JSON -> normalized findings
# ------------------------------
def parse_zap_json(path: Path) -> List[Dict]:
    findings: List[Dict] = []
    if not path.exists():
        return findings
    try:
        data = json.loads(path.read_text() or "{}")

        # Format A: {"site":[{"@name": "...", "alerts":[{...,"instances":[{...}]}]}]}
        sites = data.get("site", [])
        if isinstance(sites, list) and sites:
            for site in sites:
                base = site.get("@name")
                for a in site.get("alerts", []):
                    title = a.get("name", "ZAP alert")
                    risk = _sev_map((a.get("riskdesc") or "").split(" ")[0])
                    insts = a.get("instances") or [{}]
                    if not insts:
                        insts = [{}]
                    for inst in insts:
                        url = (inst.get("uri") if isinstance(inst, dict) else None) or base
                        fid = str(a.get("pluginid", "zap"))
                        cweid = a.get("cweid")
                        cwe = [f"CWE-{cweid}"] if cweid not in (None, "-1") else None
                        findings.append({
                            "id": fid,
                            "title": title,
                            "description": a.get("desc", ""),
                            "severity": risk,
                            "location": url,
                            "tool": "zap",
                            "rule_id": fid,
                            "cwe": cwe,
                            "tags": a.get("tags") or [],
                            "evidence": {
                                "param": (inst.get("param") if isinstance(inst, dict) else None),
                                "evidence": (inst.get("evidence") if isinstance(inst, dict) else None),
                                "attack": (inst.get("attack") if isinstance(inst, dict) else None),
                            },
                        })
            return findings

        # Format B: {"alerts":[{...}]}
        for a in data.get("alerts", []) or []:
            title = a.get("alert", "ZAP alert")
            risk = _sev_map(a.get("risk", "info"))
            url = a.get("url") or a.get("uri")
            fid = str(a.get("pluginId") or a.get("id") or "zap")
            cweid = a.get("cweid") or a.get("cweId")
            cwe = [f"CWE-{cweid}"] if cweid not in (None, "-1") else None
            findings.append({
                "id": fid,
                "title": title,
                "description": a.get("desc", ""),
                "severity": risk,
                "location": url,
                "tool": "zap",
                "rule_id": fid,
                "cwe": cwe,
                "tags": a.get("tags") or [],
                "evidence": {
                    "param": a.get("param"),
                    "evidence": a.get("evidence"),
                    "attack": a.get("attack"),
                },
            })
    except Exception:
        # tolerate parse issues; return whatever we built
        pass
    return findings

def _filter_by_threshold(findings: List[Dict], threshold: Optional[str]) -> List[Dict]:
    if not threshold:
        return findings
    thr = SEV_ORDER.get(threshold.lower(), 0)
    return [f for f in findings if SEV_ORDER.get((f.get("severity") or "").lower(), 0) >= thr]

# ------------------------------
# Wrapper selection & command build
# ------------------------------
def _zap_script(which: str) -> Optional[str]:
    """Return local wrapper path if present."""
    if which == "full":
        p = shutil.which("zap-full-scan.py")
        if p: return p
        p2 = "/usr/local/bin/zap-full-scan.py"
        return p2 if Path(p2).exists() else None
    else:
        p = shutil.which("zap-baseline.py")
        if p: return p
        p2 = "/usr/local/bin/zap-baseline.py"
        return p2 if Path(p2).exists() else None

def _build_cmd(
    which: str,
    artifacts_dir: Path,
    target: str,
    html_name: str,
    json_name: str,
    extra_args: List[str],
    docker_image: str,
    docker_extra_args: List[str],
    log_path: Path
) -> Tuple[List[str], str, Dict]:
    """Return (cmd, cwd, exec_meta). Prefer local wrapper; else Docker."""
    local = _zap_script(which)
    if local:
        cmd = [local, "-t", target, "-r", html_name, "-J", json_name] + list(extra_args or [])
        _dbg(log_path, f"Using LOCAL wrapper: {local}")
        _dbg(log_path, f"Workdir (cwd): {artifacts_dir}")
        return cmd, str(artifacts_dir), {"mode": "local", "image": None}
    # Docker fallback (GHCR default)
    cmd = [
        "docker", "run", "--rm", "-u", "zap",
        *docker_extra_args,
        "-v", f"{artifacts_dir.resolve()}:/zap/wrk",
        "-t", docker_image,
        ("zap-full-scan.py" if which == "full" else "zap-baseline.py"),
        "-t", target, "-r", html_name, "-J", json_name
    ] + list(extra_args or [])
    _dbg(log_path, f"Using DOCKER image: {docker_image}")
    if docker_extra_args:
        _dbg(log_path, f"Docker extra args: {' '.join(docker_extra_args)}")
    _dbg(log_path, f"Mount: {artifacts_dir.resolve()} -> /zap/wrk")
    return cmd, str(artifacts_dir), {"mode": "docker", "image": docker_image}

import sys, json

def _merge_target_into_inputs(inputs: dict, target: str | None) -> dict:
    inputs = dict(inputs or {})
    if target and "target_url" not in inputs:
        inputs["target_url"] = target
    return inputs

def _adapt_engine_input(m: dict) -> dict:
    # If already in plugin shape (manual runs), return as-is
    if "inputs" in m or "workdir" in m:
        return m
    # Adapt engine ModuleInput -> plugin's expected shape
    return {
        "run_id": m.get("run_id"),
        "workdir": m.get("workspace_dir"),
        "artifacts_dir": m.get("artifacts_dir"),
        "inputs": _merge_target_into_inputs(m.get("config") or {}, m.get("target")),
        "previous_outputs": m.get("previous_outputs") or {},
    }

# ------------------------------
# Main
# ------------------------------
def main():
    # Read stdin
    try:
        raw = json.loads(sys.stdin.read() or "{}")
        m_input = _adapt_engine_input(raw)
        #m_input = json.loads(sys.stdin.read() or "{}")
    except Exception:
        m_input = {}

    # Base paths
    workdir = Path(m_input.get("workdir") or "data/runs/dev-zap/workspace")
    artifacts_dir = Path(m_input.get("artifacts_dir") or (workdir.parent / "artifacts"))
    _ensure_dir(artifacts_dir)
    tool_dir = workdir / "zap"
    _ensure_dir(tool_dir)
    log_path = artifacts_dir / "zap-debug.log"

    # Load config file (if provided)
    inputs = m_input.get("inputs") or {}
    config_file = inputs.get("config_file")
    cfg = _load_config_file(config_file, log_path) if config_file else {}

    # Merge config (defaults <- file <- inputs)
    def g(key, default=None):
        if key in inputs and inputs.get(key) is not None:
            return inputs.get(key)
        if isinstance(cfg, dict) and key in cfg and cfg.get(key) is not None:
            return cfg.get(key)
        return default

    # Target
    target = (
        m_input.get("target")
        or g("target_url")
        or g("target")
    )
    if not target:
        print(json.dumps({"status": "error", "error": "target (or inputs.target_url) is required"}))
        return

    # Basic knobs
    mode = (g("mode", "baseline") or "baseline").lower()  # "baseline" | "full"
    ajax_spider = bool(g("ajax_spider", False))
    policy = g("policy", None)
    max_duration_min = g("max_duration_min", None)
    risk_threshold = g("risk_threshold", None)
    include_patterns = g("include_patterns", []) or []
    exclude_patterns = g("exclude_patterns", []) or []
    debug_flag = bool(g("debug", False) or (os.getenv("DEBUG_ZAP") == "1"))

    # Extra ZAP options: from file + inline list
    extra_zap_file = g("extra_zap_file", None)
    extra_zap_from_file = _load_lines_file(extra_zap_file, log_path)
    extra_zap_inline = g("extra_zap", []) or []
    if isinstance(extra_zap_inline, str):
        extra_zap_inline = [extra_zap_inline]
    extra_zap: List[str] = [*extra_zap_from_file, *extra_zap_inline]

    # Docker image/args (env overrides file)
    docker_image = os.environ.get("ZAP_DOCKER_IMAGE") or g("docker_image", "ghcr.io/zaproxy/zaproxy:stable")
    docker_extra_args_env = os.environ.get("ZAP_DOCKER_EXTRA_ARGS", "")
    docker_extra_args = docker_extra_args_env.split() if docker_extra_args_env.strip() else (g("docker_extra_args", []) or [])
    if isinstance(docker_extra_args, str):
        docker_extra_args = docker_extra_args.split()

    # Announce
    _dbg(log_path, "=== ZAP module start ===")
    _dbg(log_path, f"Target: {target}")
    _dbg(log_path, f"Workdir: {workdir}")
    _dbg(log_path, f"Artifacts: {artifacts_dir}")
    _dbg(log_path, f"Mode: {mode}, ajax_spider={ajax_spider}, policy={policy}, "
                   f"max_duration_min={max_duration_min}, risk_threshold={risk_threshold}, debug={debug_flag}")
    if include_patterns: _dbg(log_path, f"Include patterns: {include_patterns}")
    if exclude_patterns: _dbg(log_path, f"Exclude patterns: {exclude_patterns}")
    if extra_zap: _dbg(log_path, f"extra_zap ({len(extra_zap)}): {extra_zap}")
    _dbg(log_path, f"Docker image: {docker_image}")
    if docker_extra_args: _dbg(log_path, f"Docker extra args: {docker_extra_args}")

    # Output names
    which = "full" if mode == "full" else "baseline"
    html_name = "zap-full.html" if which == "full" else "zap-baseline.html"
    json_name = "zap-full.json" if which == "full" else "zap-baseline.json"
    html_path = artifacts_dir / html_name
    json_path = artifacts_dir / json_name

    # ---- Build wrapper args safely ----
    extra: List[str] = []

    # time budget
    if isinstance(max_duration_min, int) and max_duration_min > 0:
        extra += ["-m", str(max_duration_min)]

    # ajax spider (full only)
    if which == "full" and ajax_spider:
        extra += ["-j"]

    # policy (full only)
    if which == "full" and isinstance(policy, str) and policy.strip():
        extra += ["-P", policy.strip()]

    # include/exclude via -z
    for inc in include_patterns or []:
        if inc:
            extra += ["-z", f"spider.include={inc}"]
    for exc in exclude_patterns or []:
        if exc:
            extra += ["-z", f"spider.exclude={exc}"]

    # extra -z configs (from file and inline)
    for opt in extra_zap:
        if isinstance(opt, str) and opt.strip():
            extra += ["-z", opt.strip()]

    # wrapper debug flag
    if debug_flag:
        extra += ["-d"]

    # Build command
    cmd, cwd, exec_meta = _build_cmd(
        which, artifacts_dir, target, html_name, json_name, extra,
        docker_image, docker_extra_args, log_path
    )
    _dbg(log_path, f"Command: {' '.join(cmd)}")

    # Watchdog timeout (derived from max_duration_min)
    if isinstance(max_duration_min, int) and max_duration_min > 0:
        timeout_sec = max(120, (max_duration_min + 3) * 60)  # +3 min buffer
    else:
        timeout_sec = 20 * 60  # default 20 min

    # Execute with live log streaming
    start_ts = time.time()
    combined_tail: List[str] = []
    tail_limit = 4000
    try:
        proc = subprocess.Popen(
            cmd, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        _dbg(log_path, "Process started.")
        last_heartbeat = time.time()
        while True:
            if proc.stdout is None:
                break
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.2)
            else:
                _dbg(log_path, line.rstrip())
                combined_tail.append(line)
                # bound the tail by chars
                joined = "".join(combined_tail)
                if len(joined) > tail_limit:
                    excess = len(joined) - tail_limit
                    joined = joined[excess:]
                    combined_tail = [joined]

            # heartbeat + timeout
            now = time.time()
            if now - last_heartbeat > 15:
                _dbg(log_path, f"[heartbeat] running for {int(now - start_ts)}s...")
                last_heartbeat = now
            if (now - start_ts) > timeout_sec:
                _dbg(log_path, f"[timeout] Exceeded {timeout_sec}s; terminating process.")
                proc.kill()
                break

        return_code = proc.wait()
        duration = int(time.time() - start_ts)
        _dbg(log_path, f"Process finished with code {return_code} in {duration}s.")

        # Parse findings (only if JSON exists)
        if json_path.exists():
            _dbg(log_path, f"Found JSON report: {json_path} ({json_path.stat().st_size} bytes)")
        else:
            _dbg(log_path, f"[warn] JSON report not found at {json_path}")

        findings = parse_zap_json(json_path)
        if risk_threshold:
            findings = _filter_by_threshold(findings, risk_threshold)

        # Persist per-tool normalized findings for aggregator
        try:
            (tool_dir / "findings.json").write_text(
                json.dumps({"findings": findings}, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            _dbg(log_path, f"Wrote normalized findings: {tool_dir / 'findings.json'} ({len(findings)} items)")
        except Exception as e:
            _dbg(log_path, f"[warn] write findings.json failed: {e}")

        # Build output
        status = "ok" if return_code == 0 else "error"
        stdout_tail = "".join(combined_tail)[-tail_limit:]
        print(json.dumps({
            "status": status,
            "findings": findings,
            "artifacts": [
                {"path": str(html_path), "type": "html", "description": f"ZAP {'Full' if which=='full' else 'Baseline'} HTML"},
                {"path": str(json_path), "type": "json", "description": f"ZAP {'Full' if which=='full' else 'Baseline'} JSON"},
                {"path": str(log_path), "type": "txt", "description": "ZAP debug log"}
            ],
            "stdout": stdout_tail,
            "stderr": "",
            "stats": {
                "mode": which,
                "normalized_findings": len(findings),
                "duration_sec": duration,
                "exec": exec_meta
            }
        }))
    except Exception as e:
        _dbg(log_path, f"[fatal] Exception: {e}")
        print(json.dumps({
            "status": "error",
            "error": f"zap exception: {e}",
            "findings": [],
            "artifacts": [{"path": str(log_path), "type": "txt", "description": "ZAP debug log"}],
        }))

if __name__ == "__main__":
    main()
