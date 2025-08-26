#!/usr/bin/env python3
# core/plugins/web/zap/main.py
import json, sys, os, shutil, subprocess, time
from pathlib import Path
from typing import List, Dict, Optional

SEV_ORDER = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3}

def _sev_map(v: str) -> str:
    v = (v or "").lower()
    return {"informational": "info", "info": "info", "low": "low", "medium": "medium", "high": "high"}.get(v, "info")

def _ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)
def _to_list(v) -> List[str]: return [] if v is None else (v if isinstance(v, list) else [v])

def _filter_by_threshold(findings: List[Dict], threshold: Optional[str]) -> List[Dict]:
    if not threshold: return findings
    thr = SEV_ORDER.get(threshold.lower(), 0)
    return [f for f in findings if SEV_ORDER.get((f.get("severity") or "").lower(), 0) >= thr]

def _zap_script(which: str) -> Optional[str]:
    # local wrappers if present
    if which == "full":
        p = shutil.which("zap-full-scan.py") or ("/usr/local/bin/zap-full-scan.py" if Path("/usr/local/bin/zap-full-scan.py").exists() else None)
    else:
        p = shutil.which("zap-baseline.py") or ("/usr/local/bin/zap-baseline.py" if Path("/usr/local/bin/zap-baseline.py").exists() else None)
    return p

def parse_zap_json(path: Path) -> List[Dict]:
    findings: List[Dict] = []
    if not path.exists(): return findings
    try:
        data = json.loads(path.read_text() or "{}")
        sites = data.get("site", [])
        if isinstance(sites, list) and sites:
            for site in sites:
                base = site.get("@name")
                for a in site.get("alerts", []):
                    title = a.get("name", "ZAP alert")
                    risk = _sev_map((a.get("riskdesc") or "").split(" ")[0])
                    insts = a.get("instances") or [{}]
                    if not insts: insts = [{}]
                    for inst in insts:
                        url = (inst.get("uri") if isinstance(inst, dict) else None) or base
                        fid = str(a.get("pluginid", "zap"))
                        cweid = a.get("cweid")
                        cwe = [f"CWE-{cweid}"] if cweid not in (None, "-1") else None
                        findings.append({
                            "id": fid, "title": title, "description": a.get("desc", ""),
                            "severity": risk, "location": url, "tool": "zap",
                            "rule_id": fid, "cwe": cwe, "tags": a.get("tags") or [],
                            "evidence": {
                                "param": (inst.get("param") if isinstance(inst, dict) else None),
                                "evidence": (inst.get("evidence") if isinstance(inst, dict) else None),
                                "attack": (inst.get("attack") if isinstance(inst, dict) else None),
                            },
                        })
            return findings
        for a in data.get("alerts", []) or []:
            title = a.get("alert", "ZAP alert")
            risk = _sev_map(a.get("risk", "info"))
            url = a.get("url") or a.get("uri")
            fid = str(a.get("pluginId") or a.get("id") or "zap")
            cweid = a.get("cweid") or a.get("cweId")
            cwe = [f"CWE-{cweid}"] if cweid not in (None, "-1") else None
            findings.append({
                "id": fid, "title": title, "description": a.get("desc", ""),
                "severity": risk, "location": url, "tool": "zap",
                "rule_id": fid, "cwe": cwe, "tags": a.get("tags") or [],
                "evidence": {"param": a.get("param"), "evidence": a.get("evidence"), "attack": a.get("attack")},
            })
    except Exception:
        pass
    return findings

def _dbg(log_path: Path, msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    _ensure_dir(log_path.parent)
    with log_path.open("a", encoding="utf-8") as f: f.write(f"[{ts}] {msg}\n")

def _build_cmd(which: str, artifacts_dir: Path, target: str, html_name: str, json_name: str,
               extra_args: List[str], log_path: Path):
    local = _zap_script(which)
    docker_image = os.environ.get("ZAP_DOCKER_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
    extra_docker = os.environ.get("ZAP_DOCKER_EXTRA_ARGS", "")
    extra_docker = extra_docker.split() if extra_docker.strip() else []
    if local:
        cmd = [local, "-t", target, "-r", html_name, "-J", json_name] + list(extra_args or [])
        _dbg(log_path, f"Using LOCAL wrapper: {local}")
        _dbg(log_path, f"Workdir (cwd): {artifacts_dir}")
        return cmd, str(artifacts_dir), {"mode":"local", "image": None}
    # Docker fallback
    cmd = ["docker","run","--rm","-u","zap", *extra_docker,
           "-v", f"{artifacts_dir.resolve()}:/zap/wrk", "-t", docker_image,
           ("zap-full-scan.py" if which=="full" else "zap-baseline.py"),
           "-t", target, "-r", html_name, "-J", json_name] + list(extra_args or [])
    _dbg(log_path, f"Using DOCKER image: {docker_image}")
    if extra_docker: _dbg(log_path, f"Docker extra args: {' '.join(extra_docker)}")
    _dbg(log_path, f"Mount: {artifacts_dir.resolve()} -> /zap/wrk")
    return cmd, str(artifacts_dir), {"mode":"docker", "image": docker_image}

def main():
    try:
        m_input = json.loads(sys.stdin.read() or "{}")
    except Exception:
        m_input = {}

    target = (m_input.get("target")
              or ((m_input.get("inputs") or {}).get("target_url"))
              or ((m_input.get("inputs") or {}).get("target")))
    if not target:
        print(json.dumps({"status":"error","error":"target (or inputs.target_url) is required"})); return

    workdir = Path(m_input.get("workdir") or "data/runs/dev-zap/workspace")
    artifacts_dir = Path(m_input.get("artifacts_dir") or (workdir.parent / "artifacts"))
    _ensure_dir(artifacts_dir)
    tool_dir = workdir / "zap"; _ensure_dir(tool_dir)

    log_path = artifacts_dir / "zap-debug.log"
    _dbg(log_path, "=== ZAP module start ===")
    _dbg(log_path, f"Target: {target}")
    _dbg(log_path, f"Workdir: {workdir}")
    _dbg(log_path, f"Artifacts: {artifacts_dir}")

    inputs = m_input.get("inputs") or {}
    which = "full" if (inputs.get("mode") or "baseline").lower() == "full" else "baseline"
    ajax_spider = bool(inputs.get("ajax_spider") or False)
    policy = inputs.get("policy")
    max_duration_min = inputs.get("max_duration_min")
    risk_threshold = inputs.get("risk_threshold")
    include_patterns = _to_list(inputs.get("include_patterns"))
    exclude_patterns = _to_list(inputs.get("exclude_patterns"))
    extra_zap = inputs.get("extra_zap") or [] 
    for inc in include_patterns:
        if inc: extra += ["-z", f"spider.include={inc}"]
    for exc in exclude_patterns:
        if exc: extra += ["-z", f"spider.exclude={exc}"]
    for opt in extra_zap:                        # NEW
        if isinstance(opt, str) and opt.strip():
            extra += ["-z", opt.strip()]

    debug_flag = bool(inputs.get("debug") or (os.getenv("DEBUG_ZAP") == "1"))

    _dbg(log_path, f"Mode: {which}, ajax_spider={ajax_spider}, policy={policy}, "
                   f"max_duration_min={max_duration_min}, risk_threshold={risk_threshold}, debug={debug_flag}")
    if include_patterns: _dbg(log_path, f"Include patterns: {include_patterns}")
    if exclude_patterns: _dbg(log_path, f"Exclude patterns: {exclude_patterns}")

    html_name = "zap-full.html" if which=="full" else "zap-baseline.html"
    json_name = "zap-full.json" if which=="full" else "zap-baseline.json"
    html_path = artifacts_dir / html_name
    json_path = artifacts_dir / json_name

    extra: List[str] = []
    if isinstance(max_duration_min, int) and max_duration_min > 0:
        extra += ["-m", str(max_duration_min)]
    if which == "full" and ajax_spider:
        extra += ["-j"]
    if which == "full" and isinstance(policy, str) and policy.strip():
        extra += ["-P", policy.strip()]
    for inc in include_patterns:
        if inc: extra += ["-z", f"spider.include={inc}"]
    for exc in exclude_patterns:
        if exc: extra += ["-z", f"spider.exclude={exc}"]
    if debug_flag:
        extra += ["-d"]  # wrapper debug

    cmd, cwd, exec_meta = _build_cmd(which, artifacts_dir, target, html_name, json_name, extra, log_path)
    _dbg(log_path, f"Command: {' '.join(cmd)}")
    start_ts = time.time()

    # Compute a hard timeout for the wrapper
    timeout_sec = None
    if isinstance(max_duration_min, int) and max_duration_min > 0:
        timeout_sec = max(120, (max_duration_min + 3) * 60)  # +3 min buffer
    else:
        timeout_sec = 20 * 60  # 20 min safety

    # Run with live log streaming
    combined_tail: List[str] = []
    tail_limit = 4000  # chars
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        _dbg(log_path, "Process started.")
        last_heartbeat = time.time()
        while True:
            if proc.stdout is None: break
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.2)
            else:
                _dbg(log_path, line.rstrip())
                combined_tail.append(line)
                # keep tail bounded by chars
                joined = "".join(combined_tail)
                if len(joined) > tail_limit:
                    # drop from front
                    excess = len(joined) - tail_limit
                    # simple trim
                    joined = joined[excess:]
                    combined_tail = [joined]

            # heartbeat every 15s
            now = time.time()
            if now - last_heartbeat > 15:
                _dbg(log_path, f"[heartbeat] running for {int(now - start_ts)}s...")
                last_heartbeat = now

            # check timeout
            if (now - start_ts) > timeout_sec:
                _dbg(log_path, f"[timeout] Exceeded {timeout_sec}s; terminating process.")
                proc.kill()
                break

        return_code = proc.wait()
        duration = int(time.time() - start_ts)
        _dbg(log_path, f"Process finished with code {return_code} in {duration}s.")

        # Parse findings
        if json_path.exists():
            _dbg(log_path, f"Found JSON report: {json_path} ({json_path.stat().st_size} bytes)")
        else:
            _dbg(log_path, f"[warn] JSON report not found at {json_path}")

        findings = parse_zap_json(json_path)
        if risk_threshold: findings = _filter_by_threshold(findings, risk_threshold)

        # Persist per-tool normalized file
        try:
            (tool_dir / "findings.json").write_text(json.dumps({"findings": findings}, ensure_ascii=False, indent=2), encoding="utf-8")
            _dbg(log_path, f"Wrote normalized findings: {tool_dir / 'findings.json'} ({len(findings)} items)")
        except Exception as e:
            _dbg(log_path, f"[warn] write findings.json failed: {e}")

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
