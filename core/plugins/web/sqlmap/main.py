#!/usr/bin/env python3
# core/plugins/web/sqlmap/main.py
import json, sys, os, re, time, shutil, subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# --------- utils ----------
def _ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)
def _slug(s: str) -> str: return re.sub(r"[^a-zA-Z0-9._-]+","_", (s or ""))[:120] or "target"

def _append(log: Path, msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    _ensure_dir(log.parent)
    with log.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")

def _to_text(x) -> str:
    if x is None: return ""
    if isinstance(x, bytes):
        try: return x.decode("utf-8", "ignore")
        except Exception: return x.decode(errors="ignore")
    return str(x)

def _load_cfg(path: Optional[str], log: Path) -> Dict:
    if not path: return {}
    p = Path(path)
    if not p.exists():
        _append(log, f"[config] not found: {p}"); return {}
    txt = p.read_text(encoding="utf-8")
    # try yaml then json
    if p.suffix.lower() in (".yml",".yaml"):
        try:
            import yaml  # pip install pyyaml
            d = yaml.safe_load(txt) or {}
            _append(log, f"[config] loaded YAML: {p}")
            return d
        except Exception as e:
            _append(log, f"[config] YAML parse failed: {e}; trying JSON")
    try:
        d = json.loads(txt) or {}
        _append(log, f"[config] loaded JSON: {p}")
        return d
    except Exception as e:
        _append(log, f"[config] parse failed: {e}")
        return {}

def _merge(inputs: Dict, cfg: Dict, key: str, default=None):
    return inputs.get(key) if inputs.get(key) is not None else (cfg.get(key) if cfg.get(key) is not None else default)

# --------- candidates ----------
def _load_findings(path: Path, log: Path) -> List[Dict]:
    if not path.exists(): return []
    try:
        data = json.loads(path.read_text() or "{}")
        items = data.get("findings") or []
        _append(log, f"[candidates] loaded {len(items)} from {path}")
        return items
    except Exception as e:
        _append(log, f"[candidates] parse error {path}: {e}")
        return []

def _looks_sqlish(f: Dict) -> bool:
    title = (f.get("title") or "").lower()
    tags = " ".join(f.get("tags") or []).lower()
    rule = (f.get("rule_id") or "").lower()
    cwe  = " ".join(f.get("cwe") or []).lower()
    return ("sql" in title and "injection" in title) or ("sqli" in title or "sqli" in tags or "sqli" in rule) or ("cwe-89" in cwe)

def _extract_candidates(items: List[Dict], host_rx: Optional[re.Pattern], log: Path) -> List[Dict]:
    out = []
    for f in items:
        if not _looks_sqlish(f): continue
        url = f.get("location") or f.get("url")
        if not url: continue
        if host_rx and not host_rx.search(url): continue
        ev = f.get("evidence") or {}
        param = ev.get("param") or ev.get("parameter")
        method = f.get("method")
        data = ev.get("data") or f.get("data")
        headers = ev.get("headers") or f.get("headers")
        cookies = ev.get("cookies") or f.get("cookie") or f.get("cookies")
        out.append({"url": url, "param": param, "method": method, "data": data, "headers": headers, "cookies": cookies})
    # dedupe
    seen=set(); uniq=[]
    for c in out:
        k=(c["url"], c.get("param") or "", c.get("method") or "")
        if k in seen: continue
        seen.add(k); uniq.append(c)
    _append(log, f"[candidates] extracted {len(uniq)} sql-ish")
    return uniq

# --------- sqlmap exec ----------
PROFILES = {
    "quick":    {"risk":1, "level":2, "tech":"BEU",    "time_sec":2, "threads":1, "verbosity":"2"},
    "standard": {"risk":1, "level":3, "tech":"BEUSTQ", "time_sec":3, "threads":2, "verbosity":"2"},
    "deep":     {"risk":2, "level":5, "tech":"BEUSTQ", "time_sec":4, "threads":2, "verbosity":"3"},
}

def _sqlmap_local() -> Optional[str]:
    return shutil.which("sqlmap") or shutil.which("sqlmap.py")

def _build_cmd_local(args: List[str]) -> List[str]:
    sm = shutil.which("sqlmap") or shutil.which("sqlmap.py")
    if not sm: return []
    if sm.endswith("sqlmap.py"):
        return [sys.executable, sm] + args
    return [sm] + args

def _build_cmd_docker(args: List[str], artifacts_dir: Path, image: str, extra: List[str]) -> List[str]:
    env_passthru = []
    for k in ("HTTP_PROXY","HTTPS_PROXY","NO_PROXY","http_proxy","https_proxy","no_proxy"):
        if os.environ.get(k): env_passthru += ["-e", f"{k}={os.environ[k]}"]
    return ["docker","run","--rm",*extra,"-v", f"{artifacts_dir.resolve()}:/data",*env_passthru, image, "sqlmap", *args]

def _run_with_timeout(cmd: List[str], cwd: Path, timeout_s: int, log: Path) -> Tuple[int,str,float]:
    if not cmd:
        _append(log, "[fatal] sqlmap not found locally and no docker image set")
        return 127, "sqlmap not available", 0.0
    _append(log, f"[exec] {' '.join(cmd)} (timeout {timeout_s}s)")
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout_s)
        dur = time.time()-t0
        return proc.returncode, proc.stdout or "", dur
    except subprocess.TimeoutExpired as e:
        out = _to_text(getattr(e, "stdout", "")) + _to_text(getattr(e, "stderr", ""))
        dur = time.time()-t0
        _append(log, f"[timeout] exceeded {timeout_s}s after {int(dur)}s")
        return -9, (out + "\n[TIMEOUT]"), dur
    except Exception as e:
        dur = time.time()-t0
        _append(log, f"[fatal] {e}")
        return 1, _to_text(e), dur

def _parse_stdout(s: str) -> Dict:
    out = {"vulnerable": False, "dbms": None, "technique": None, "payload": None}
    sl = s.lower()
    if "identified the following injection point" in sl or "resumed the following injection point" in sl or "is vulnerable" in sl:
        out["vulnerable"] = True
    m = re.search(r"back-end dbms:\s*([^\n\r]+)", s, flags=re.I);     out["dbms"] = m.group(1).strip() if m else None
    pm= re.search(r"payload:\s*([^\n\r]+)", s, flags=re.I);           out["payload"] = pm.group(1).strip()[:160] if pm else None
    tm= re.search(r"(?i)type:\s*([A-Z-]+)\s+title:", s);             out["technique"]= tm.group(1).strip() if tm else None
    return out

def _normalize(url:str, param:Optional[str], parsed:Dict) -> Dict:
    return {
        "id": f"SQLMAP-{_slug(url)}-{_slug(param or 'all')}",
        "title": "SQL Injection confirmed",
        "description": "Confirmed SQL injection via sqlmap.",
        "severity": "high",
        "location": url,
        "tool": "sqlmap",
        "rule_id": "SQLMAP.SQLI",
        "cwe": ["CWE-89"],
        "tags": ["sqli","confirmed"],
        "evidence": {"param": param, "dbms": parsed.get("dbms"), "technique": parsed.get("technique"), "payload": parsed.get("payload")},
        "confirmed": True,
        "confidence": "high"
    }

def _status_from_rc(rc:int, confirmed:bool) -> str:
    if confirmed: return "confirmed"
    if rc == 0: return "not_confirmed"
    if rc == -9: return "inconclusive_timeout"
    if rc == 127: return "environment_error"
    return "error"
def _adapt_engine_input(m: dict) -> dict:
    """Normalize engine ModuleInput -> plugin's expected shape."""
    if "inputs" in m or "workdir" in m:
        # already plugin-shaped (manual runs you did earlier)
        return m
    # Engine-shaped -> adapt
    return {
        "run_id": m.get("run_id"),
        "workdir": m.get("workspace_dir") or m.get("work_dir") or m.get("workdir"),
        "artifacts_dir": m.get("artifacts_dir"),
        "inputs": _merge_target_into_inputs(m.get("config") or {}, m.get("target")),
        "previous_outputs": m.get("previous_outputs") or {},
    }

def _merge_target_into_inputs(inputs: dict, target: str | None) -> dict:
    # For web tools, expose the engine's 'target' as 'target_url' if not present.
    if target and "target_url" not in (inputs or {}):
        inputs = dict(inputs or {})
        inputs["target_url"] = target
    return inputs

def _load_param_urls(path: Path, host_rx: Optional[re.Pattern], param_rx: re.Pattern, log: Path) -> List[Dict]:
    if not path.exists():
        _append(log, f"[file] candidates_file not found: {path}")
        return []
    out = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            url = line.strip()
            if not url or url.startswith("#"): 
                continue
            if host_rx and not host_rx.search(url):
                continue
            if not param_rx.search(url):
                continue
            # Derive a default param name if present (best-effort)
            m = re.search(r"[?&]([A-Za-z0-9_\-]+)=", url)
            param = m.group(1) if m else None
            out.append({"url": url, "param": param})
    except Exception as e:
        _append(log, f"[file] read error {path}: {e}")
    # dedupe
    seen=set(); uniq=[]
    for c in out:
        k=(c["url"], c.get("param") or "")
        if k in seen: 
            continue
        seen.add(k); uniq.append(c)
    _append(log, f"[file] loaded {len(uniq)} param-url candidates from {path}")
    return uniq

# --------- main ----------
def main():
    try:
        raw = json.loads(sys.stdin.read() or "{}")
        m_input = _adapt_engine_input(raw) 
    except Exception:
        m_input = {}

    run_id = m_input.get("run_id") or f"sqlmap-{int(time.time())}"
    workdir = Path(m_input.get("workdir") or f"data/runs/{run_id}/workspace")
    artifacts = Path(m_input.get("artifacts_dir") or (workdir.parent / "artifacts"))
    _ensure_dir(workdir); _ensure_dir(artifacts)
    tool_dir = workdir / "sqlmap"; _ensure_dir(tool_dir)
    log = artifacts / "sqlmap-debug.log"
    _append(log, "=== sqlmap module start ===")

    inputs = m_input.get("inputs") or {}
    cfg = _load_cfg(inputs.get("config_file"), log) if inputs.get("config_file") else {}
    G = lambda k, d=None: _merge(inputs, cfg, k, d)

    # profile & knobs
    profile_name = (G("profile","standard") or "standard").lower()
    prof = PROFILES.get(profile_name, PROFILES["standard"])
    risk  = int(G("risk",  prof["risk"]))
    level = int(G("level", prof["level"]))
    tech  = G("technique", prof["tech"])
    time_sec = int(G("time_sec", prof["time_sec"]))
    threads  = int(G("threads",  prof["threads"]))
    verbosity= str(G("verbosity", prof["verbosity"]))
    allow_deep = bool(G("allow_deep", False))
    timeout_per = int(G("timeout_per_target_sec", 300))
    max_targets = int(G("max_targets", 20))

    extra_args = G("extra_args", []) or []
    if isinstance(extra_args, str): extra_args = [extra_args]

    # docker cfg
    docker_image = os.environ.get("SQLMAP_DOCKER_IMAGE") or G("docker_image","parrotsec/sqlmap")
    docker_extra = os.environ.get("SQLMAP_DOCKER_EXTRA_ARGS","").split()
    use_local = bool(_sqlmap_local())
    _append(log, f"[env] sqlmap local available: {use_local}; docker image: {docker_image}")

    # collect candidates
    candidates: List[Dict] = []
    host_rx = None
    if G("target_host_filter"):
        try: host_rx = re.compile(G("target_host_filter"))
        except Exception as e: _append(log, f"[config] invalid host filter: {e}")
    if isinstance(G("candidates"), list):
        candidates = G("candidates") or []
        _append(log, f"[candidates] got {len(candidates)} directly")
    else:
        sources = G("candidates_from", ["zap","nuclei"])
        if "zap" in sources:
            candidates += _extract_candidates(_load_findings(workdir/"zap"/"findings.json", log), host_rx, log)
        if "nuclei" in sources:
            candidates += _extract_candidates(_load_findings(workdir/"nuclei"/"findings.json", log), host_rx, log)
        # dedupe
        
        # file-based fallback (param URLs)
        if "file" in sources:
            cf = G("candidates_file", str(Path(m_input.get("artifacts_dir") or artifacts) / "urls.txt"))
            param_pat = G("param_url_regex", r"\?.+=.+")
            try:
                param_rx = re.compile(param_pat)
            except Exception as e:
                _append(log, f"[config] invalid param_url_regex: {e}; using default")
                param_rx = re.compile(r"\?.+=.+")
            candidates += _load_param_urls(Path(cf), host_rx, param_rx, log)

        # If still none and user asked to auto-promote param URLs from urls.txt
        if not candidates and G("auto_promote_param_urls", True):
            default_urls = Path(m_input.get("artifacts_dir") or artifacts) / "urls.txt"
            _append(log, f"[fallback] no candidates; probing param URLs in {default_urls}")
            candidates += _load_param_urls(default_urls, host_rx, re.compile(r"\?.+=.+"), log)
        seen=set(); uniq=[]
        for c in candidates:
            key=(c.get("url"), c.get("param") or "")
            if key in seen: continue
            seen.add(key); uniq.append(c)
        candidates = uniq

    # discovery mode if none
    discovery = G("discovery", None)  # e.g., {"crawl":2, "forms":true, "url":"https://target"}
    if not candidates and isinstance(discovery, dict):
        url = discovery.get("url") or G("discovery_url") or (G("base_url") or "")
        if url:
            _append(log, f"[discovery] no candidates; will probe forms on {url}")
            candidates = [{"url": url, "discovery": True}]

    if not candidates:
        _append(log, "[candidates] none to test; exiting")
        print(json.dumps({
            "status":"ok",
            "findings": [],
            "artifacts": [{"path": str(log), "type":"txt", "description":"sqlmap debug log"}],
            "stats": {"tested":0,"confirmed":0}
        }))
        return

    candidates = candidates[:max_targets]
    summary=[]; normalized=[]

    # per-candidate run
    for idx, c in enumerate(candidates, 1):
        url = c.get("url"); param = c.get("param"); method=c.get("method")
        data = c.get("data"); headers=c.get("headers"); cookies=c.get("cookies")
        out_log = artifacts / f"sqlmap-{idx:02d}.log"

        base = ["-u", url, "--batch", "--level", str(level), "--risk", str(risk),
                "--random-agent", "--flush-session", "--disable-coloring",
                "--technique="+tech, "--time-sec", str(time_sec), "-v", verbosity,
                "--threads", str(threads)]
        if param: base += ["-p", param]
        if method: base += ["--method", method]
        if data: base += ["--data", data]
        if headers: base += ["--headers", headers]
        if cookies: base += ["--cookie", cookies]

        # discovery toggles
        if c.get("discovery"):
            cr = int(discovery.get("crawl", 2) if isinstance(discovery, dict) else 2)
            forms = bool(discovery.get("forms", True) if isinstance(discovery, dict) else True)
            base += ["--crawl", str(cr)]
            if forms: base += ["--forms"]
            # keep it light
            base = [a for a in base if not a.startswith("--technique=")]
            base += ["--technique=BEU", "--time-sec", "2", "--threads", "1"]

        base += list(extra_args)

        # build command
        if use_local:
            cmd = _build_cmd_local(base)
        else:
            cmd = _build_cmd_docker(base, artifacts, docker_image, docker_extra)

        rc, stdout, dur = _run_with_timeout(cmd, artifacts, timeout_per, log)
        out_log.write_text(stdout, encoding="utf-8")

        parsed = _parse_stdout(stdout)
        confirmed = bool(parsed.get("vulnerable"))

        # adaptive fallback on timeout
        if rc == -9 and not confirmed:
            _append(log, "[retry] timeout; retrying light profile (BEU, time-sec=2, threads=1)")
            lite = [a for a in base if not a.startswith("--technique=")]
            lite += ["--technique=BEU","--time-sec","2","--threads","1","-v","2"]
            if use_local:
                cmd2 = _build_cmd_local(lite)
            else:
                cmd2 = _build_cmd_docker(lite, artifacts, docker_image, docker_extra)
            rc, stdout, dur2 = _run_with_timeout(cmd2, artifacts, min(timeout_per, 240), log)
            out_log.write_text(stdout, encoding="utf-8")
            parsed = _parse_stdout(stdout)
            confirmed = bool(parsed.get("vulnerable"))
            dur += dur2

        # optional deep escalation if clean but unconfirmed
        if rc == 0 and not confirmed and allow_deep and not c.get("discovery"):
            _append(log, "[retry] clean run, not confirmed; escalating deep once")
            deep = [a for a in base if not a.startswith("--technique=")]
            deep += ["--technique="+PROFILES["deep"]["tech"], "--time-sec", str(PROFILES["deep"]["time_sec"]), "--threads", str(PROFILES["deep"]["threads"]), "-v", PROFILES["deep"]["verbosity"]]
            if use_local:
                cmd3 = _build_cmd_local(deep)
            else:
                cmd3 = _build_cmd_docker(deep, artifacts, docker_image, docker_extra)
            rc, stdout, dur3 = _run_with_timeout(cmd3, artifacts, min(timeout_per, 360), log)
            out_log.write_text(stdout, encoding="utf-8")
            parsed = _parse_stdout(stdout)
            confirmed = bool(parsed.get("vulnerable"))
            dur += dur3

        status = _status_from_rc(rc, confirmed)
        summary.append({
            "url": url, "param": param, "rc": rc, "status": status,
            "dbms": parsed.get("dbms"), "technique": parsed.get("technique"),
            "log": str(out_log), "duration_sec": int(dur),
            "profile": {"risk":risk,"level":level,"technique":tech,"time_sec":time_sec,"threads":threads}
        })

        if confirmed:
            normalized.append(_normalize(url, param, parsed))

    # outputs
    (artifacts / "sqlmap-summary.json").write_text(json.dumps({"results": summary}, ensure_ascii=False, indent=2), encoding="utf-8")
    (tool_dir / "findings.json").write_text(json.dumps({"findings": normalized}, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps({
        "status": "ok",
        "findings": normalized,
        "artifacts": [
            {"path": str(artifacts / "sqlmap-summary.json"), "type":"json", "description":"sqlmap results summary"},
            {"path": str(log), "type":"txt", "description":"sqlmap debug log"},
            *[{"path": str(p), "type":"txt", "description":"sqlmap target log"} for p in sorted(artifacts.glob("sqlmap-*.log"))]
        ],
        "stats": {"tested": len(summary), "confirmed": len(normalized)}
    }))
if __name__ == "__main__":
    main()
