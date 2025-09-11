#!/usr/bin/env python3
# core/plugins/web/nuclei/main.py
import os
import sys
import io
import json
import shlex
import re
import datetime
import subprocess
from pathlib import Path
from urllib.parse import urlparse

# ----------------- tiny io helpers -----------------

def _eprint(*a):
    print(*a, file=sys.stderr, flush=True)

def _json_out(payload: dict, code: int = 0):
    """Emit JSON to stdout for the engine; exit with given code (0 even on error so artifacts persist)."""
    print(json.dumps(payload))
    sys.exit(code)

def _safe_iterdir(p: Path):
    try:
        return list(p.iterdir())
    except Exception:
        return []

def _has_content(p: Path) -> bool:
    return bool(_safe_iterdir(p))

# ----------------- arg normalizer ------------------

def _normalize_extra_args(extra_args: str):
    """Allow '-timeout 10s' by converting to '-timeout 10' (nuclei expects numeric seconds)."""
    toks = shlex.split(extra_args or "")
    for i, t in enumerate(toks):
        if t in ("-timeout", "-tmo") and i + 1 < len(toks):
            m = re.fullmatch(r"(\d+)[sS]", toks[i + 1])
            if m:
                toks[i + 1] = m.group(1)
    return toks

# ----------------- templates -----------------------

def _count_templates(templates_dir: Path, log) -> int:
    try:
        p = subprocess.run(
            ["nuclei", "-tl", "-t", str(templates_dir)],
            capture_output=True, text=True, check=False
        )
        if p.returncode != 0:
            if p.stderr:
                log(f"[wrapper] nuclei -tl stderr:\n{p.stderr}")
            return 0
        return len([ln for ln in p.stdout.splitlines() if ln.strip()])
    except Exception as ex:
        log(f"[wrapper] WARN: template count failed: {ex}")
        return 0

def _ensure_templates(templates_dir: Path, cache_dir: Path, log):
    import urllib.request, zipfile, shutil
    templates_dir.mkdir(parents=True, exist_ok=True)
    if any(templates_dir.iterdir()):
        log(f"[wrapper] templates already present at {templates_dir}")
        return
    archive = os.getenv(
        "NUCLEI_TPL_ARCHIVE",
        "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
    )
    try:
        log(f"[wrapper] downloading nuclei-templates zip …")
        with urllib.request.urlopen(archive, timeout=120) as resp:
            zdata = io.BytesIO(resp.read())
        with zipfile.ZipFile(zdata) as zf:
            # find top-level dir in archive
            top = next((n.split("/", 1)[0] for n in zf.namelist() if "/" in n), "")
            tmp_extract = cache_dir / "_tpl_extract"
            shutil.rmtree(tmp_extract, ignore_errors=True)
            tmp_extract.mkdir(parents=True, exist_ok=True)
            zf.extractall(tmp_extract)
        src = tmp_extract / top if top else tmp_extract
        if src.exists():
            for item in src.iterdir():
                dst = templates_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dst)
        log(f"[wrapper] templates ready at {templates_dir}")
    except Exception as ex:
        log(f"[wrapper] WARNING: Python fallback failed to fetch templates: {ex}")

# ----------------- url harvesting ------------------

def _harvest_urls(artifacts_dir: Path, target: str, log):
    urls = set()
    pre = artifacts_dir / "urls.txt"
    if pre.exists():
        try:
            for ln in pre.read_text(encoding="utf-8").splitlines():
                u = ln.strip()
                if u.startswith("http"):
                    urls.add(u)
            log(f"[wrapper] found pre-existing urls.txt with {len(urls)} urls")
        except Exception as ex:
            log(f"[wrapper] WARN: could not read urls.txt: {ex}")

    if not urls:
        for cand in ("zap-baseline.json", "zap-baseline-raw.json", "zap.json"):
            p = artifacts_dir / cand
            if not p.exists():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            # zap-like structures
            for s in data.get("site") or []:
                for a in s.get("alerts") or []:
                    for i in a.get("instances") or []:
                        u = (i.get("uri") or "").strip()
                        if u.startswith("http"):
                            urls.add(u)
            for u in data.get("urls") or []:
                if isinstance(u, str) and u.startswith("http"):
                    urls.add(u)
            if urls:
                log(f"[wrapper] harvested {len(urls)} urls from {p.name}")
                break

    if not urls and target:
        base = target.rstrip("/")
        try:
            pu = urlparse(base)
            if pu.scheme and pu.netloc:
                urls.update({
                    base,
                    f"{base}/robots.txt",
                    f"{base}/sitemap.xml",
                    f"{base}/login.jsp",
                    f"{base}/feedback.jsp",
                })
                log(f"[wrapper] fallback url seeding -> {len(urls)}")
        except Exception:
            urls.add(target)

    out = artifacts_dir / "urls.txt"
    try:
        with out.open("w", encoding="utf-8") as f:
            for u in sorted(urls):
                f.write(u + "\n")
        log(f"[wrapper] wrote {len(urls)} urls to {out}")
    except Exception as ex:
        log(f"[wrapper] WARN: could not write urls.txt: {ex}")
    return out, len(urls)

# ----------------- input adapter -------------------

def _merge_target_into_inputs(inputs: dict, target: str | None) -> dict:
    inputs = dict(inputs or {})
    if target and "target_url" not in inputs:
        inputs["target_url"] = target
    return inputs

def _adapt_engine_input(m: dict) -> dict:
    """Accept engine ModuleInput or simple {"target": "..."} and return a uniform shape."""
    if "inputs" in m or "workdir" in m:
        return m
    return {
        "run_id": m.get("run_id"),
        "workdir": m.get("workspace_dir"),
        "artifacts_dir": m.get("artifacts_dir"),
        "inputs": _merge_target_into_inputs(m.get("config") or {}, m.get("target")),
        "previous_outputs": m.get("previous_outputs") or {},
    }

# ----------------- dir picking ---------------------

def _first_writable_dir(candidates):
    for c in candidates:
        if not c:
            continue
        try:
            p = Path(c)
            p.mkdir(parents=True, exist_ok=True)
            test = p / ".touch"
            with test.open("w") as fh:
                fh.write("ok")
            test.unlink(missing_ok=True)
            return p
        except Exception:
            continue
    # final fallback
    p = Path("/tmp/nuclei_fallback")
    p.mkdir(parents=True, exist_ok=True)
    return p

# ----------------- main ----------------------------

def main():
    # timezone-aware timestamp (fixes DeprecationWarning)
    #started_at = datetime.datetime.now(datetime.UTC).isoformat()
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # stdin → json → adapt
    raw = sys.stdin.read() or "{}"
    try:
        mod_in = json.loads(raw)
        mod_in = _adapt_engine_input(mod_in)
    except Exception as ex:
        _eprint(f"[wrapper] WARN: failed to parse/adapt stdin JSON: {ex}")
        mod_in = {}

    # dirs (pick truly writable artifacts first; avoid /artifacts if not writable)
    requested_artifacts = [
        os.getenv("ARTIFACTS_DIR"),
        mod_in.get("artifacts_dir"),
        "/artifacts",                 # will be tested
        "/tmp/nuclei_artifacts",      # good fallback
    ]
    artifacts_dir = _first_writable_dir(requested_artifacts)

    cache_dir = _first_writable_dir([
        os.getenv("CACHE_DIR"),
        mod_in.get("cache_dir"),
        "/cache",
        "/tmp/nuclei_cache",
    ])
    templates_dir = Path(os.getenv("NUCLEI_TEMPLATES") or str(cache_dir / "nuclei-templates"))
    xdg_cfg = Path(os.getenv("XDG_CONFIG_HOME") or str(cache_dir / ".config"))

    # env
    os.environ.setdefault("HOME", str(cache_dir))
    os.environ["XDG_CONFIG_HOME"] = str(xdg_cfg)

    # target + files
    target = (os.getenv("TARGET") or mod_in.get("target") or mod_in.get("inputs", {}).get("target_url") or "").strip()

    # Align artifact file paths to the writable artifacts_dir
    jsonl_path = Path(mod_in.get("jsonl_path") or (artifacts_dir / "nuclei.jsonl"))
    debug_log_path = artifacts_dir / "nuclei.debug.log"  # optional, file logging off by default

    # ensure dirs exist (best-effort)
    for p in (artifacts_dir, cache_dir, templates_dir, xdg_cfg, debug_log_path.parent):
        try:
            p.mkdir(parents=True, exist_ok=True)
        except Exception as ex:
            _eprint(f"[wrapper] WARN: could not mkdir {p}: {ex}")

    # Final permission sanity check before any file opens; force /tmp if needed
    try:
        if not os.access(str(artifacts_dir), os.W_OK):
            raise PermissionError(f"artifacts_dir not writable: {artifacts_dir}")
    except Exception as ex:
        _eprint(f"[wrapper] WARN: artifacts dir not writable ({ex}); forcing /tmp fallback")
        artifacts_dir = _first_writable_dir(["/tmp/nuclei_artifacts_fallback", "/tmp/nuclei_artifacts"])
        jsonl_path = artifacts_dir / "nuclei.jsonl"
        debug_log_path = artifacts_dir / "nuclei.debug.log"
        try:
            artifacts_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    # ---- logging strategy ----
    # Print everything to console (stderr). Optional file logging only if explicitly enabled.
    ENABLE_DEBUG_FILE = os.getenv("ENABLE_DEBUG_FILE", "0") == "1"
    dbg_file = None

    def log(msg: str):
        _eprint(msg)
        if dbg_file is not None:
            try:
                dbg_file.write(msg + "\n")
                dbg_file.flush()
            except Exception:
                pass

    if ENABLE_DEBUG_FILE:
        try:
            dbg_file = debug_log_path.open("w", encoding="utf-8")
        except Exception as ex:
            _eprint(f"[wrapper] WARN: debug log file not writable ({ex}); continuing without file")

    # banner
    log(f"[wrapper] build_id={os.getenv('WRAPPER_BUILD_ID','(none)')}")
    log(f"[wrapper] started_at={started_at}")
    log(f"[wrapper] target={target or '(missing)'}")
    log(f"[wrapper] artifacts_dir={artifacts_dir}")
    log(f"[wrapper] cache_dir={cache_dir}")
    log(f"[wrapper] templates_dir={templates_dir}")
    log(f"[wrapper] HOME={os.getenv('HOME')}")
    log(f"[wrapper] XDG_CONFIG_HOME={os.getenv('XDG_CONFIG_HOME')}")

    # extra diagnostics
    if os.getenv("WRAPPER_DEBUG") == "1":
        try:
            import getpass, platform, shutil
            log("[diag] ===== debug mode on =====")
            log(f"[diag] python_exe={sys.executable}")
            log(f"[diag] argv={' '.join(shlex.quote(a) for a in sys.argv)}")
            log(f"[diag] cwd={os.getcwd()}")
            log(f"[diag] uid={os.getuid()} gid={os.getgid()} user={getpass.getuser()}")
            log(f"[diag] platform={platform.platform()}")
            log(f"[diag] which_nuclei={shutil.which('nuclei')}")
            log(f"[diag] perms artifacts: exists={os.path.exists(str(artifacts_dir))} "
                f"writable={os.access(str(artifacts_dir), os.W_OK)}")
            log(f"[diag] perms cache: exists={os.path.exists(str(cache_dir))} "
                f"writable={os.access(str(cache_dir), os.W_OK)}")
            allow = {"HOME","XDG_CONFIG_HOME","NUCLEI_TEMPLATES","NUCLEI_SKIP_UPDATE",
                     "WRAPPER_BUILD_ID","TARGET","NUCLEI_ARGS","ARTIFACTS_DIR","CACHE_DIR"}
            env_dump = {k: v for k, v in os.environ.items() if k in allow}
            log(f"[diag] env={json.dumps(env_dump)}")
        except Exception as ex:
            log(f"[diag] early diagnostics failed: {ex}")

    # nuclei version
    try:
        ver = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, check=False)
        log(ver.stdout.strip() or ver.stderr.strip() or "[wrapper] nuclei -version produced no output")
    except Exception as ex:
        log(f"[wrapper] ERROR: cannot exec nuclei: {ex}")

    # require target
    if not target:
        artifacts = [
            {"path": str(jsonl_path), "type": "json", "description": "Nuclei raw JSONL"},
        ]
        if ENABLE_DEBUG_FILE and debug_log_path.exists():
            artifacts.append({"path": str(debug_log_path), "type": "txt", "description": "Nuclei debug log"})
        if dbg_file:
            dbg_file.close()
        _json_out({"status": "error", "error": "missing target (stdin target or TARGET env)",
                   "findings": [], "artifacts": artifacts})

    # templates
    _ensure_templates(templates_dir, cache_dir, log)
    tpl_count = _count_templates(templates_dir, log)
    log(f"[wrapper] templates_available={tpl_count}")

    # urls
    urls_file, urls_count = _harvest_urls(artifacts_dir, target, log)
    log(f"[wrapper] urls_count={urls_count}")

    # nuclei cmd
    cmd = ["nuclei", "-t", str(templates_dir), "-silent", "-retries", "1", "-jle", str(jsonl_path)]
    if urls_count > 0:
        cmd += ["-l", str(urls_file)]
    else:
        cmd += ["-u", target]

    extra_args = (mod_in.get("args") or os.getenv("NUCLEI_ARGS") or "").strip()
    if extra_args:
        norm = _normalize_extra_args(extra_args)
        log(f"[wrapper] appending extra args: {' '.join(shlex.quote(x) for x in norm)}")
        cmd += norm

    log(f"[wrapper] running: {' '.join(shlex.quote(c) for c in cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stdout:
        log(proc.stdout.strip())
    if proc.stderr:
        log(proc.stderr.strip())
    log(f"[wrapper] exit_code={proc.returncode}")

    artifacts = [
        {"path": str(jsonl_path), "type": "json", "description": "Nuclei raw JSONL"},
        {"path": str(urls_file),  "type": "txt",  "description": "URL list used by Nuclei"},
    ]
    if ENABLE_DEBUG_FILE and debug_log_path.exists():
        artifacts.append({"path": str(debug_log_path), "type": "txt", "description": "Nuclei debug log"})

    if proc.returncode != 0:
        if dbg_file:
            dbg_file.close()
        _json_out({"status": "error", "error": f"nuclei exited {proc.returncode}",
                   "findings": [], "artifacts": artifacts})

    # parse jsonl → findings
    findings = []
    try:
        if jsonl_path.exists():
            with jsonl_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except Exception:
                        continue
                    info = evt.get("info") or {}
                    title = info.get("name") or evt.get("template-id", "nuclei")
                    sev = str(info.get("severity", "info"))
                    match = evt.get("matched-at") or evt.get("host") or target
                    fid = evt.get("template-id", "nuclei")
                    if evt.get("matcher-name"):
                        fid += f":{evt['matcher-name']}"
                    findings.append({
                        "id": fid,
                        "title": title,
                        "description": info.get("description") or "",
                        "severity": sev,
                        "location": match,
                        "tool": "nuclei",
                        "cwe": (info.get("classification") or {}).get("cwe-id"),
                        "tags": info.get("tags") or [],
                    })
    except Exception as ex:
        log(f"[wrapper] WARN: JSONL parse failed: {ex}")

    if dbg_file:
        dbg_file.close()
    _json_out({"status": "ok", "findings": findings, "artifacts": artifacts, "stderr": ""})

if __name__ == "__main__":
    main()
