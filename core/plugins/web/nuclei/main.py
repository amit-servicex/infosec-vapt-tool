#!/usr/bin/env python3
# core/plugins/web/nuclei/main.py
import os
import sys
import json
import shlex
import re
import datetime
import subprocess
from pathlib import Path
from urllib.parse import urlparse

# ---------- small helpers ----------

def _eprint(*a): print(*a, file=sys.stderr, flush=True)

def _json_out(payload: dict):
    """Emit the module's JSON result on stdout."""
    print(json.dumps(payload))
    # status != ok should still exit 0 so the engine can persist artifacts
    sys.exit(0)

def _safe_iterdir(p: Path):
    try:
        return list(p.iterdir())
    except Exception:
        return []

def _has_content(p: Path) -> bool:
    return bool(_safe_iterdir(p))

def _normalize_extra_args(extra_args: str):
    """Allow -timeout 10s by converting to -timeout 10 (nuclei expects numeric seconds)."""
    toks = shlex.split(extra_args or "")
    for i, t in enumerate(toks):
        if t in ("-timeout", "-tmo") and i + 1 < len(toks):
            m = re.fullmatch(r"(\d+)[sS]", toks[i+1])
            if m:
                toks[i+1] = m.group(1)
    return toks

# ---------- templates management (no /root access) ----------

def _count_templates(templates_dir: Path, log) -> int:
    try:
        p = subprocess.run(
            ["nuclei", "-tl", "-t", str(templates_dir)],
            capture_output=True, text=True, check=False
        )
        if p.returncode != 0:
            if p.stderr: log(f"[wrapper] nuclei -tl stderr:\n{p.stderr}")
            return 0
        return len([ln for ln in p.stdout.splitlines() if ln.strip()])
    except Exception as ex:
        log(f"[wrapper] WARN: template count failed: {ex}")
        return 0

def _ensure_templates(templates_dir: Path, cache_dir: Path, log):
    """
    Ensure templates live under a WRITABLE dir (templates_dir).
    Strategy:
      1) Make sure dirs exist; set HOME and XDG_CONFIG_HOME into cache_dir.
      2) Run `nuclei -update-templates` (it honors HOME/NUCLEI_TEMPLATES).
      3) If still empty, optional best-effort ZIP fallback when curl+unzip exist.
    """
    templates_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: update-templates (uses HOME/NUCLEI_TEMPLATES)
    log("[wrapper] templates check: running nuclei -update-templates …")
    up = subprocess.run(["nuclei", "-update-templates"], capture_output=True, text=True)
    if up.stdout: log(up.stdout.strip())
    if up.stderr: log(up.stderr.strip())

    cnt = _count_templates(templates_dir, log)
    if cnt > 0:
        log(f"[wrapper] templates available after update: {cnt}")
        return

    # Step 2 (optional): fallback download if tools exist
    curl = subprocess.run(["/bin/sh", "-lc", "command -v curl >/dev/null 2>&1"], capture_output=True)
    unzip = subprocess.run(["/bin/sh", "-lc", "command -v unzip >/dev/null 2>&1"], capture_output=True)
    if curl.returncode == 0 and unzip.returncode == 0:
        log("[wrapper] templates still empty; trying archive fallback download …")
        archive = os.getenv(
            "NUCLEI_TPL_ARCHIVE",
            "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
        )
        cmd = (
            f'curl -fsSL "{archive}" -o /tmp/ntpl.zip && '
            f'unzip -q /tmp/ntpl.zip -d /tmp && '
            f'src="$(ls -d /tmp/nuclei-templates-* | head -n1)" && '
            f'cp -a "$src/." "{templates_dir}/" || true'
        )
        dl = subprocess.run(["/bin/sh", "-lc", cmd], capture_output=True, text=True)
        if dl.stdout: log(dl.stdout.strip())
        if dl.stderr: log(dl.stderr.strip())
        cnt = _count_templates(templates_dir, log)
        log(f"[wrapper] templates after fallback: {cnt}")
    else:
        log("[wrapper] WARNING: curl/unzip not available for fallback; proceeding without.")

# ---------- URL harvesting ----------

def _harvest_urls(artifacts_dir: Path, target: str, log):
    """
    Build a seed list of URLs for nuclei:
      1) Use existing /artifacts/urls.txt if present.
      2) Try ZAP baseline JSON for discovered URLs.
      3) Seed a few common paths under the target.
    """
    urls = set()

    # (1) pre-supplied list
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

    # (2) ZAP outputs
    if not urls:
        for cand in ("zap-baseline.json", "zap-baseline-raw.json", "zap.json"):
            p = artifacts_dir / cand
            if not p.exists():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue

            # ZAP "site[].alerts[].instances[].uri"
            for s in data.get("site") or []:
                for a in s.get("alerts") or []:
                    for i in a.get("instances") or []:
                        u = (i.get("uri") or "").strip()
                        if u.startswith("http"):
                            urls.add(u)

            # Some wrappers add a top-level urls[]
            for u in data.get("urls") or []:
                if isinstance(u, str) and u.startswith("http"):
                    urls.add(u)

            if urls:
                log(f"[wrapper] harvested {len(urls)} urls from {p.name}")
                break

    # (3) fallback seeds
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

# ---------- main ----------

def main():
    started_at = datetime.datetime.utcnow().isoformat()

    # Read module input JSON from stdin (engine provides it)
    #raw = sys.stdin.read()
    raw = json.loads(sys.stdin.read() or "{}")
    m_input = _adapt_engine_input(raw)
    try:
        mod_in = json.loads(raw) if raw.strip() else {}
    except Exception as ex:
        _eprint(f"[wrapper] WARN: failed to parse stdin as JSON: {ex}")
        mod_in = {}

    # Resolve paths / env (MUST be writable)
    artifacts_dir = Path(os.getenv("ARTIFACTS_DIR") or mod_in.get("artifacts_dir") or "/artifacts")
    cache_dir     = Path(os.getenv("CACHE_DIR")     or mod_in.get("cache_dir")     or "/cache")
    templates_dir = Path(os.getenv("NUCLEI_TEMPLATES") or str(cache_dir / "nuclei-templates"))
    xdg_cfg       = Path(os.getenv("XDG_CONFIG_HOME") or str(cache_dir / ".config"))

    # Force HOME to a writable place so nuclei stores config/templates under /cache
    os.environ.setdefault("HOME", str(cache_dir))
    os.environ["XDG_CONFIG_HOME"] = str(xdg_cfg)

    target = (os.getenv("TARGET") or mod_in.get("target") or "").strip()
    jsonl_path = Path(mod_in.get("jsonl_path") or artifacts_dir / "nuclei.jsonl")
    debug_log  = artifacts_dir / "nuclei.debug.log"

    # Ensure dirs
    for p in (artifacts_dir, cache_dir, templates_dir, xdg_cfg, debug_log.parent):
        p.mkdir(parents=True, exist_ok=True)

    # Open debug sink
    dbg = debug_log.open("w", encoding="utf-8")
    def log(msg: str):
        dbg.write(msg + "\n"); dbg.flush(); _eprint(msg)

    log(f"[wrapper] started_at={started_at}")
    log(f"[wrapper] target={target or '(missing)'}")
    log(f"[wrapper] artifacts_dir={artifacts_dir}")
    log(f"[wrapper] cache_dir={cache_dir}")
    log(f"[wrapper] templates_dir={templates_dir}")
    log(f"[wrapper] HOME={os.getenv('HOME')}")
    log(f"[wrapper] XDG_CONFIG_HOME={os.getenv('XDG_CONFIG_HOME')}")

    # Nuclei version
    try:
        ver = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, check=False)
        log(ver.stdout.strip() or ver.stderr.strip() or "[wrapper] nuclei -version produced no output")
    except Exception as ex:
        log(f"[wrapper] ERROR: cannot exec nuclei: {ex}")

    if not target:
        artifacts = [
            {"path": str(debug_log), "type": "txt",  "description": "Nuclei debug log"},
            {"path": str(jsonl_path), "type": "json", "description": "Nuclei raw JSONL"},
        ]
        dbg.close()
        _json_out({"status": "error", "error": "missing target (stdin target or TARGET env)", "findings": [], "artifacts": artifacts})

    # Ensure templates (rootless)
    _ensure_templates(templates_dir, cache_dir, log)
    tpl_count = _count_templates(templates_dir, log)
    log(f"[wrapper] templates_available={tpl_count}")

    # Build URL list
    urls_file, urls_count = _harvest_urls(artifacts_dir, target, log)
    log(f"[wrapper] urls_count={urls_count}")

    # Build nuclei cmd
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
    if proc.stdout: log(proc.stdout.strip())
    if proc.stderr: log(proc.stderr.strip())
    log(f"[wrapper] exit_code={proc.returncode}")

    artifacts = [
        {"path": str(jsonl_path), "type": "json", "description": "Nuclei raw JSONL"},
        {"path": str(debug_log),  "type": "txt",  "description": "Nuclei debug log"},
        {"path": str(urls_file),  "type": "txt",  "description": "URL list used by Nuclei"},
    ]

    if proc.returncode != 0:
        dbg.close()
        _json_out({"status": "error", "error": f"nuclei exited {proc.returncode}", "findings": [], "artifacts": artifacts})

    # Parse JSONL -> normalized findings (lenient)
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
                    sev   = str(info.get("severity", "info"))
                    match = evt.get("matched-at") or evt.get("host") or target
                    fid   = evt.get("template-id", "nuclei")
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

    dbg.close()
    _json_out({"status": "ok", "findings": findings, "artifacts": artifacts, "stderr": ""})

if __name__ == "__main__":
    main()
