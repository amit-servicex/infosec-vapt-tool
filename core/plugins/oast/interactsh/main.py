#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oast.interactsh
- mode="broker": writes an Interactsh session file (session_id, server)
- mode="poll":   runs the client, captures events, correlates -> findings[]
JSON I/O contract aligns with core pipeline (stdin -> stdout).
"""

import json, os, sys, time, uuid, pathlib, subprocess, shlex
from typing import Dict, Any

def _read_stdin() -> Dict[str, Any]:
    raw = sys.stdin.read()
    return json.loads(raw) if raw.strip() else {}

def _ensure_dir(p: pathlib.Path):
    p.mkdir(parents=True, exist_ok=True)

def _dump(path: pathlib.Path, data: Any):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2))

def _load_map(maybe_path_or_dict):
    # Accept dict or file path
    if isinstance(maybe_path_or_dict, dict):
        return maybe_path_or_dict
    if isinstance(maybe_path_or_dict, str) and maybe_path_or_dict:
        p = pathlib.Path(maybe_path_or_dict)
        if p.exists():
            return json.loads(p.read_text())
    return {}

def _open_debug(path: pathlib.Path):
    return path.open("a", buffering=1, encoding="utf-8")

def _docker_cmd(args):
    extra = os.getenv("ZAP_DOCKER_EXTRA_ARGS", "")
    base = ["docker", "run", "--rm", "-i"]
    if extra:
        base += shlex.split(extra)
    return base + args

def _interactsh_client_cmd(server: str):
    image = os.getenv("INTERACTSH_DOCKER_IMAGE", "projectdiscovery/interactsh-client:latest")
    cmd = _docker_cmd([image, "-json"])
    if server:
        cmd += ["-server", server]
    return cmd

def _emit(status="ok", artifacts=None, findings=None, stats=None):
    print(json.dumps({
        "status": status,
        "artifacts": artifacts or [],
        "findings": findings or [],
        "stats": stats or {},
    }, ensure_ascii=False))

def main():
    i = _read_stdin()
    run_id   = i.get("run_id", f"run-{int(time.time())}")
    workdir  = pathlib.Path(i.get("workdir", f"data/runs/{run_id}/workspace"))
    inputs   = i.get("inputs", {}) or {}
    mode     = inputs.get("mode", "broker")
    server   = inputs.get("interactsh_server", os.getenv("INTERACTSH_SERVER", ""))
    max_dur  = int(inputs.get("max_duration_sec", 120))
    request_map_in = inputs.get("request_map", {})

    oast_dir = workdir / "oast"
    _ensure_dir(oast_dir)
    dbg_fp = _open_debug(oast_dir / "oast-debug.log")

    try:
        if mode == "broker":
            # Generate a session id and persist it for other modules to consume
            session = {
                "session_id": str(uuid.uuid4()),
                "server": server or "auto",
                "created_at": int(time.time())
            }
            sess_path = oast_dir / "interactsh-session.json"
            _dump(sess_path, session)
            dbg_fp.write(f"[broker] session created: {session['session_id']}\n")
            _emit(
                artifacts=[{"path": str(sess_path), "description":"OAST session", "content_type":"application/json"}],
                stats={"mode": "broker"}
            )
            return

        # POLL MODE
        # 1) Build request map (to correlate callbacks -> original request)
        request_map: Dict[str, Any] = _load_map(request_map_in)
        if not request_map:
            dbg_fp.write("[poll] warning: empty request_map; correlation may be limited\n")

        # 2) Run interactsh-client in JSON streaming mode via Docker
        events_path = oast_dir / "interactsh-events.jsonl"
        cmd = _interactsh_client_cmd(server)
        dbg_fp.write(f"[poll] cmd: {' '.join(shlex.quote(c) for c in cmd)}\n")
        start = time.time()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # 3) Stream lines up to max_dur; persist raw events
        findings = []
        with events_path.open("w", encoding="utf-8") as outf:
            while True:
                if proc.poll() is not None:
                    # process exited
                    break
                if time.time() - start >= max_dur:
                    try: proc.terminate()
                    except Exception: pass
                    break
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                outf.write(line)
                # parse incrementally for low-latency correlation
                try:
                    ev = json.loads(line)
                except Exception as e:
                    dbg_fp.write(f"[poll] parse error: {e}\n")
                    continue

                # common fields across interactsh-client
                host = ev.get("full-id") or ev.get("unique-id") or ""
                if not host:
                    # fallback: sometimes 'raw-request' or 'qname' carries the id; keep raw evidence
                    findings.append({
                        "id": f"OAST-CALLBACK-{len(findings)+1}",
                        "type": "oast_callback",
                        "tool": "interactsh",
                        "severity": "high",
                        "confidence": "high",
                        "location": "",
                        "evidence": {"raw": ev},
                        "tags": ["oast","callback"]
                    })
                    continue

                # convention: <reqid>.<session>.<rest>
                req_id = host.split(".", 1)[0] if "." in host else host
                src = request_map.get(req_id, {})
                finding = {
                    "id": f"OAST-CALLBACK-{req_id}",
                    "title": "Out-of-band interaction observed",
                    "type": "oast_callback",
                    "tool": "interactsh",
                    "severity": "high",
                    "confidence": "high",
                    "location": src.get("url", ""),
                    "method": src.get("method", "GET"),
                    "parameter": src.get("param"),
                    "evidence": {
                        "host": host,
                        "protocol": ev.get("protocol"),
                        "timestamp": ev.get("timestamp"),
                        "remote_addr": ev.get("remote-addr"),
                        "raw": ev
                    },
                    "tags": ["oast","ssrf","xxe","blind"],
                    "cwe": "CWE-918",     # SSRF (most common OAST trigger)
                    "owasp": "A10:2021"   # Server-Side Request Forgery
                }
                findings.append(finding)

        duration = int(time.time() - start)
        dbg_fp.write(f"[poll] duration={duration}s findings={len(findings)}\n")

        _emit(
            artifacts=[
                {"path": str(events_path), "description":"Interactsh events", "content_type":"application/x-ndjson"},
                {"path": str(oast_dir / "oast-debug.log"), "description":"OAST debug", "content_type":"text/plain"}
            ],
            findings=findings,
            stats={"mode":"poll","duration_sec": duration, "events": sum(1 for _ in events_path.open())}
        )

    except FileNotFoundError as e:
        # docker not present or image missing
        dbg_fp.write(f"[error] {e}\n")
        _emit(status="error", stats={"error":"docker/image not found", "detail": str(e)})
    except Exception as e:
        dbg_fp.write(f"[error] {e}\n")
        _emit(status="error", stats={"error": str(e)})
    finally:
        try: dbg_fp.close()
        except Exception: pass

if __name__ == "__main__":
    main()
