#!/usr/bin/env python3
import sys, json, os, time, uuid, pathlib, subprocess, shlex, threading

"""
Reads ModuleInput on stdin:
{
  "run_id": "...",
  "workdir": "data/runs/<id>/workspace",
  "inputs": {"server":"https://oast.pro","lifetime_sec":900,"poll_interval_sec":5},
  "env": {}
}

Writes ModuleOutput on stdout with env containing OAST token+fqdn and starts a
detached poller (interactsh-client) that keeps writing callbacks into:
  <workdir>/oast/callbacks.json   (ndjson merged into JSON list by the poller)
Also writes:
  <workdir>/oast/poller.pid
  <workdir>/oast/oast.log
"""

DEF_SERVER = "https://oast.pro"  # override with inputs.server or INTERACTSH_SERVER
DOCKER_IMAGE = os.getenv("INTERACTSH_DOCKER_IMAGE", "projectdiscovery/interactsh-client:latest")

def _json_print(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()

def main():
    cfg = json.load(sys.stdin)
    run_id = cfg["run_id"]
    workdir = pathlib.Path(cfg["workdir"])
    inputs = cfg.get("inputs") or {}
    server = inputs.get("server") or os.getenv("INTERACTSH_SERVER") or DEF_SERVER
    lifetime = int(inputs.get("lifetime_sec") or os.getenv("INTERACTSH_LIFETIME_SEC") or 900)
    poll_iv = int(inputs.get("poll_interval_sec") or os.getenv("INTERACTSH_POLL_IV") or 5)

    oast_dir = workdir / "oast"
    oast_dir.mkdir(parents=True, exist_ok=True)
    callbacks_path = oast_dir / "callbacks.json"
    log_path = oast_dir / "oast.log"
    pid_path = oast_dir / "poller.pid"

    # Token + fqdn we will inject into payloads downstream
    token = str(uuid.uuid4()).replace("-", "")[:12]
    fqdn = f"{token}.oast.pro" if "oast." in server else f"{token}.oast.pro"

    # Start interactsh-client via Docker if available; fall back to "passive token" mode
    docker_cmd = (
        f"docker run --rm -i "
        f"-v {shlex.quote(str(oast_dir))}:/data "
        f"{DOCKER_IMAGE} "
        f"-json -o /data/callbacks.ndjson -q"
    )
    # NOTE: The official client auto-registers and prints domain on startup.
    # We detach it via a lightweight wrapper that keeps it alive; we also
    # backfill callbacks.json by compacting NDJSON periodically.

    def _poller():
        # Write a small supervisor loop
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(f"[poller] starting interactsh-client (docker image: {DOCKER_IMAGE})\n")
            proc = None
            try:
                proc = subprocess.Popen(
                    docker_cmd, shell=True, stdout=lf, stderr=lf, text=True
                )
                pid_path.write_text(str(proc.pid))
                ndjson_path = oast_dir / "callbacks.ndjson"
                started = time.time()
                events = []
                seen = 0
                while time.time() - started < lifetime:
                    time.sleep(poll_iv)
                    # Compact NDJSON into a single JSON list for easy reading by aggregator
                    if ndjson_path.exists():
                        try:
                            # Only append new events
                            with ndjson_path.open("r", encoding="utf-8") as f:
                                lines = f.readlines()
                            if len(lines) > seen:
                                for line in lines[seen:]:
                                    line = line.strip()
                                    if not line:
                                        continue
                                    try:
                                        events.append(json.loads(line))
                                    except Exception:
                                        pass
                                seen = len(lines)
                                callbacks_path.write_text(json.dumps({"events": events}, ensure_ascii=False))
                        except Exception as ex:
                            lf.write(f"[poller] compact error: {ex}\n")
                lf.write("[poller] lifetime reached, stopping client\n")
            except FileNotFoundError:
                with open(log_path, "a", encoding="utf-8") as lf2:
                    lf2.write("[poller] docker not found; running in passive token-only mode\n")
            finally:
                if proc and proc.poll() is None:
                    try:
                        proc.terminate()
                    except Exception:
                        pass

    # Spawn the poller in the background and return immediately
    t = threading.Thread(target=_poller, daemon=True)
    t.start()

    # Minimal self-finding to indicate OAST session context
    finding = {
        "id": f"OAST-{token}",
        "title": "OAST session initialized",
        "severity": "info",
        "tool": "oast",
        "type": "oast.session",
        "sources": ["oast"],
        "evidence": {"callback_id": token, "server": server, "fqdn": fqdn}
    }

    _json_print({
        "status": "ok",
        "artifacts": [
            {"path": str(callbacks_path), "description": "OAST callbacks (compacted JSON)", "content_type": "application/json"},
            {"path": str(pid_path), "description": "Poller PID", "content_type": "text/plain"},
            {"path": str(log_path), "description": "OAST client log", "content_type": "text/plain"}
        ],
        "findings": [finding],
        "stats": {"duration_sec": 1},
        "env": {"OAST_TOKEN": token, "OAST_FQDN": fqdn, "OAST_SERVER": server}
    })

if __name__ == "__main__":
    main()
