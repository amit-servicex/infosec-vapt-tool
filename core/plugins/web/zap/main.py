#!/usr/bin/env python3
import json, sys, shutil, subprocess
from pathlib import Path
from datetime import datetime

def _sev_map(v: str) -> str:
    v = (v or "").lower()
    return {"informational":"info","info":"info","low":"low","medium":"medium","high":"high"}.get(v, "info")

def parse_zap_json(path: Path):
    findings = []
    if not path.exists():
        return findings
    try:
        data = json.loads(path.read_text() or "{}")
        for site in data.get("site", []):
            for a in site.get("alerts", []):
                title = a.get("name","ZAP alert")
                risk = _sev_map((a.get("riskdesc") or "").split(" ")[0])
                insts = a.get("instances") or [{}]
                for inst in insts:
                    url = inst.get("uri") or site.get("@name")
                    fid = a.get("pluginid","zap-baseline")
                    findings.append({
                        "id": fid,
                        "title": title,
                        "description": a.get("desc",""),
                        "severity": risk,
                        "location": url,
                        "tool": "zap-baseline",
                        "cwe": [f"CWE-{a.get('cweid')}"] if a.get("cweid") not in (None,"-1") else None,
                        "tags": a.get("tags") or [],
                        "evidence": {"param": inst.get("param"), "evidence": inst.get("evidence")},
                    })
    except Exception:
        pass
    return findings

def main():
    try:
        m_input = json.loads(sys.stdin.read() or "{}")
    except Exception:
        m_input = {}
    target = m_input.get("target")
    # In docker mode, engine rewrites this to /zap/wrk
    art_dir = Path(m_input.get("artifacts_dir", "/zap/wrk"))
    art_dir.mkdir(parents=True, exist_ok=True)

    html_name = "zap-baseline.html"
    json_name = "zap-baseline.json"
    html_path = art_dir / html_name
    json_path = art_dir / json_name

    zap = shutil.which("zap-baseline.py") or "/usr/local/bin/zap-baseline.py"
    cmd = [zap, "-t", target, "-r", html_name, "-J", json_name, "-m", "3"]

    try:
        proc = subprocess.run(cmd, cwd=str(art_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.stdout, proc.stderr
        findings = parse_zap_json(json_path)
        status = "ok" if proc.returncode == 0 else "error"
        print(json.dumps({
            "status": status,
            "findings": findings,
            "artifacts": [
                {"path": str(html_path), "type": "html", "description": "ZAP Baseline HTML"},
                {"path": str(json_path), "type": "json", "description": "ZAP Baseline JSON"},
            ],
            "stdout": (stdout or "")[-4000:],
            "stderr": (stderr or "")[-4000:]
        }))
    except Exception as e:
        # Always return JSON on failure
        print(json.dumps({
            "status": "error",
            "error": f"zap exception: {e}",
            "findings": [],
            "artifacts": [],
        }))

if __name__ == "__main__":
    main()
