#!/usr/bin/env python3
import json, subprocess, shutil
from pathlib import Path

def main():
    m_input = json.loads(input())
    target = m_input["target"]
    art_dir = Path(m_input["artifacts_dir"])
    art_dir.mkdir(parents=True, exist_ok=True)
    out_json = art_dir / "nuclei.jsonl"

    findings = []

    nuclei = shutil.which("nuclei")
    if nuclei:
        cmd = [nuclei, "-u", target, "-json"]
        with open(out_json, "w") as f:
            subprocess.run(cmd, stdout=f, check=False)
        # parse jsonl
        for line in out_json.read_text().splitlines():
            try:
                obj = json.loads(line)
                findings.append({
                    "id": obj.get("template-id") or obj.get("templateID","nuclei-issue"),
                    "title": obj.get("info",{}).get("name","Nuclei finding"),
                    "description": obj.get("matcher-name",""),
                    "severity": obj.get("info",{}).get("severity","info"),
                    "location": obj.get("host"),
                    "tags": obj.get("info",{}).get("tags",[]),
                    "tool": "nuclei",
                })
            except Exception:
                continue
    else:
        # dev stub
        out_json.write_text("")
        findings.append({
            "id": "nuclei-stub",
            "title": "Nuclei not installed",
            "description": "Running in stub mode.",
            "severity": "info",
            "tool": "nuclei"
        })

    payload = {
        "status": "ok",
        "findings": findings,
        "artifacts": [{
            "path": str(out_json),
            "type": "json",
            "description": "Nuclei raw output (JSONL)"
        }],
    }
    print(json.dumps(payload))

if __name__ == "__main__":
    main()
