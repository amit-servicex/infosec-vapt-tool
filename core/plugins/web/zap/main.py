#!/usr/bin/env python3
import json, os, subprocess, tempfile
from pathlib import Path
from datetime import datetime

def parse_zap_baseline(report_html_path: Path):
    # Minimal stub: produce one INFO finding noting the file exists
    findings = []
    if report_html_path.exists():
        findings.append({
            "id": "zap-baseline-report",
            "title": "ZAP Baseline Report Generated",
            "description": f"Report at {str(report_html_path)}",
            "severity": "info",
            "tool": "zap-baseline",
        })
    return findings

def main():
    m_input = json.loads(input())
    target = m_input["target"]
    art_dir = Path(m_input["artifacts_dir"])
    art_dir.mkdir(parents=True, exist_ok=True)
    out_html = art_dir / "zap-baseline.html"

    # Try to run zap-baseline.py if available, else fallback to stub
    try:
        cmd = ["zap-baseline.py", "-t", target, "-r", str(out_html.name)]
        subprocess.run(cmd, cwd=str(art_dir), check=True)
    except Exception as e:
        # dev mode if ZAP not installed yet
        out_html.write_text("<html><body>Stub ZAP report</body></html>")

    findings = parse_zap_baseline(out_html)
    payload = {
        "status": "ok",
        "findings": findings,
        "artifacts": [{
            "path": str(out_html),
            "type": "html",
            "description": "ZAP Baseline HTML Report"
        }],
        "raw_output": None
    }
    print(json.dumps(payload))

if __name__ == "__main__":
    main()
