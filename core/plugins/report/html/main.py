#!/usr/bin/env python3
import json, sys
from pathlib import Path

def main():
    m_input = json.loads(sys.stdin.read() or "{}")
    findings = []
    for _, modres in (m_input.get("previous_outputs") or {}).items():
        if isinstance(modres, dict):
            findings.extend(modres.get("findings") or [])

    # Where to write
    workdir = Path(m_input.get("workdir","workspace"))
    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_html = reports_dir / "report.html"

    # Template dir (defaults to your reporting/templates/)
    template_dir = Path(m_input.get("inputs", {}).get("template_dir", "reporting/templates"))

    # Use your existing writer
    from reporting.writers.html_writer import write_html
    write_html(findings, template_dir=template_dir, out_path=out_html, context={
        "title": "VAPT Attack Report",
        "run_id": m_input.get("run_id"),
    })

    print(json.dumps({
        "status": "ok",
        "findings": [],
        "artifacts": [{
            "path": str(out_html),
            "type": "html",
            "description": "Consolidated HTML report"
        }]
    }))

if __name__ == "__main__":
    main()
