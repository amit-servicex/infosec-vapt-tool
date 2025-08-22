#!/usr/bin/env python3
import json
from pathlib import Path
from collections import Counter

def main():
    m_input = json.loads(input() or "{}")
    findings = []
    for _, modres in (m_input.get("previous_outputs") or {}).items():
        if isinstance(modres, dict):
            findings.extend(modres.get("findings") or [])

    reports_dir = Path(m_input.get("reports_dir","reports"))
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_html = reports_dir / "report.html"

    # Try Jinja writer; fallback simple HTML if not available
    try:
        from core.reporting.writers.html_writer import write_html
        from pathlib import Path as _P
        tpl_dir = _P(__file__).resolve().parents[2] / "templates"
        write_html(findings, tpl_dir, out_html, context={"generated_by":"report.html module"})
    except Exception:
        # minimal fallback
        rows = "".join(
            f"<tr><td>{f.get('severity','info')}</td><td>{f.get('title','')}</td>"
            f"<td>{f.get('tool','')}</td><td>{f.get('location','')}</td>"
            f"<td>{f.get('description','')}</td></tr>" for f in findings
        )
        out_html.write_text(
            "<html><body><h1>Findings</h1>"
            "<table border='1' cellpadding='6' cellspacing='0'>"
            "<tr><th>Severity</th><th>Title</th><th>Tool</th><th>Location</th><th>Description</th></tr>"
            f"{rows}</table></body></html>"
        )

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
