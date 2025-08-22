from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from collections import Counter

def write_html(findings, template_dir: Path, out_path: Path, context=None):
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"])
    )
    tpl = env.get_template("report.html.j2")
    sev_counts = Counter([f.get("severity","info") for f in findings])
    html = tpl.render(findings=findings, sev_counts=sev_counts, extra=(context or {}))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    return out_path
