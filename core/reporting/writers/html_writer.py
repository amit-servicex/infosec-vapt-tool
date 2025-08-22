def write(data, path):
    html = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>VAPT Report</title>
<style>body{{font-family:system-ui,Arial,sans-serif;margin:24px}} .sev{{padding:2px 6px;border-radius:6px}} .h{{background:#fee}} .m{{background:#ffe}} .l{{background:#efe}}</style>
</head><body>
<h1>VAPT Report</h1>
<p>Total findings: {len(data.get('findings', []))}</p>
<table border="1" cellspacing="0" cellpadding="6">
<tr><th>Severity</th><th>Title</th><th>Location</th><th>Tool</th></tr>
{''.join(f"<tr><td><span class='sev'>{f.get('severity','')}</span></td><td>{f.get('title','')}</td><td>{f.get('location','')}</td><td>{f.get('tool','')}</td></tr>" for f in data.get('findings', []))}
</table>
</body></html>"""
    open(path, "w", encoding="utf-8").write(html)
