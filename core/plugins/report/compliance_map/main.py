#!/usr/bin/env python3
import sys, json, re

# Minimal default crosswalks; extend via configs later
RULES = [
  # type_pattern (regex), tags
  (r"sqli", {"cwe":"89","owasp":"A03:2021","pci":["6.5.1","6.6"],"gdpr":[]}),
  (r"xss",  {"cwe":"79","owasp":"A03:2021","pci":["6.5.7","6.6"],"gdpr":[]}),
  (r"rce|command\.inj", {"cwe":"78","owasp":"A03:2021","pci":["6.5","6.6"],"gdpr":["32"]}),
  (r"ssrf", {"cwe":"918","owasp":"A10:2021","pci":["1.3.7","6.4"],"gdpr":["25","32"]}),
  (r"xxe",  {"cwe":"611","owasp":"A05:2021","pci":["6.5.XX"],"gdpr":["32"]}),
]

def annotate(f):
    t = (f.get("type") or f.get("title") or "").lower()
    for pat, tags in RULES:
        if re.search(pat, t):
            c = f.setdefault("compliance", {})
            c.setdefault("pci", []).extend(tags["pci"])
            c.setdefault("gdpr", []).extend(tags["gdpr"])
            c.setdefault("cwe", tags["cwe"])
            c.setdefault("owasp", tags["owasp"])
            # make lists unique
            c["pci"] = sorted(set(c["pci"]))
            c["gdpr"] = sorted(set(c["gdpr"]))
            break
    return f

def main():
    m_input = json.loads(sys.stdin.read() or "{}")
    findings = []
    prev = m_input.get("previous_outputs") or {}
    for _, modres in prev.items():
        if isinstance(modres, dict):
            findings.extend(modres.get("findings") or [])

    findings = [annotate(dict(f)) for f in findings]

    print(json.dumps({
        "status":"ok",
        "findings": findings,
        "artifacts": [],
        "stats": {"annotated": len(findings)}
    }))

if __name__ == "__main__":
    main()
