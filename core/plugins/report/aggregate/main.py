#!/usr/bin/env python3
import json, re, hashlib, pathlib, sys
from typing import List, Dict, Any

_OAST_TOKEN_RE = re.compile(r"\b([0-9a-f]{12})\b", re.I)

# ---------- helpers ----------
def _stable_hash(obj: Any) -> str:
    s = json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(s.encode()).hexdigest()

def _norm_location(f: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns {"url": <str|None>, "param": <str|None>} without assuming location type.
    Accepts:
      - f["location"] as str url
      - f["location"] as dict with url/path/target/value + param/name
      - fallbacks to f.request.url / f.asset / f.target
    """
    url = None
    param = None
    loc = f.get("location")
    if isinstance(loc, str):
        url = loc
    elif isinstance(loc, dict):
        url = loc.get("url") or loc.get("path") or loc.get("target") or loc.get("value")
        param = loc.get("param") or loc.get("name")

    # explicit fields
    param = f.get("param") or param

    # more fallbacks for URL
    if not url:
        req = f.get("request") or {}
        url = req.get("url") or f.get("asset") or f.get("target")

    return {"url": url, "param": param}

def _load_oast(workdir: pathlib.Path):
    callbacks_by_token, tokens_by_fp = {}, {}

    cb = workdir / "oast" / "callbacks.json"
    if cb.exists():
        try:
            payload = json.loads(cb.read_text() or "{}")
            for ev in payload.get("events", []):
                token = ev.get("unique_id") or ev.get("correlation_id") or ev.get("full_id")
                if not token:
                    m = _OAST_TOKEN_RE.search(json.dumps(ev, ensure_ascii=False))
                    token = m.group(1) if m else None
                if token:
                    callbacks_by_token.setdefault(token, []).append({
                        "ts": ev.get("timestamp"),
                        "protocol": ev.get("protocol") or ev.get("type"),
                        "remote_addr": ev.get("remote_address") or ev.get("ip"),
                        "raw": ev
                    })
        except Exception:
            pass

    tm = workdir / "oast" / "token_map.json"
    if tm.exists():
        try:
            bindings = json.loads(tm.read_text() or "{}").get("bindings", [])
            for b in bindings:
                fp = b.get("fp")
                tok = b.get("token")
                if fp and tok:
                    tokens_by_fp.setdefault(fp, []).append(tok)
        except Exception:
            pass
    return callbacks_by_token, tokens_by_fp

def _enrich_with_oast(findings: List[Dict[str, Any]], workdir: pathlib.Path):
    callbacks_by_token, tokens_by_fp = _load_oast(workdir)
    if not callbacks_by_token and not tokens_by_fp:
        return findings

    for f in findings:
        tokens = set()

        # token in evidence
        ev = f.get("evidence") or {}
        m = _OAST_TOKEN_RE.search(json.dumps(ev, ensure_ascii=False))
        if m:
            tokens.add(m.group(1))

        # token via request fingerprint
        req_fp = f.get("request_fp") or (f.get("debug") or {}).get("request_fp")
        if req_fp and req_fp in tokens_by_fp:
            tokens.update(tokens_by_fp[req_fp])

        hits = []
        for t in tokens:
            hits.extend(callbacks_by_token.get(t, []))

        if hits:
            srcs = set(f.get("sources") or [])
            srcs.add("oast")
            f["sources"] = sorted(srcs)
            f["oast"] = {"tokens": sorted(tokens), "hits": hits}
            if (f.get("confidence") or "").lower() in ("", "low", None):
                f["confidence"] = "medium"
    return findings

def _dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, out = set(), []
    for f in findings:
        loc = _norm_location(f)
        key_obj = {
            "type": f.get("type"),
            "title": f.get("title"),
            "url": loc["url"],
            "param": loc["param"],
            "evidence_sig": _stable_hash(f.get("evidence") or {}),
        }
        k = _stable_hash(key_obj)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
# ---------- /helpers ----------

def main():
    m_input = json.loads(sys.stdin.read() or "{}")
    workdir = pathlib.Path(m_input.get("workdir") or m_input.get("workspace_dir") or ".")
    prev = m_input.get("previous_outputs") or {}

    findings: List[Dict[str, Any]] = []
    for _, modres in prev.items():
        if isinstance(modres, dict):
            findings.extend(modres.get("findings") or [])

    findings = _enrich_with_oast(findings, workdir)
    findings = _dedupe(findings)

    out_path = workdir / "findings.json"
    out_path.write_text(json.dumps(findings, ensure_ascii=False, indent=2))

    print(json.dumps({
        "status": "ok",
        "findings": findings,
        "artifacts": [{
            "path": str(out_path),
            "type": "application/json",
            "description": "Merged & OAST-enriched findings"
        }],
        "stats": {"total_findings": len(findings)}
    }))

if __name__ == "__main__":
    main()
