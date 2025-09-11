#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aggregate findings from ZAP, Nuclei, sqlmap, and ffuf into a canonical list.

- Reads:
  workspace/zap/findings.json
  workspace/nuclei/findings.jsonl or findings.json
  workspace/sqlmap/findings.json
  workspace/ffuf/findings.json
- Writes:
  workspace/findings.json (canonical list)
  artifacts/aggregate-summary.json
  artifacts/aggregate-debug.log
- Stdout:
  {"status":"ok","counts":{"input":...,"output":...,"deduped":...},"artifacts":[...]}
- Stderr:
  human-readable logs
"""

import argparse, json, os, sys, hashlib, traceback, datetime, re
from urllib.parse import urlsplit, unquote, parse_qsl

ISO_NOW = lambda: datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

# ------------- CLI --------------

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True, help="Path to workspace/")
    ap.add_argument("--artifacts", required=True, help="Path to artifacts/")
    ap.add_argument("--configs", required=False, default="configs", help="Path to configs/")
    ap.add_argument("--debug", action="store_true")
    return ap.parse_args()

# ------------- Logging -----------

def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)

def log_debug(log_fp, msg):
    ts = ISO_NOW()
    line = f"[{ts}] {msg}\n"
    log_fp.write(line)
    log_fp.flush()
    eprint(msg)

# ------------- Normalization -----

def normalize_url(raw):
    sp = urlsplit(raw)
    scheme = (sp.scheme or "http").lower()
    host = (sp.hostname or "").rstrip(".").lower()
    port = sp.port or (443 if scheme == "https" else 80)
    # Path: decode once, collapse slashes, resolve simple dot segments
    path = unquote(sp.path or "/")
    path = re.sub(r"/{2,}", "/", path)
    # remove '/./'
    path = path.replace("/./", "/")
    if not path.startswith("/"):
        path = "/" + path
    # Query: sorted, decoded
    q = tuple(sorted([(unquote(k), unquote(v)) for (k, v) in parse_qsl(sp.query, keep_blank_values=True)]))
    return {
        "scheme": scheme, "host": host, "port": port,
        "path": path, "query_kv": list(q)
    }

def dedupe_key(norm, ftype, parameter_or_empty, include_query_when_no_param=True):
    # When parameter present (param findings), ignore query tuple to avoid oversplitting
    if parameter_or_empty:
        return (norm["host"], norm["path"], parameter_or_empty.lower(), ftype)
    if include_query_when_no_param:
        return (norm["host"], norm["path"], tuple(norm["query_kv"]), ftype)
    return (norm["host"], norm["path"], ftype)

def trim_evidence(s, limit=500):
    if not s:
        return None
    s = str(s)
    if len(s) <= limit:
        return s
    return s[:limit] + f"... [trimmed {len(s)-limit} chars]"

# ------------- Mappings ----------

SEVERITY_MAP = {
    "informational":"info","information":"info","info":"info","0":"info","trace":"info",
    "low":"low","1":"low",
    "medium":"medium","moderate":"medium","2":"medium",
    "high":"high","3":"high",
    "critical":"critical","4":"critical","5":"critical"
}
CONFIDENCE_MAP = {
    "possible":"low","tentative":"low","soft":"low","0":"low",
    "medium":"medium","suspicious":"medium","1":"medium",
    "firm":"high","confirmed":"high","2":"high",
    "certain":"certain","proof":"certain","exploited":"certain","3":"certain"
}

def map_severity(raw, default="medium"):
    if raw is None: return default
    v = str(raw).strip().lower()
    return SEVERITY_MAP.get(v, default)

def map_confidence(raw, default=None, tool=None, active=False):
    if raw:
        v = str(raw).strip().lower()
        if v in CONFIDENCE_MAP: return CONFIDENCE_MAP[v]
    # heuristic defaults
    if default: return default
    if tool == "sqlmap": return "certain"
    if tool == "nuclei": return "high" if active else "medium"
    if tool == "zap": return "medium"
    if tool == "ffuf": return "low"
    return "medium"

# Type mapping (extend as needed)
TYPE_PATTERNS = [
    (re.compile(r"xss", re.I), "xss.reflected"),
    (re.compile(r"open[_\- ]?redirect", re.I), "open_redirect"),
    (re.compile(r"sql[iI]", re.I), "sqli.confirmed"),
    (re.compile(r"\blfi\b", re.I), "lfi"),
    (re.compile(r"\bdir(listing|_listing)\b", re.I), "misconfig.dir_listing"),
    (re.compile(r"xxe", re.I), "xxe"),
    (re.compile(r"\brce\b|\bremote code\b", re.I), "rce"),
    (re.compile(r"csrf", re.I), "csrf"),
    (re.compile(r"sensitive|info[_\- ]?disclosure", re.I), "info.disclosure"),
]

def infer_type(tool, tool_id=None, name=None, tags=None):
    hay = " ".join([tool_id or "", name or "", " ".join(tags or [])])
    for rx, mapped in TYPE_PATTERNS:
        if rx.search(hay):
            return mapped
    if tool == "ffuf":
        return "fuzz.discovered_path"
    if tool == "sqlmap":
        return "sqli.confirmed"
    return "misc"

# ------------- Parsers per tool ---

def read_json_if_exists(p):
    if os.path.isfile(p):
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

def read_jsonl_if_exists(p):
    out = []
    if os.path.isfile(p):
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    return out

def parse_zap(ws):
    p = os.path.join(ws, "zap", "findings.json")
    data = read_json_if_exists(p) or []
    findings = []
    for it in data:
        # Expected ZAP common fields
        url = it.get("url") or it.get("uri") or ""
        method = it.get("method") or "GET"
        param = it.get("param") or it.get("parameter")
        loc = it.get("location") or ("query" if param else "response")
        raw_sev = it.get("risk") or it.get("severity")
        raw_conf = it.get("confidence")
        name = it.get("name") or it.get("alert")
        ftype = infer_type("zap", tool_id=str(it.get("pluginId")), name=name, tags=it.get("tags") or [])
        sev = map_severity(raw_sev, default="medium")
        conf = map_confidence(raw_conf, tool="zap")
        ev = it.get("evidence") or it.get("attack") or it.get("otherinfo") or ""
        findings.append({
            "tool":"zap",
            "tool_id": str(it.get("pluginId")),
            "name": name,
            "url": url,
            "method": method,
            "parameter": param,
            "location": loc,
            "severity": sev,
            "confidence": conf,
            "type": ftype,
            "evidence": ev,
            "tags": list(set((it.get("tags") or []) + ["web","zap"])),
            "timestamp": it.get("timestamp") or ISO_NOW(),
            "raw": it
        })
    return findings

def parse_nuclei(ws):
    # Support jsonl or json
    p_jsonl = os.path.join(ws, "nuclei", "findings.jsonl")
    p_json  = os.path.join(ws, "nuclei", "findings.json")
    data = read_jsonl_if_exists(p_jsonl) or (read_json_if_exists(p_json) or [])
    findings = []
    for it in data:
        url = it.get("matched-at") or it.get("url") or ""
        method = (it.get("request") or {}).get("method") or it.get("method") or "GET"
        name = it.get("template-id") or it.get("name")
        tags = (it.get("info") or {}).get("tags")
        sev_raw = (it.get("info") or {}).get("severity") or it.get("severity")
        ftype = infer_type("nuclei", tool_id=name, name=(it.get("info") or {}).get("name"), tags=(tags.split(",") if isinstance(tags, str) else tags or []))
        sev = map_severity(sev_raw, default="medium")
        conf = map_confidence(it.get("confidence"), tool="nuclei", active=True)
        param = None; loc = "response"
        ev = it.get("extracted-results") or it.get("matcher-name") or ""
        flat_tags = []
        if isinstance(tags, str): flat_tags = [t.strip() for t in tags.split(",") if t.strip()]
        elif isinstance(tags, list): flat_tags = tags
        findings.append({
            "tool":"nuclei",
            "tool_id": name,
            "name": (it.get("info") or {}).get("name") or name,
            "url": url,
            "method": method,
            "parameter": param,
            "location": loc,
            "severity": sev,
            "confidence": conf,
            "type": ftype,
            "evidence": json.dumps(it.get("extracted-results")) if isinstance(it.get("extracted-results"), list) else str(ev or "")[:500],
            "tags": list(set(flat_tags + ["web","nuclei"])),
            "timestamp": it.get("timestamp") or ISO_NOW(),
            "raw": it
        })
    return findings

def parse_sqlmap(ws):
    p = os.path.join(ws, "sqlmap", "findings.json")
    data = read_json_if_exists(p) or []
    findings = []
    for it in data:
        url = it.get("url") or ""
        method = it.get("method") or "GET"
        param = it.get("parameter")
        loc = it.get("location") or ("query" if param else "body")
        sev = "critical" if it.get("level") in (4,5) else "high"
        conf = "certain"
        name = it.get("title") or "SQL Injection"
        ev = it.get("payload") or it.get("proof") or ""
        findings.append({
            "tool":"sqlmap",
            "tool_id": str(it.get("id") or it.get("hash") or ""),
            "name": name,
            "url": url,
            "method": method,
            "parameter": param,
            "location": loc,
            "severity": sev,
            "confidence": conf,
            "type": "sqli.confirmed",
            "evidence": ev,
            "tags": ["web","sqlmap","injection","sqli"],
            "timestamp": it.get("timestamp") or ISO_NOW(),
            "raw": it
        })
    return findings

def parse_ffuf(ws):
    p = os.path.join(ws, "ffuf", "findings.json")
    data = read_json_if_exists(p) or []
    findings = []
    for it in data:
        url = it.get("url") or ""
        method = it.get("method") or "GET"
        param = it.get("parameter")  # may be None; ffuf often fuzzes path/query keys
        loc = it.get("location") or ("path" if not param else "query")
        code = it.get("status") or 200
        size = it.get("length") or it.get("words") or 0
        name = it.get("name") or "Fuzz discovery"
        # Severity heuristic: 200/204 on hidden paths => low; 30x maybe info; 401/403 medium
        if code in (401,403): sev = "medium"
        elif 200 <= code < 300: sev = "low"
        else: sev = "info"
        conf = "low"
        ev = it.get("payload") or it.get("value") or ""
        findings.append({
            "tool":"ffuf",
            "tool_id": str(it.get("id") or ""),
            "name": name,
            "url": url,
            "method": method,
            "parameter": param,
            "location": loc,
            "severity": sev,
            "confidence": conf,
            "type": "fuzz.discovered_path" if loc == "path" else "fuzz.param_discovery",
            "evidence": f"status={code}, size={size}, payload={ev}",
            "tags": ["web","ffuf","fuzzing"],
            "timestamp": it.get("timestamp") or ISO_NOW(),
            "raw": it
        })
    return findings

# ------------- Compliance --------

def load_crosswalks(cfg_root):
    out = {}
    files = {
        "pci_dss": os.path.join(cfg_root, "crosswalks", "pci.json"),
        "iso_27001": os.path.join(cfg_root, "crosswalks", "iso27001.json"),
        "gdpr": os.path.join(cfg_root, "crosswalks", "gdpr.json"),
    }
    for name, p in files.items():
        try:
            if os.path.isfile(p):
                with open(p, "r", encoding="utf-8") as f:
                    out[name] = json.load(f)
        except Exception:
            pass
    return out

def crosswalk_types_to_clauses(ftype, crosswalks):
    res = {}
    for scheme, doc in crosswalks.items():
        rules = doc.get("rules", {})
        # exact or prefix wildcard match
        clauses = set()
        for k, v in rules.items():
            if k.endswith(".*"):
                if ftype.startswith(k[:-2]):
                    clauses.update(v)
            elif k == ftype:
                clauses.update(v)
        if clauses:
            res[scheme] = sorted(clauses)
    return res

# ------------- Core pipeline -----

def canonicalize(f):
    # Build canonical structure + norm + id
    norm = normalize_url(f["url"])
    key = dedupe_key(norm, f["type"], f.get("parameter") or "")
    # Deterministic id: sha1 over tuple repr
    h = hashlib.sha1(repr((key, f["method"].upper(), f.get("location"))).encode("utf-8")).hexdigest()
    canon = {
        "id": f"sha1:{h}",
        "type": f["type"],
        "url": f["url"],
        "norm": norm,
        "method": f["method"].upper(),
        "parameter": f.get("parameter"),
        "location": f.get("location") or None,
        "severity": f["severity"],
        "confidence": f["confidence"],
        "sources": [{"tool": f["tool"], "id": f.get("tool_id",""), "raw_severity": (f.get("raw") or {}).get("severity") or ""}],
        "evidence": trim_evidence(f.get("evidence")),
        "tags": sorted(list(set(f.get("tags") or []))),
        "timestamp": f.get("timestamp") or ISO_NOW(),
        "compliance": {}
    }
    return canon, key

def merge_into(dest, src):
    # Merge sources, bump severity/confidence to the max
    dest["sources"].extend(src["sources"])
    dest["tags"] = sorted(list(set((dest.get("tags") or []) + (src.get("tags") or []))))
    # Severity order
    sev_order = ["info","low","medium","high","critical"]
    if sev_order.index(src["severity"]) > sev_order.index(dest["severity"]):
        dest["severity"] = src["severity"]
    conf_order = ["low","medium","high","certain"]
    if conf_order.index(src["confidence"]) > conf_order.index(dest["confidence"]):
        dest["confidence"] = src["confidence"]
    # Prefer non-empty evidence (first is fine; avoid bloat)
    if not dest.get("evidence") and src.get("evidence"):
        dest["evidence"] = src["evidence"]

def main():
    args = parse_args()
    ws = args.workspace
    arts = args.artifacts
    os.makedirs(arts, exist_ok=True)
    dbg_path = os.path.join(arts, "aggregate-debug.log")
    sum_path = os.path.join(arts, "aggregate-summary.json")
    out_path = os.path.join(ws, "findings.json")

    with open(dbg_path, "a", encoding="utf-8") as log_fp:
        try:
            log_debug(log_fp, "Aggregator start")

            inputs = []
            for parser, name in [(parse_zap,"zap"), (parse_nuclei,"nuclei"), (parse_sqlmap,"sqlmap"), (parse_ffuf,"ffuf")]:
                try:
                    fs = parser(ws)
                    log_debug(log_fp, f"Loaded {len(fs)} from {name}")
                    inputs.extend(fs)
                except Exception as e:
                    log_debug(log_fp, f"Parser {name} error: {e}")

            crosswalks = load_crosswalks(args.configs)
            log_debug(log_fp, f"Crosswalks loaded: {list(crosswalks.keys())}")

            registry = {}   # key -> canonical finding
            key_map = {}    # key -> list of ids (for summary)

            for f in inputs:
                try:
                    # Fill defaults
                    f["type"] = f.get("type") or infer_type(f.get("tool"), f.get("tool_id"), f.get("name"), f.get("tags"))
                    f["severity"] = map_severity(f.get("severity"), default="medium")
                    f["confidence"] = map_confidence(f.get("confidence"), tool=f.get("tool"))
                    canon, key = canonicalize(f)
                    # apply compliance
                    canon["compliance"] = crosswalk_types_to_clauses(canon["type"], crosswalks)
                    if key in registry:
                        merge_into(registry[key], canon)
                    else:
                        registry[key] = canon
                    key_map.setdefault(key, []).append(canon["id"])
                except Exception as e:
                    log_debug(log_fp, f"Finding error: {e}\n{traceback.format_exc()}")

            findings = sorted(registry.values(), key=lambda x: (x["severity"], x["type"], x["url"]))
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2, ensure_ascii=False)

            summary = {
                "started_at": ISO_NOW(),
                "input_count": len(inputs),
                "unique_count": len(findings),
                "by_severity": {k: sum(1 for i in findings if i["severity"]==k) for k in ["critical","high","medium","low","info"]},
                "by_type_top": sorted(
                    ((t, sum(1 for i in findings if i["type"]==t)) for t in sorted(set(i["type"] for i in findings))),
                    key=lambda kv: kv[1], reverse=True)[:10],
                "artifacts": {
                    "workspace_findings": out_path,
                    "aggregate_debug_log": dbg_path,
                    "aggregate_summary": sum_path
                }
            }
            with open(sum_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)

            print(json.dumps({
                "status":"ok",
                "counts":{"input": len(inputs), "output": len(findings), "deduped": len(inputs)-len(findings)},
                "artifacts":[out_path, sum_path, dbg_path]
            }))
            log_debug(log_fp, "Aggregator done")
        except Exception as e:
            err = {"status":"error","message":str(e)}
            print(json.dumps(err))
            eprint("FATAL:", e)
            sys.exit(1)

if __name__ == "__main__":
    main()
