#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compliance Expert Agent
- Reads canonical findings (workspace/findings.json) produced by your aggregator
- Loads compliance packs (configs/crosswalks/*.json) with rules
- Applies deterministic rules + heuristics to assign clauses with rationale & confidence
- Writes workspace/findings.enriched.json
- Writes artifacts/compliance-expert-summary.json and artifacts/compliance-expert-debug.log
- Stdout: {"status":"ok", "counts": {...}, "artifacts": [...]}

Python 3, stdlib only.
"""

import argparse, json, os, sys, traceback, datetime, re, fnmatch
from collections import defaultdict

ISO_NOW = lambda: datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

SEV_ORDER = ["info","low","medium","high","critical"]

def eprint(*a, **k): print(*a, file=sys.stderr, **k)

def log(fp, msg):
    fp.write(f"[{ISO_NOW()}] {msg}\n"); fp.flush()
    eprint(msg)

def read_json(path):
    if not os.path.isfile(path): return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def score_from_severity(sev:str)->float:
    try: return SEV_ORDER.index(sev) / (len(SEV_ORDER)-1)  # 0..1
    except: return 0.5

def confidence_label(x: float)->str:
    # 0..1 -> low/medium/high/certain
    if x >= 0.85: return "certain"
    if x >= 0.65: return "high"
    if x >= 0.40: return "medium"
    return "low"

def normalize_list(x):
    if not x: return []
    if isinstance(x, str): return [x]
    return list(x)

# ---------- Rule Evaluation ----------

def match_any(globs, value):
    if value is None: return False
    for g in globs:
        if fnmatch.fnmatch(str(value).lower(), g.lower()):
            return True
    return False

def evidence_matches(patterns, evidence, url):
    text = ((evidence or "") + " " + (url or "")).lower()
    for pat in patterns:
        try:
            if re.search(pat, text, re.I): return True
        except re.error:
            # bad regex -> ignore
            continue
    return False

def load_packs(cfg_root):
    """Load compliance packs (supports simple {rules:{type->clauses}} and advanced DSL {rules:[...]})"""
    paths = {
        "pci_dss"  : os.path.join(cfg_root, "crosswalks", "pci.json"),
        "iso_27001": os.path.join(cfg_root, "crosswalks", "iso27001.json"),
        "gdpr"     : os.path.join(cfg_root, "crosswalks", "gdpr.json"),
    }
    packs = {}
    for k,p in paths.items():
        try:
            obj = read_json(p)
            if obj: packs[k]=obj
        except Exception:
            pass
    return packs

def fire_rules(framework_name, pack, finding):
    """
    Supports two shapes:
    1) Simple dict:
       { "rules": { "sqli.*": ["6.5.1","11.3"], "xss.*": ["6.5.7"] } }
       -> matches finding['type'] with glob, yields clauses with default weight 1.0

    2) DSL list:
       {
         "rules": [
            {"when":{"type":["sqli.*"], "tags":["injection"], "evidence_regex":["union select"]},
             "then":{"clauses":["6.5.1"], "weight":2.0, "reason":"SQLi evidence present"}}
         ]
       }
    """
    out_clauses = defaultdict(float)  # clause -> score
    fired = []  # explanations

    rules = pack.get("rules", {})
    ftype = (finding.get("type") or "").lower()
    tags  = [t.lower() for t in finding.get("tags") or []]
    sev   = finding.get("severity") or "medium"
    evidence = finding.get("evidence") or ""
    url   = finding.get("url") or ""

    base = score_from_severity(sev) * 0.5  # base confidence contribution
    base_reason = f"Base severity contribution ({sev})"
    # Add base to a virtual clause score bucket (not a real clause)
    # We'll add it to every fired clause later.

    if isinstance(rules, dict):
        # simple mapping: type-glob -> [clauses]
        for glob_pat, clauses in rules.items():
            if match_any([glob_pat], ftype):
                w = 1.0
                for c in normalize_list(clauses):
                    out_clauses[c] += w
                    fired.append({"framework":framework_name,"clause":c,"reason":f"type matches '{glob_pat}'","weight":w})
    elif isinstance(rules, list):
        # DSL rules
        for r in rules:
            cond = r.get("when", {})
            act  = r.get("then", {})
            weight = float(act.get("weight", 1.0))
            reason = act.get("reason", "rule matched")

            ok = True
            if "type" in cond:      ok = ok and match_any(normalize_list(cond["type"]), ftype)
            if "tags" in cond:      ok = ok and any(match_any(normalize_list(cond["tags"]), t) for t in tags)
            if "location" in cond:  ok = ok and match_any(normalize_list(cond["location"]), finding.get("location") or "")
            if "parameter" in cond: ok = ok and match_any(normalize_list(cond["parameter"]), finding.get("parameter") or "")
            if "evidence_regex" in cond: ok = ok and evidence_matches(normalize_list(cond["evidence_regex"]), evidence, url)
            if "path_regex" in cond:
                try:
                    ok = ok and re.search(cond["path_regex"], finding.get("norm",{}).get("path",""), re.I) is not None
                except re.error:
                    pass

            if ok:
                for c in normalize_list(act.get("clauses", [])):
                    out_clauses[c] += weight
                    fired.append({"framework":framework_name,"clause":c,"reason":reason,"weight":weight})

    # add base contribution to any clause that fired
    if fired:
        for c in list(out_clauses.keys()):
            out_clauses[c] += base
            fired.append({"framework":framework_name,"clause":c,"reason":base_reason,"weight":round(base,3)})

    return out_clauses, fired

def enrich_findings(findings, packs, log_fp):
    total = len(findings)
    updated = 0
    for f in findings:
        try:
            per_fw = {}
            rationale = []
            for fw_name, pack in packs.items():
                clauses, fired = fire_rules(fw_name, pack, f)
                if clauses:
                    # pick sorted by score desc
                    ranked = sorted(clauses.items(), key=lambda kv: kv[1], reverse=True)
                    # confidence from top score capped at 1.0
                    top = ranked[0][1]
                    conf = confidence_label(min(1.0, top/2.5))  # simple scaling
                    per_fw[fw_name] = {
                        "clauses": [c for (c,_) in ranked],
                        "confidence": conf,
                        "scores": {c: round(s,3) for c,s in ranked}
                    }
                    rationale.extend([x for x in fired])
            # Stitch into finding
            f.setdefault("compliance", {}).update(per_fw)
            f.setdefault("expert", {})
            if rationale:
                f["expert"]["rationale"] = rationale  # explicit why
            updated += 1
        except Exception as e:
            log(log_fp, f"enrich error on {f.get('id','<noid>')}: {e}\n{traceback.format_exc()}")
    return updated, total

def collect_evidence_refs(f):
    """
    Build a tiny evidence reference block to help auditors find proof quickly.
    (No external fetches. We rely on existing fields/artifacts.)
    """
    refs = {
        "url": f.get("url"),
        "method": f.get("method"),
        "parameter": f.get("parameter"),
        "location": f.get("location"),
        "sources": f.get("sources", []),
        "snippet": (f.get("evidence") or "")[:180]
    }
    return refs

def add_evidence_refs(findings):
    for f in findings:
        f.setdefault("expert", {})
        f["expert"]["evidence_refs"] = collect_evidence_refs(f)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--artifacts", required=True)
    ap.add_argument("--configs", default="configs")
    ap.add_argument("--input", default=None, help="Override input findings path")
    ap.add_argument("--output", default=None, help="Override output enriched path")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    ws = args.workspace
    arts = args.artifacts
    os.makedirs(arts, exist_ok=True)
    dbg = os.path.join(arts, "compliance-expert-debug.log")
    summ = os.path.join(arts, "compliance-expert-summary.json")

    input_path  = args.input or os.path.join(ws, "findings.json")
    output_path = args.output or os.path.join(ws, "findings.enriched.json")

    with open(dbg, "a", encoding="utf-8") as log_fp:
        try:
            log(log_fp, "Compliance Expert Agent start")
            findings = read_json(input_path) or []
            if not isinstance(findings, list):
                raise ValueError("input findings must be a JSON array")
            packs = load_packs(args.configs)
            if not packs:
                log(log_fp, "WARNING: no crosswalk packs loaded; output will equal input with evidence refs only")

            updated, total = enrich_findings(findings, packs, log_fp)
            add_evidence_refs(findings)
            write_json(output_path, findings)

            # Summary
            by_fw = defaultdict(int)
            for f in findings:
                for fw in (f.get("compliance") or {}).keys():
                    by_fw[fw]+=1
            summary = {
                "started_at": ISO_NOW(),
                "input_count": total,
                "enriched_count": updated,
                "framework_coverage": by_fw,
                "artifacts": {
                    "enriched_findings": output_path,
                    "debug_log": dbg
                }
            }
            write_json(summ, summary)
            print(json.dumps({"status":"ok","counts":{"input":total,"enriched":updated},"artifacts":[output_path, summ, dbg]}))
            log(log_fp, "Compliance Expert Agent done")
        except Exception as e:
            err = {"status":"error","message":str(e)}
            print(json.dumps(err))
            eprint("FATAL:", e)
            sys.exit(1)

if __name__ == "__main__":
    main()
