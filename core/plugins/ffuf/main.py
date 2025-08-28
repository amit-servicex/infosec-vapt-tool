#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json, sys, os, re, shutil, subprocess, uuid, time, tempfile, urllib.parse, statistics
from datetime import datetime

# ---------- Utilities ----------

def log(msg, debug_fp):
    ts = datetime.utcnow().isoformat()
    line = f"[web.ffuf] {ts} {msg}\n"
    debug_fp.write(line)
    debug_fp.flush()

def ensure_dirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)

def load_stdin_module_input():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return {}
        return json.loads(raw)
    except Exception:
        return {}

def which_ffuf():
    return shutil.which("ffuf")

def docker_cmd(image, workdir, extra_docker_args=None):
    absw = os.path.abspath(workdir)
    cmd = ["docker", "run", "--rm",
           "-v", f"{absw}:{absw}",
           "-w", absw]
    if extra_docker_args:
        cmd += list(extra_docker_args)
    cmd += [image, "ffuf"]
    return cmd


def safe_json_load(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def safe_json_dump(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [x.strip() for x in f if x.strip()]
    except Exception:
        return []

def parse_query_params(url):
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    # q: {param: [value1, ...]}
    params = {k: (v[0] if v else "") for k,v in q.items()}
    return params

def replace_query_value(url, key, new_value):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[key] = [new_value]
    new_query = urllib.parse.urlencode([(k, v[0] if isinstance(v, list) else v) for k,v in qs.items()], doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))

def build_post_body_with_fuzz(body_str, mapping):
    # body like "a=1&b=2" -> replace a/b values per mapping
    pairs = urllib.parse.parse_qsl(body_str, keep_blank_values=True)
    out = []
    for k,v in pairs:
        if k in mapping:
            out.append((k, mapping[k]))
        else:
            out.append((k, v))
    return urllib.parse.urlencode(out)

def guess_body_from_candidate(c):
    # Accept raw string body or dict; normalize to "k=v&..."
    body = c.get("body")
    if body is None:
        return None
    if isinstance(body, str):
        return body
    if isinstance(body, dict):
        return urllib.parse.urlencode([(k, str(v)) for k,v in body.items()])
    return None

# ---------- Candidate harvesting ----------

def harvest_from_zap(workdir, debug_fp):
    # best-effort: workspace/zap/findings.json (your pipeline emits this)
    zap_path = os.path.join(workdir, "workspace", "zap", "findings.json")
    data = safe_json_load(zap_path, default=[])
    out = []
    for item in data:
        url = item.get("url") or item.get("evidence", {}).get("url")
        method = (item.get("method") or "GET").upper()
        if not url:
            continue
        body = item.get("requestBody")
        out.append({"method": method, "url": url, "body": body})
    log(f"harvest_from_zap: {len(out)} candidates", debug_fp)
    return out

def harvest_from_nuclei(workdir, debug_fp):
    # common artifact path from your Week-1 notes
    # try artifacts/nuclei.jsonl (raw) or workspace/nuclei/findings.json
    paths = [
        os.path.join(workdir, "artifacts", "nuclei.jsonl"),
        os.path.join(workdir, "workspace", "nuclei", "findings.json")
    ]
    out = []
    count = 0
    for p in paths:
        if not os.path.exists(p): 
            continue
        if p.endswith(".jsonl"):
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line: 
                        continue
                    try:
                        j = json.loads(line)
                    except Exception:
                        continue
                    url = j.get("matched-at") or j.get("host") or j.get("url")
                    if url:
                        out.append({"method": "GET", "url": url})
                        count += 1
        else:
            j = safe_json_load(p, default=[])
            for item in j:
                url = item.get("url")
                if url:
                    out.append({"method": "GET", "url": url})
                    count += 1
    log(f"harvest_from_nuclei: {count} candidates", debug_fp)
    return out

def normalize_candidates(inputs, workdir, debug_fp):
    cands = []
    # 1) explicit candidates
    explicit = inputs.get("candidates") or []
    for c in explicit:
        if isinstance(c, str):
            cands.append({"method": "GET", "url": c})
        elif isinstance(c, dict) and c.get("url"):
            m = (c.get("method") or "GET").upper()
            cands.append({"method": m, "url": c["url"], "body": c.get("body")})
    # 2) from sources
    sources = set([s.lower() for s in (inputs.get("candidates_from") or [])])
    if "zap" in sources:
        cands.extend(harvest_from_zap(workdir, debug_fp))
    if "nuclei" in sources:
        cands.extend(harvest_from_nuclei(workdir, debug_fp))
    # 3) base_urls fallback
    for u in (inputs.get("base_urls") or []):
        cands.append({"method": "GET", "url": u})

    # Dedup by (method,url,body)
    seen = set()
    uniq = []
    for c in cands:
        key = (c["method"], c["url"], json.dumps(c.get("body"), sort_keys=True) if isinstance(c.get("body"), dict) else c.get("body"))
        if key in seen: 
            continue
        seen.add(key)
        uniq.append(c)
    return uniq

# ---------- FUZZ target builders ----------

def build_sniper_targets(candidate):
    """
    Return a list of ffuf invocations (each with its own URL/body having a single FUZZ placeholder)
    """
    method = candidate["method"]
    url = candidate["url"]
    targets = []

    # Query params
    qparams = parse_query_params(url)
    for key in qparams.keys():
        fu_url = replace_query_value(url, key, "FUZZ")
        targets.append({"method": method, "url": fu_url, "param": key, "location": "query"})

    # Body params for POST/PUT/PATCH (application/x-www-form-urlencoded assumed for fuzzing)
    if method in ("POST","PUT","PATCH"):
        body_str = guess_body_from_candidate(candidate) or ""
        if body_str:
            body_params = dict(urllib.parse.parse_qsl(body_str, keep_blank_values=True))
            for key in body_params.keys():
                fu_body = build_post_body_with_fuzz(body_str, {key: "FUZZ"})
                targets.append({"method": method, "url": url, "param": key, "location": "body", "body": fu_body})
    return targets

def build_clusterbomb_target(candidate, max_slots, reuse_same_wordlists):
    """
    Build ONE clusterbomb target per candidate.
    We’ll place FUZZ, FUZZ2, FUZZ3 ... in each param up to max_slots.
    """
    method = candidate["method"]
    url = candidate["url"]
    mapping = {}
    param_names = []

    # Take query first
    qparams = parse_query_params(url)
    for k in qparams.keys():
        param_names.append(("query", k))
    # Then body (for POST-like)
    body_str = None
    if method in ("POST","PUT","PATCH"):
        body_str = guess_body_from_candidate(candidate) or ""
        if body_str:
            bparams = dict(urllib.parse.parse_qsl(body_str, keep_blank_values=True))
            for k in bparams.keys():
                param_names.append(("body", k))

    # cap to max_slots
    param_names = param_names[:max_slots]
    if not param_names:
        return None

    # assign FUZZ placeholders
    placeholders = []
    for i, (_loc, _k) in enumerate(param_names, start=1):
        placeholders.append("FUZZ" if i == 1 else f"FUZZ{i}")

    # build mutated url/body
    new_url = url
    if qparams:
        for i, (loc, k) in enumerate(param_names, start=1):
            if loc != "query": continue
            ph = "FUZZ" if i == 1 else f"FUZZ{i}"
            new_url = replace_query_value(new_url, k, ph)

    new_body = body_str
    if body_str:
        bmapping = {}
        for i, (loc, k) in enumerate(param_names, start=1):
            if loc != "body": continue
            ph = "FUZZ" if i == 1 else f"FUZZ{i}"
            bmapping[k] = ph
        if bmapping:
            new_body = build_post_body_with_fuzz(body_str, bmapping)

    return {
        "method": method,
        "url": new_url,
        "body": new_body,
        "locations": param_names,   # list of (location, name)
        "placeholders": placeholders,
        "reuse_same_wordlists": reuse_same_wordlists
    }

# ---------- ffuf runner ----------

def run_ffuf(job, wordlists, mode, rate, threads, timeout_sec, filters, matchers, extra_args, ffuf_bin, docker_image, artifacts_dir, debug_fp):
    """
    job:
      sniper: {method,url,param,location,body?}
      clusterbomb: {method,url,body?, placeholders[], reuse_same_wordlists}
    Returns output json path (string) or None
    """
    out_json = os.path.join(artifacts_dir, f"ffuf-{uuid.uuid4().hex}.json")
    cmd = []

    if ffuf_bin:
        cmd = [ffuf_bin]
    else:
        cmd = docker_cmd(docker_image)
        cmd += ["ffuf"]  # container entrypoint

    cmd += ["-of", "json", "-o", out_json, "-rate", str(rate), "-t", str(threads), "-timeout", str(timeout_sec)]
    # method
    if job.get("method", "GET") != "GET":
        cmd += ["-X", job["method"]]

    # URL/body
    cmd += ["-u", job["url"]]
    if job.get("body"):
        cmd += ["-d", job["body"]]
        # Assume form content-type unless overridden by extra_args
        cmd += ["-H", "Content-Type: application/x-www-form-urlencoded"]

    # Mode & wordlists
    if mode == "sniper":
        # single FUZZ
        wl = wordlists[0] if wordlists else "configs/wordlists/quick.txt"
        cmd += ["-w", wl]
        # optional: -mode sniper (ffuf defaults are replaced-based; explicit is fine)
        cmd += ["-mode", "sniper"]
    else:
        # clusterbomb
        placeholders = job["placeholders"]
        # ffuf understands multiple wordlists; placeholders are FUZZ, FUZZ2, ...
        # attach :<KEY> (the placeholder) to each -w
        if not wordlists:
            wordlists = ["configs/wordlists/quick.txt"] * len(placeholders)
        elif len(wordlists) < len(placeholders) and job.get("reuse_same_wordlists", True):
            # reuse last for remaining
            last = wordlists[-1]
            wordlists = wordlists + [last] * (len(placeholders) - len(wordlists))
        for i, ph in enumerate(placeholders):
            wl = wordlists[i]
            cmd += ["-w", f"{wl}:{ph}"]
        cmd += ["-mode", "clusterbomb"]

    # Filters & matchers (pass-through)
    for tok in (filters or []):
        cmd.append(tok)
    for tok in (matchers or []):
        cmd.append(tok)
    for tok in (extra_args or []):
        cmd.append(tok)

    log(f"Running ffuf: {' '.join(cmd)}", debug_fp)

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        if proc.stdout:
            debug_fp.write(proc.stdout + ("\n" if not proc.stdout.endswith("\n") else ""))
        rc = proc.returncode
        if rc not in (0,):
            log(f"ffuf non-zero exit: {rc}", debug_fp)
        # ffuf writes JSON even on no-matches; ensure file exists
        if not os.path.exists(out_json):
            # Create an empty valid structure
            safe_json_dump({"results": [], "meta": {"cmd": cmd}}, out_json)
        return out_json
    except Exception as e:
        log(f"ffuf run failed: {e}", debug_fp)
        return None

# ---------- Post-processing & findings ----------

def compute_anomaly_flags(results):
    """
    Given ffuf result entries (each has status, words, lines, length), mark anomalies compared to median.
    """
    if not results:
        return {}
    metrics = {"status": [], "length": [], "words": [], "lines": []}
    for r in results:
        for k in metrics.keys():
            v = r.get(k)
            if isinstance(v, int):
                metrics[k].append(v)
    med = {}
    for k, arr in metrics.items():
        if arr:
            try:
                med[k] = int(statistics.median(arr))
            except Exception:
                med[k] = None
        else:
            med[k] = None
    return med

SQLI_HINTS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql",
    "postgresql",
    "sqlite",
    "odbc",
    "oracle",
    "syntax error",
    "fatal error"
]

def likely_sqli(entry):
    # ffuf JSON doesn’t include body; rely on title/banner if present and size jumps
    title = (entry.get("redirectlocation") or "") + " " + (entry.get("url") or "")
    title = title.lower()
    if any(h in title for h in SQLI_HINTS):
        return True
    # if status is 500 and huge size jump, flag
    if entry.get("status") == 500 and entry.get("length", 0) > 20000:
        return True
    return False

def normalize_ffuf_result(entry, meta):
    """
    Convert one ffuf result line into our unified finding schema.
    """
    url = entry.get("url") or meta.get("target_url")
    method = meta.get("method", "GET")
    attack = meta.get("attack")
    param = meta.get("param")
    location = meta.get("location")
    payload_map = entry.get("input") or {}  # dict of FUZZ, FUZZ2 -> payload values

    # evidence
    ev = {
        "status": entry.get("status"),
        "size": entry.get("length"),
        "words": entry.get("words"),
        "lines": entry.get("lines"),
        "payloads": payload_map
    }

    finding = {
        "id": "ffuf-" + uuid.uuid4().hex[:12],
        "source": "ffuf",
        "attack": attack,
        "url": url,
        "method": method,
        "parameter": param,
        "location": location,
        "evidence": ev,
        "matcher": "ffuf-match",
        "severity": "low",
        "timestamp": datetime.utcnow().isoformat()
    }
    return finding

def mark_reflection_flags(findings, detect_reflection):
    # Heuristic: if payload value string appears in URL (redirectlocation) field we can catch, but ffuf json is limited.
    # Light-touch: if value contains quotes and status deviates, note it.
    if not detect_reflection:
        return findings
    for f in findings:
        payloads = f.get("evidence", {}).get("payloads") or {}
        payload_concat = " ".join(str(v) for v in payloads.values())
        f.setdefault("tags", [])
        if any(ch in payload_concat for ch in ["'", "\"", "<", ">", "/*", "*/", ";"]):
            f["tags"].append("tainted-input")
    return findings

def assign_anomaly_and_sqli(findings, median):
    for f in findings:
        e = f.get("evidence", {})
        s, l, w, ln = e.get("status"), e.get("size"), e.get("words"), e.get("lines")
        f.setdefault("tags", [])
        # anomaly if deviates strongly from median
        if median.get("status") and s and s != median["status"]:
            f["tags"].append("anomaly:status")
            f["severity"] = "medium"
        if median.get("length") and l and abs(l - median["length"]) > max(1000, int(0.3 * (median["length"] or 1))):
            f["tags"].append("anomaly:size")
        if median.get("words") and w and abs(w - median["words"]) > max(100, int(0.3 * (median["words"] or 1))):
            f["tags"].append("anomaly:words")
        if median.get("lines") and ln and abs(ln - median["lines"]) > max(100, int(0.3 * (median["lines"] or 1))):
            f["tags"].append("anomaly:lines")
        # sqli hint
        if likely_sqli(e):
            f["tags"].append("suspect:sqli")
            f["severity"] = "medium"
    return findings

# ---------- Main ----------

def main():
    module_input = _load_module_input()
    inputs = module_input.get("inputs", {}) or {}

    # --- Resolve absolute paths (fixes: docker needs absolute -v/-w) ---
    raw_workdir = module_input.get("workdir") or os.getcwd()
    workdir = os.path.abspath(raw_workdir)

    def _abs_in(base, p):
        if not p:
            return base
        return p if os.path.isabs(p) else os.path.abspath(os.path.join(base, p))

    artifacts_dir = _abs_in(workdir, module_input.get("artifacts_dir") or "artifacts")
    workspace_dir = _abs_in(workdir, "workspace")
    ffuf_workspace = _abs_in(workdir, "workspace/ffuf")
    ensure_dirs(artifacts_dir, workspace_dir, ffuf_workspace)

    debug_log_path = os.path.join(artifacts_dir, "ffuf-debug.log")
    logger = Logger(debug_log_path, quiet=bool(inputs.get("quiet", False)))

    # --- Inputs / defaults ---
    attack = (inputs.get("attack") or "sniper").lower()
    rate = int(inputs.get("rate", 300))
    threads = int(inputs.get("threads", 40))
    timeout_sec = int(inputs.get("timeout_sec", 10))
    filters = inputs.get("filters") or []
    matchers = inputs.get("matchers") or []
    extra_args = inputs.get("extra_args") or []
    wordlists = inputs.get("wordlists") or []
    detect_reflection = bool(inputs.get("detect_reflection", True))
    max_targets = int(inputs.get("max_targets", 200))
    extra_docker_args = inputs.get("extra_docker_args") or []  # e.g. ["--network","host"]

    ffuf_bin = which_ffuf()
    docker_image = os.environ.get("FFUF_DOCKER_IMAGE") or "secsi/ffuf:2.0.0"

    try:
        logger.log("START web.ffuf")
        if ffuf_bin:
            logger.log(f"Using local ffuf: {ffuf_bin}")
        else:
            logger.log(f"No local ffuf found; using Docker image: {docker_image}")
            docker_preflight(docker_image, logger, workdir, extra_docker_args)

        # --- Gather candidates (explicit + from ZAP/Nuclei + base_urls) ---
        cands = normalize_candidates(inputs, workdir, logger)
        if len(cands) > max_targets:
            logger.log(f"Capping candidates {len(cands)} -> {max_targets}")
            cands = cands[:max_targets]

        # --- Build ffuf jobs ---
        jobs = []
        for c in cands:
            if attack == "sniper":
                jobs.extend(build_sniper_targets(c))
            else:
                t = build_clusterbomb_target(c, max_slots=5)
                if t:
                    jobs.append(t)
        logger.log(f"Prepared {len(jobs)} ffuf jobs (attack={attack})")

        # --- Run jobs ---
        raw_json_paths = []
        jobs_ok = 0
        jobs_fail = 0
        all_findings = []

        for idx, job in enumerate(jobs, start=1):
            # meta for normalization/logging
            meta = {
                "method": job.get("method", "GET"),
                "attack": attack,
                "param": job.get("param") or (
                    ",".join([n for (_loc, n) in job.get("locations", [])]) if "locations" in job else None
                ),
                "location": job.get("location") or (
                    ",".join([loc for (loc, _n) in job.get("locations", [])]) if "locations" in job else None
                ),
                "target_url": job["url"]
            }

            logger.log(f"[{idx}/{len(jobs)}] ffuf job -> {meta['method']} {meta['target_url']} param={meta['param']} loc={meta['location']}")
            out_json, rc = run_ffuf(
                job, wordlists, attack, rate, threads, timeout_sec, filters, matchers, extra_args,
                ffuf_bin, docker_image, workdir, artifacts_dir, logger, extra_docker_args
            )
            raw_json_paths.append(out_json)

            j = safe_json_load(out_json, default={"results": []})
            res = j.get("results", [])
            med = median_metrics(res)
            chunk = [normalize_result(r, meta) for r in res]
            if detect_reflection:
                chunk = mark_reflection(chunk)
            chunk = mark_anomalies_and_sqli(chunk, med)
            all_findings.extend(chunk)

            if rc == 0:
                jobs_ok += 1
                logger.log(f"[{idx}/{len(jobs)}] DONE rc=0 results={len(res)} normalized={len(chunk)}")
            else:
                jobs_fail += 1
                logger.log(f"[{idx}/{len(jobs)}] ERROR rc={rc} (see {out_json} and ffuf-debug.log)")

        # --- Write artifacts ---
        findings_path = os.path.join(ffuf_workspace, "findings.json")
        safe_json_dump(all_findings, findings_path)

        run_summary = {
            "attack": attack,
            "candidates_total": len(cands),
            "jobs_total": len(jobs),
            "jobs_ok": jobs_ok,
            "jobs_fail": jobs_fail,
            "hits_total": len(all_findings),
            "artifacts": {
                "raw_json_files": raw_json_paths,
                "debug_log": debug_log_path,
                "normalized_findings": findings_path
            },
            "rate": rate,
            "threads": threads,
            "timeout_sec": timeout_sec,
            "workdir": workdir
        }
        run_summary_path = os.path.join(artifacts_dir, "ffuf-run-summary.json")
        safe_json_dump(run_summary, run_summary_path)

        # --- Final status ---
        status = "ok"
        msg = f"ffuf completed: jobs_ok={jobs_ok}, jobs_fail={jobs_fail}, hits={len(all_findings)}"
        if jobs_ok == 0 and jobs_fail > 0:
            status = "error"
            msg = "ffuf failed: all jobs errored (see artifacts/ffuf-debug.log)"

        logger.log(f"SUMMARY: jobs_ok={jobs_ok} jobs_fail={jobs_fail} hits={len(all_findings)}")
        logger.log(f"Artifacts: findings={findings_path} summary={run_summary_path} log={debug_log_path}")
        logger.log("END web.ffuf")

        # --- Engine-facing JSON (stdout only) ---
        result = {
            "status": status,
            "message": msg,
            "findings_count": len(all_findings),
            "jobs_ok": jobs_ok,
            "jobs_fail": jobs_fail,
            "artifacts": [
                {"path": debug_log_path, "type": "txt", "description": "ffuf debug log"},
                {"path": run_summary_path, "type": "json", "description": "Run summary"},
                {"path": findings_path, "type": "json", "description": "FFUF normalized findings"}
            ]
        }
        print(json.dumps(result))

    except Exception as e:
        logger.log(f"FATAL: {e}")
        err = {
            "status": "error",
            "message": str(e),
            "artifacts": [
                {"path": debug_log_path, "type": "txt", "description": "ffuf debug log (may contain stack)"},
            ]
        }
        print(json.dumps(err))
    finally:
        logger.close()



if __name__ == "__main__":
    main()
