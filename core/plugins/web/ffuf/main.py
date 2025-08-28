#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
web.ffuf — Parameter fuzzing via ffuf for the infosec-vapt-tool pipeline.

Features:
- Reads ModuleInput JSON from STDIN (engine) or manual via --input / --stdin.
- Local ffuf preferred; Docker fallback (image from $FFUF_DOCKER_IMAGE or default).
- Absolute -v/-w for Docker to avoid path errors.
- Creates/ensures a quick wordlist if none provided.
- Validates jobs; SKIP malformed ones with reason; RUN others.
- Logs to STDERR (live) and artifacts/ffuf-debug.log (full).
- Outputs:
  * artifacts/ffuf-*.json (raw ffuf JSON)
  * artifacts/ffuf-run-summary.json
  * workspace/ffuf/findings.json (normalized for aggregator/sqlmap)
- Returns JSON on STDOUT only (status ok/error, counts, artifact paths).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import statistics
import urllib.parse
import uuid
from datetime import datetime
from typing import Optional, Tuple

# ---------- IO / Logging ----------

def ensure_dirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)

def _ts():
    return datetime.utcnow().isoformat()

class Logger:
    def __init__(self, logfile_path: str, quiet: bool = False):
        self.logfile_path = logfile_path
        self.quiet = quiet
        self.fp = open(logfile_path, "a", encoding="utf-8")

    def log(self, msg: str):
        line = f"[web.ffuf] {_ts()} {msg}"
        # file
        self.fp.write(line + "\n")
        self.fp.flush()
        # stderr (live in pipeline)
        if not self.quiet:
            sys.stderr.write(line + "\n")
            sys.stderr.flush()

    def close(self):
        try:
            self.fp.flush()
            self.fp.close()
        except Exception:
            pass

# ---------- CLI / Input loader ----------

def _load_module_input():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--input", help="Path to ModuleInput JSON (manual mode).")
    p.add_argument("--stdin", action="store_true", help="Force reading JSON from STDIN (manual mode).")
    args, _ = p.parse_known_args()

    # 1) explicit --input
    if args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            return json.load(f)

    # 2) explicit --stdin or piped data (not a TTY)
    if args.stdin or not sys.stdin.isatty():
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}

    # 3) fallback
    return {}

# ---------- Path setup helper ----------

def update_paths(module_input: dict) -> Tuple[str, str, str, str]:
    """
    Returns (workdir, artifacts_dir, workspace_dir, ffuf_workspace),
    all as absolute paths. Also ensures the directories exist.
    """
    raw_workdir = module_input.get("workdir") or os.getcwd()
    workdir = os.path.abspath(raw_workdir)

    def _abs_in(base: str, p: Optional[str]) -> str:
        if not p:
            return base
        return p if os.path.isabs(p) else os.path.abspath(os.path.join(base, p))

    artifacts_dir  = _abs_in(workdir, module_input.get("artifacts_dir") or "artifacts")
    workspace_dir  = _abs_in(workdir, "workspace")
    ffuf_workspace = _abs_in(workdir, "workspace/ffuf")

    ensure_dirs(artifacts_dir, workspace_dir, ffuf_workspace)
    return workdir, artifacts_dir, workspace_dir, ffuf_workspace

# ---------- Safe JSON helpers ----------

def safe_json_load(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def safe_json_dump(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

# ---------- ffuf / Docker helpers ----------

def which_ffuf():
    return shutil.which("ffuf")



def docker_cmd(image, workdir, extra_docker_args=None):
    absw = os.path.abspath(workdir)
    cmd = ["docker", "run", "--rm",
           "-v", f"{absw}:{absw}",
           "-w", absw]
    if extra_docker_args:
        cmd += list(extra_docker_args)
    # IMPORTANT: do NOT append "ffuf" here — most images set ENTRYPOINT to ffuf already
    cmd += [image]
    return cmd

def docker_preflight(image, logger, workdir, extra_docker_args=None):
    if not shutil.which("docker"):
        raise RuntimeError("Docker not found. Install Docker or provide a local ffuf binary.")
    # Quick version check (ensures mount/working dir ok)
    cmd = docker_cmd(image, workdir, extra_docker_args) + ["-V"]
    logger.log(f"docker preflight: {' '.join(cmd)}")
    cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if cp.returncode != 0:
        logger.log(cp.stdout.strip())
        # Try to pull once
        logger.log(f"Pulling Docker image {image} ...")
        pp = subprocess.run(["docker", "pull", image], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        logger.log(pp.stdout.strip())
        if pp.returncode != 0:
            raise RuntimeError(f"Failed to use/pull Docker image {image}. Check network/credentials.")

# ---------- URL/body utilities ----------

def parse_query_params(url):
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in q.items()}

def replace_query_value(url, key, new_value):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[key] = [new_value]
    new_query = urllib.parse.urlencode([(k, v[0] if isinstance(v, list) else v) for k, v in qs.items()], doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))

def build_post_body_with_fuzz(body_str, mapping):
    pairs = urllib.parse.parse_qsl(body_str, keep_blank_values=True)
    out = []
    for k, v in pairs:
        out.append((k, mapping.get(k, v)))
    return urllib.parse.urlencode(out)

def guess_body_from_candidate(c):
    body = c.get("body")
    if body is None:
        return None
    if isinstance(body, str):
        return body
    if isinstance(body, dict):
        return urllib.parse.urlencode([(k, str(v)) for k, v in body.items()])
    return None

# ---------- Candidate harvesting ----------

def harvest_from_zap(workdir, logger):
    path = os.path.join(workdir, "workspace", "zap", "findings.json")
    data = safe_json_load(path, default=[])
    out = []
    for item in data:
        url = item.get("url") or item.get("evidence", {}).get("url")
        method = (item.get("method") or "GET").upper()
        if url:
            out.append({"method": method, "url": url, "body": item.get("requestBody")})
    logger.log(f"harvest_from_zap: {len(out)} candidates from {path}")
    return out

def harvest_from_nuclei(workdir, logger):
    paths = [
        os.path.join(workdir, "artifacts", "nuclei.jsonl"),
        os.path.join(workdir, "workspace", "nuclei", "findings.json"),
    ]
    out = []
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
        else:
            j = safe_json_load(p, default=[])
            for item in j:
                url = item.get("url")
                if url:
                    out.append({"method": "GET", "url": url})
    logger.log(f"harvest_from_nuclei: {len(out)} candidates")
    return out

def normalize_candidates(inputs, workdir, logger):
    cands = []

    explicit = inputs.get("candidates") or []
    for c in explicit:
        if isinstance(c, str):
            cands.append({"method": "GET", "url": c})
        elif isinstance(c, dict) and c.get("url"):
            cands.append({"method": (c.get("method") or "GET").upper(), "url": c["url"], "body": c.get("body")})

    sources = set([s.lower() for s in (inputs.get("candidates_from") or [])])
    if "zap" in sources:
        cands.extend(harvest_from_zap(workdir, logger))
    if "nuclei" in sources:
        cands.extend(harvest_from_nuclei(workdir, logger))

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

    logger.log(f"normalize_candidates: {len(uniq)} unique candidates")
    return uniq

# ---------- Target builders ----------

def build_sniper_targets(candidate):
    method = candidate["method"]
    url = candidate["url"]
    targets = []

    qparams = parse_query_params(url)
    for key in qparams.keys():
        fu_url = replace_query_value(url, key, "FUZZ")
        targets.append({"method": method, "url": fu_url, "param": key, "location": "query"})

    if method in ("POST", "PUT", "PATCH"):
        body_str = guess_body_from_candidate(candidate) or ""
        if body_str:
            body_params = dict(urllib.parse.parse_qsl(body_str, keep_blank_values=True))
            for key in body_params.keys():
                fu_body = build_post_body_with_fuzz(body_str, {key: "FUZZ"})
                targets.append({"method": method, "url": url, "param": key, "location": "body", "body": fu_body})
    return targets

def build_clusterbomb_target(candidate, max_slots=5):
    method = candidate["method"]
    url = candidate["url"]

    param_names = []
    qparams = parse_query_params(url)
    for k in qparams.keys():
        param_names.append(("query", k))

    body_str = None
    if method in ("POST", "PUT", "PATCH"):
        body_str = guess_body_from_candidate(candidate) or ""
        if body_str:
            bparams = dict(urllib.parse.parse_qsl(body_str, keep_blank_values=True))
            for k in bparams.keys():
                param_names.append(("body", k))

    if not param_names:
        return None

    param_names = param_names[:max_slots]
    placeholders = []
    for i in range(len(param_names)):
        placeholders.append("FUZZ" if i == 0 else f"FUZZ{i+1}")

    new_url = url
    if qparams:
        idx = 0
        for loc, k in param_names:
            if loc != "query": 
                continue
            ph = placeholders[idx]
            idx += 1
            new_url = replace_query_value(new_url, k, ph)

    new_body = body_str
    if body_str:
        bmapping = {}
        for i, (loc, k) in enumerate(param_names):
            if loc != "body": 
                continue
            bmapping[k] = placeholders[i]
        if bmapping:
            new_body = build_post_body_with_fuzz(body_str, bmapping)

    return {
        "method": method,
        "url": new_url,
        "body": new_body,
        "locations": param_names,
        "placeholders": placeholders
    }

# ---------- Wordlist & job validation ----------

def ensure_quick_wordlist(workdir, wordlists):
    """
    Returns a non-empty list of absolute wordlist paths.
    Ensures at least one exists; creates a minimal quick.txt if needed.
    """
    out = []
    # Normalize to absolute paths
    for wl in (wordlists or []):
        out.append(wl if os.path.isabs(wl) else os.path.abspath(os.path.join(workdir, wl)))

    # If none provided, default to configs/wordlists/quick.txt
    if not out:
        default_rel = "configs/wordlists/quick.txt"
        default_abs = os.path.abspath(os.path.join(workdir, default_rel))
        os.makedirs(os.path.dirname(default_abs), exist_ok=True)
        if not os.path.exists(default_abs):
            with open(default_abs, "w", encoding="utf-8") as f:
                f.write("test\nadmin\n' OR '1'='1\n<script>alert(1)</script>\n../etc/passwd\n")
        out = [default_abs]

    # Create a minimal file if any entry doesn't exist
    ensured = []
    for p in out:
        if not os.path.exists(p):
            try:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as f:
                    f.write("test\n")
            except Exception:
                pass
        ensured.append(p)
    return ensured

def validate_job(job, mode, wordlists_abs):
    """
    Returns (ok: bool, reason: str). Verifies URL and wordlists presence.
    For clusterbomb, also requires at least one placeholder.
    """
    url = job.get("url")
    if not url or not isinstance(url, str) or not url.strip():
        return False, "missing -u URL"
    if mode == "sniper":
        if not wordlists_abs:
            return False, "missing -w wordlist"
    else:  # clusterbomb
        ph = job.get("placeholders") or []
        if not ph:
            return False, "clusterbomb with zero placeholders"
        if not wordlists_abs:
            return False, "missing -w wordlists for placeholders"
    return True, ""

# ---------- ffuf runner ----------

def run_ffuf(job, wordlists, mode, rate, threads, timeout_sec, filters, matchers, extra_args,
             ffuf_bin, docker_image, workdir, artifacts_dir, logger, extra_docker_args):
    """
    job:
      sniper: {method,url,param,location,body?}
      clusterbomb: {method,url,body?,placeholders[]}
    """
    out_json = os.path.join(artifacts_dir, f"ffuf-{uuid.uuid4().hex}.json")
    base_cmd = [ffuf_bin] if ffuf_bin else docker_cmd(docker_image, workdir, extra_docker_args)

    cmd = base_cmd + ["-of", "json", "-o", out_json, "-rate", str(rate), "-t", str(threads), "-timeout", str(timeout_sec)]

    if job.get("method", "GET") != "GET":
        cmd += ["-X", job["method"]]

    cmd += ["-u", job["url"]]

    if job.get("body"):
        cmd += ["-d", job["body"], "-H", "Content-Type: application/x-www-form-urlencoded"]

    # # Wordlists / modes
    # if mode == "sniper":
    #     wl = wordlists[0] if wordlists else "configs/wordlists/quick.txt"  # safeguard
    #     cmd += ["-w", wl, "-mode", "sniper"]
    # else:
    #     placeholders = job["placeholders"]
    #     wls = list(wordlists)
    #     if len(wls) < len(placeholders):
    #         last = wls[-1] if wls else "configs/wordlists/quick.txt"
    #         wls = wls + [last] * (len(placeholders) - len(wls))
    #     for i, ph in enumerate(placeholders):
    #         cmd += ["-w", f"{wls[i]}:{ph}"]
    #     cmd += ["-mode", "clusterbomb"]

    if mode == "sniper":
        # Use classic FUZZ without -mode sniper (ffuf v2 treats -mode sniper as §-templating)
        wl = wordlists[0] if wordlists else "configs/wordlists/quick.txt"
        cmd += ["-w", wl]   # <-- no "-mode sniper"
    else:
        placeholders = job["placeholders"]
        wls = list(wordlists)
        if len(wls) < len(placeholders):
            last = wls[-1] if wls else "configs/wordlists/quick.txt"
            wls = wls + [last] * (len(placeholders) - len(wls))
        for i, ph in enumerate(placeholders):
            cmd += ["-w", f"{wls[i]}:{ph}"]
        cmd += ["-mode", "clusterbomb"]

    for tok in (filters or []):
        cmd.append(tok)
    for tok in (matchers or []):
        cmd.append(tok)
    for tok in (extra_args or []):
        cmd.append(tok)

    logger.log(f"RUN ffuf: {' '.join(cmd)}")
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.stdout:
        logger.log(proc.stdout.strip())

    # Ensure JSON file exists (ffuf sometimes fails before writing)
    if not os.path.exists(out_json):
        safe_json_dump({"results": [], "meta": {"cmd": cmd, "note": "ffuf produced no file"}}, out_json)

    return out_json, proc.returncode

# ---------- Analysis / Normalization ----------

def median_metrics(results):
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
    "mysql", "postgresql", "sqlite", "odbc", "oracle",
    "syntax error", "fatal error"
]

def sqli_hint(evidence, url=""):
    # evidence from normalize_result.evidence: keys: status, size, words, lines
    text = (url or "").lower()
    if any(h in text for h in SQLI_HINTS):
        return True
    status = evidence.get("status")
    length = evidence.get("length") or evidence.get("size")
    if status == 500 and isinstance(length, int) and length > 20000:
        return True
    return False

def normalize_result(entry, meta):
    url = entry.get("url") or meta.get("target_url")
    method = meta.get("method", "GET")
    attack = meta.get("attack")
    param = meta.get("param")
    location = meta.get("location")
    payloads = entry.get("input") or {}

    ev = {
        "status": entry.get("status"),
        "size": entry.get("length"),
        "words": entry.get("words"),
        "lines": entry.get("lines"),
        "payloads": payloads
    }

    return {
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
        "timestamp": _ts(),
        "tags": []
    }

def mark_reflection(findings):
    for f in findings:
        payloads = f.get("evidence", {}).get("payloads") or {}
        s = " ".join(str(v) for v in payloads.values())
        if any(ch in s for ch in ["'", "\"", "<", ">", "/*", "*/", ";"]):
            f["tags"].append("tainted-input")
    return findings

def mark_anomalies_and_sqli(findings, median):
    for f in findings:
        e = f.get("evidence", {})
        s, l, w, ln = e.get("status"), e.get("size"), e.get("words"), e.get("lines")
        if median.get("status") and s and s != median["status"]:
            f["tags"].append("anomaly:status")
            f["severity"] = "medium"
        if median.get("length") and l and abs(l - median["length"]) > max(1000, int(0.3 * (median["length"] or 1))):
            f["tags"].append("anomaly:size")
        if median.get("words") and w and abs(w - median["words"]) > max(100, int(0.3 * (median["words"] or 1))):
            f["tags"].append("anomaly:words")
        if median.get("lines") and ln and abs(ln - median["lines"]) > max(100, int(0.3 * (median["lines"] or 1))):
            f["tags"].append("anomaly:lines")
        if sqli_hint(e, url=f.get("url", "")):
            f["tags"].append("suspect:sqli")
            f["severity"] = "medium"
    return findings

# ---------- Main ----------

def main():
    module_input = _load_module_input()
    inputs = module_input.get("inputs", {}) or {}

    # Resolve absolute paths and ensure dirs
    workdir, artifacts_dir, workspace_dir, ffuf_workspace = update_paths(module_input)

    debug_log_path = os.path.join(artifacts_dir, "ffuf-debug.log")
    logger = Logger(debug_log_path, quiet=bool(inputs.get("quiet", False)))

    # Inputs / defaults
    attack = (inputs.get("attack") or "sniper").lower()
    rate = int(inputs.get("rate", 300))
    threads = int(inputs.get("threads", 40))
    timeout_sec = int(inputs.get("timeout_sec", 10))
    filters = inputs.get("filters") or []
    matchers = inputs.get("matchers") or []
    extra_args = inputs.get("extra_args") or []
    detect_reflection = bool(inputs.get("detect_reflection", True))
    max_targets = int(inputs.get("max_targets", 200))
    extra_docker_args = inputs.get("extra_docker_args") or []  # e.g., ["--network","host"]

    # ffuf selection
    ffuf_bin = which_ffuf()
    docker_image = os.environ.get("FFUF_DOCKER_IMAGE") or "secsi/ffuf:2.0.0"

    try:
        logger.log("START web.ffuf")
        if ffuf_bin:
            logger.log(f"Using local ffuf: {ffuf_bin}")
        else:
            logger.log(f"No local ffuf found; using Docker image: {docker_image}")
            docker_preflight(docker_image, logger, workdir, extra_docker_args)

        # Ensure at least one valid wordlist (make default if missing)
        wordlists_abs = ensure_quick_wordlist(workdir, inputs.get("wordlists"))

        # Gather candidates
        cands = normalize_candidates(inputs, workdir, logger)
        if len(cands) > max_targets:
            logger.log(f"Capping candidates {len(cands)} -> {max_targets}")
            cands = cands[:max_targets]

        # Build jobs
        jobs = []
        for c in cands:
            if attack == "sniper":
                jobs.extend(build_sniper_targets(c))
            else:
                t = build_clusterbomb_target(c, max_slots=5)
                if t:
                    jobs.append(t)
        logger.log(f"Prepared {len(jobs)} ffuf jobs (attack={attack})")

        # Run jobs
        raw_json_paths = []
        jobs_ok = 0
        jobs_fail = 0
        jobs_skip = 0
        all_findings = []

        for idx, job in enumerate(jobs, start=1):
            meta = {
                "method": job.get("method", "GET"),
                "attack": attack,
                "param": job.get("param") or (",".join([n for (_loc, n) in job.get("locations", [])]) if "locations" in job else None),
                "location": job.get("location") or (",".join([loc for (loc, _n) in job.get("locations", [])]) if "locations" in job else None),
                "target_url": job.get("url")
            }

            ok, reason = validate_job(job, attack, wordlists_abs)
            if not ok:
                jobs_skip += 1
                logger.log(f"[{idx}/{len(jobs)}] SKIP: {reason} -> {meta['method']} {meta.get('target_url')}")
                continue

            logger.log(f"[{idx}/{len(jobs)}] ffuf job -> {meta['method']} {meta['target_url']} param={meta['param']} loc={meta['location']}")
            out_json, rc = run_ffuf(
                job, wordlists_abs, attack, rate, threads, timeout_sec, filters, matchers, extra_args,
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

        # Write outputs
        findings_path = os.path.join(ffuf_workspace, "findings.json")
        safe_json_dump(all_findings, findings_path)

        run_summary = {
            "attack": attack,
            "candidates_total": len(cands),
            "jobs_total": len(jobs),
            "jobs_ok": jobs_ok,
            "jobs_fail": jobs_fail,
            "jobs_skip": jobs_skip,
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

        # Final status
        status = "ok"
        msg = f"ffuf completed: jobs_ok={jobs_ok}, jobs_fail={jobs_fail}, jobs_skip={jobs_skip}, hits={len(all_findings)}"
        if jobs_ok == 0 and (jobs_fail + jobs_skip) > 0:
            status = "error"
            msg = "ffuf failed: no successful jobs (see artifacts/ffuf-debug.log)"

        logger.log(f"SUMMARY: jobs_ok={jobs_ok} jobs_fail={jobs_fail} jobs_skip={jobs_skip} hits={len(all_findings)}")
        logger.log(f"Artifacts: findings={findings_path} summary={run_summary_path} log={debug_log_path}")
        logger.log("END web.ffuf")

        # Engine-facing result
        result = {
            "status": status,
            "message": msg,
            "findings_count": len(all_findings),
            "jobs_ok": jobs_ok,
            "jobs_fail": jobs_fail,
            "jobs_skip": jobs_skip,
            "artifacts": [
                {"path": debug_log_path, "type": "txt", "description": "ffuf debug log"},
                {"path": run_summary_path, "type": "json", "description": "Run summary"},
                {"path": findings_path, "type": "json", "description": "FFUF normalized findings"}
            ]
        }
        print(json.dumps(result))

    except Exception as e:
        # Ensure a meaningful failure surfaces
        try:
            logger.log(f"FATAL: {e}")
        except Exception:
            pass
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
