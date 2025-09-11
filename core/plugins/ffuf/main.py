#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json, sys, os, re, shutil, subprocess, uuid, time, tempfile, urllib.parse, statistics, traceback
from datetime import datetime

# ========================
# Logging helpers
# ========================

def _ts():
    return datetime.utcnow().isoformat()

def _fmt(msg):
    return f"[web.ffuf] {_ts()} {msg}"

class Logger:
    def __init__(self, path, quiet=False):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.fp = open(path, "a", encoding="utf-8")
        self.quiet = quiet

    def log(self, msg):
        line = _fmt(msg)
        self.fp.write(line + "\n")
        self.fp.flush()
        if not self.quiet:
            print(line, file=sys.stderr)

    def close(self):
        try:
            self.fp.close()
        except Exception:
            pass

def ensure_dirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)

def safe_json_load(path, default=None, logger=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        if logger:
            logger.log(f"safe_json_load: failed to read {path}: {e}")
        return default

def safe_json_dump(obj, path, logger=None):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
    except Exception as e:
        if logger:
            logger.log(f"safe_json_dump: failed to write {path}: {e}")

def load_stdin_module_input():
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}

def which_ffuf():
    return shutil.which("ffuf")

def docker_cmd(image, workdir, extra_docker_args=None):
    absw = os.path.abspath(workdir)
    cmd = ["docker", "run", "--rm", "-v", f"{absw}:{absw}", "-w", absw]
    if extra_docker_args:
        cmd += list(extra_docker_args)
    # secsi/ffuf uses ffuf as entrypoint; do NOT append "ffuf" again.
    cmd += [image]
    return cmd

def docker_preflight(image, logger, workdir, extra_docker_args):
    logger.log("PHASE=DOCKER: preflight begin")
    try:
        out = subprocess.run(["docker", "--version"], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        logger.log(f"docker --version rc={out.returncode} out={out.stdout.strip()}")
    except Exception as e:
        logger.log(f"docker --version failed: {e}")

    try:
        test = docker_cmd(image, workdir, extra_docker_args) + ["-V"]
        logger.log(f"docker preflight run: {' '.join(test)}")
        out = subprocess.run(test, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        logger.log(f"preflight rc={out.returncode} out-tail={(out.stdout or '').strip()[:400]}")
    except Exception as e:
        logger.log(f"docker preflight run failed: {e}")
    logger.log("PHASE=DOCKER: preflight end")

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

def harvest_from_zap(workdir, logger):
    zap_path = os.path.join(workdir, "workspace", "zap", "findings.json")
    j = safe_json_load(zap_path, default=[], logger=logger) or []
    out = []
    for item in j:
        url = item.get("url") or (item.get("evidence") or {}).get("url")
        method = (item.get("method") or "GET").upper()
        if not url:
            continue
        out.append({"method": method, "url": url, "body": item.get("requestBody")})
    logger.log(f"harvest_from_zap: {len(out)} candidates")
    return out

def harvest_from_nuclei(workdir, logger):
    paths = [
        os.path.join(workdir, "artifacts", "nuclei.jsonl"),
        os.path.join(workdir, "workspace", "nuclei", "findings.json"),
    ]
    out, count = [], 0
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
            j = safe_json_load(p, default=[], logger=logger) or []
            for item in j:
                url = item.get("url")
                if url:
                    out.append({"method": "GET", "url": url})
                    count += 1
    logger.log(f"harvest_from_nuclei: {count} candidates")
    return out

def normalize_candidates(inputs, workdir, logger):
    cands = []
    for c in (inputs.get("candidates") or []):
        if isinstance(c, str):
            cands.append({"method": "GET", "url": c})
        elif isinstance(c, dict) and c.get("url"):
            m = (c.get("method") or "GET").upper()
            cands.append({"method": m, "url": c["url"], "body": c.get("body")})
    sources = set([s.lower() for s in (inputs.get("candidates_from") or [])])
    if "zap" in sources:
        cands.extend(harvest_from_zap(workdir, logger))
    if "nuclei" in sources:
        cands.extend(harvest_from_nuclei(workdir, logger))
    for u in (inputs.get("base_urls") or []):
        cands.append({"method": "GET", "url": u})

    seen, uniq = set(), []
    for c in cands:
        key = (c["method"], c["url"], json.dumps(c.get("body"), sort_keys=True) if isinstance(c.get("body"), dict) else c.get("body"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    return uniq

def build_sniper_targets(candidate):
    method, url = candidate["method"], candidate["url"]
    targets = []
    for key in parse_query_params(url).keys():
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

def build_clusterbomb_target(candidate, max_slots, reuse_same_wordlists=True):
    method, url = candidate["method"], candidate["url"]
    param_names, qparams = [], parse_query_params(url)
    for k in qparams.keys():
        param_names.append(("query", k))

    body_str = None
    if method in ("POST", "PUT", "PATCH"):
        body_str = guess_body_from_candidate(candidate) or ""
        if body_str:
            for k in dict(urllib.parse.parse_qsl(body_str, keep_blank_values=True)).keys():
                param_names.append(("body", k))

    param_names = param_names[:max_slots]
    if not param_names:
        return None

    placeholders = []
    for i, (_loc, _k) in enumerate(param_names, start=1):
        placeholders.append("FUZZ" if i == 1 else f"FUZZ{i}")

    new_url = url
    for i, (loc, k) in enumerate(param_names, start=1):
        if loc != "query":
            continue
        ph = "FUZZ" if i == 1 else f"FUZZ{i}"
        new_url = replace_query_value(new_url, k, ph)

    new_body = body_str
    if body_str:
        bm = {}
        for i, (loc, k) in enumerate(param_names, start=1):
            if loc != "body":
                continue
            bm[k] = "FUZZ" if i == 1 else f"FUZZ{i}"
        if bm:
            new_body = build_post_body_with_fuzz(body_str, bm)

    return {
        "method": method,
        "url": new_url,
        "body": new_body,
        "locations": param_names,
        "placeholders": placeholders,
        "reuse_same_wordlists": reuse_same_wordlists,
    }

def run_ffuf(job, wordlists, mode, rate, threads, timeout_sec, filters, matchers, extra_args,
             ffuf_bin, docker_image, workdir, artifacts_dir, logger, extra_docker_args):
    out_json = os.path.join(artifacts_dir, f"ffuf-{uuid.uuid4().hex}.json")
    cmd = [ffuf_bin] if ffuf_bin else docker_cmd(docker_image, workdir, extra_docker_args)

    # Base args
    cmd += ["-of", "json", "-o", out_json, "-rate", str(rate), "-t", str(threads), "-timeout", str(timeout_sec)]
    if job.get("method", "GET") != "GET":
        cmd += ["-X", job["method"]]
    cmd += ["-u", job["url"]]
    if job.get("body"):
        cmd += ["-d", job["body"], "-H", "Content-Type: application/x-www-form-urlencoded"]

    # Mode/wordlists
    if mode == "sniper":
        wl = wordlists[0] if wordlists else "configs/wordlists/quick.txt"
        cmd += ["-w", wl, "-mode", "sniper"]
    else:
        placeholders = job["placeholders"]
        if not wordlists:
            wordlists = ["configs/wordlists/quick.txt"] * len(placeholders)
        elif len(wordlists) < len(placeholders) and job.get("reuse_same_wordlists", True):
            last = wordlists[-1]
            wordlists = wordlists + [last] * (len(placeholders) - len(wordlists))
        for i, ph in enumerate(placeholders):
            cmd += ["-w", f"{wordlists[i]}:{ph}"]
        cmd += ["-mode", "clusterbomb"]

    for tok in (filters or []): cmd.append(tok)
    for tok in (matchers or []): cmd.append(tok)
    for tok in (extra_args or []): cmd.append(tok)

    logger.log(f"RUN CMD: {' '.join(cmd)}")
    rc = 997
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        rc = proc.returncode
        # log tail of ffuf output
        if proc.stdout:
            logger.log(f"ffuf stdout (tail 800):\n{proc.stdout[-800:]}")
        if rc != 0:
            logger.log(f"ffuf exit code: {rc}")
        if not os.path.exists(out_json):
            logger.log(f"ffuf did not create output, synthesizing empty: {out_json}")
            safe_json_dump({"results": [], "meta": {"cmd": cmd, "rc": rc}}, out_json, logger=logger)
        return out_json, rc
    except Exception as e:
        logger.log(f"EXC while running ffuf: {e}")
        logger.log("TRACE:\n" + "".join(traceback.format_exc()[-1500:]))
        safe_json_dump({"results": [], "meta": {"error": str(e)}}, out_json, logger=logger)
        return out_json, rc

def compute_anomaly_flags(results):
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
        med[k] = int(statistics.median(arr)) if arr else None
    return med

SQLI_HINTS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql", "postgresql", "sqlite", "odbc", "oracle", "syntax error", "fatal error",
]

def likely_sqli(entry):
    t = ((entry.get("redirectlocation") or "") + " " + (entry.get("url") or "")).lower()
    if any(h in t for h in SQLI_HINTS):
        return True
    return entry.get("status") == 500 and entry.get("length", 0) > 20000

def normalize_ffuf_result(entry, meta):
    ev = {
        "status": entry.get("status"),
        "size": entry.get("length"),
        "words": entry.get("words"),
        "lines": entry.get("lines"),
        "payloads": entry.get("input") or {},
    }
    return {
        "id": "ffuf-" + uuid.uuid4().hex[:12],
        "source": "ffuf",
        "attack": meta.get("attack"),
        "url": entry.get("url") or meta.get("target_url"),
        "method": meta.get("method", "GET"),
        "parameter": meta.get("param"),
        "location": meta.get("location"),
        "evidence": ev,
        "matcher": "ffuf-match",
        "severity": "low",
        "timestamp": datetime.utcnow().isoformat(),
    }

def mark_reflection_flags(findings, detect_reflection):
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
        if median.get("status") and s and s != median["status"]:
            f["tags"].append("anomaly:status"); f["severity"] = "medium"
        if median.get("length") and l and abs(l - median["length"]) > max(1000, int(0.3 * (median["length"] or 1))):
            f["tags"].append("anomaly:size")
        if median.get("words") and w and abs(w - median["words"]) > max(100, int(0.3 * (median["words"] or 1))):
            f["tags"].append("anomaly:words")
        if median.get("lines") and ln and abs(ln - median["lines"]) > max(100, int(0.3 * (median["lines"] or 1))):
            f["tags"].append("anomaly:lines")
        if likely_sqli(e):
            f["tags"].append("suspect:sqli"); f["severity"] = "medium"
    return findings

def main():
    # ---------- START ----------
    module_input = load_stdin_module_input()
    inputs = module_input.get("inputs", {}) or {}

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

    try:
        logger.log("PHASE=START")
        logger.log(f"ARGS module_input keys={list(module_input.keys())}")
        logger.log(f"PATHS workdir={workdir} artifacts_dir={artifacts_dir} workspace_dir={workspace_dir} ffuf_workspace={ffuf_workspace}")
        for p in (workdir, artifacts_dir, workspace_dir, ffuf_workspace):
            logger.log(f"CHECK path exists? {p} -> {os.path.exists(p)}")

        # Optional verbose environment
        if (os.environ.get("LOG_LEVEL") or "").lower() == "debug":
            env_k = ["FFUF_DOCKER_IMAGE", "PIPELINE_CONTEXT", "CI", "GITHUB_ACTIONS", "GITLAB_CI"]
            for k in env_k:
                logger.log(f"ENV {k}={os.environ.get(k)}")

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
        extra_docker_args = inputs.get("extra_docker_args") or []

        logger.log(f"PHASE=ARGS attack={attack} rate={rate} threads={threads} timeout={timeout_sec} wordlists={wordlists} matchers={matchers} filters={filters} extra_args={extra_args} extra_docker_args={extra_docker_args}")

        ffuf_bin = which_ffuf()
        docker_image = os.environ.get("FFUF_DOCKER_IMAGE") or "secsi/ffuf:2.0.0"
        if ffuf_bin:
            logger.log(f"FFUF local binary: {ffuf_bin}")
        else:
            logger.log(f"FFUF docker image: {docker_image}")
            docker_preflight(docker_image, logger, workdir, extra_docker_args)

        # ---------- CANDIDATES ----------
        logger.log("PHASE=CANDIDATES: start")
        cands = normalize_candidates(inputs, workdir, logger)
        logger.log(f"CANDIDATES total={len(cands)} (cap={max_targets})")
        if len(cands) > max_targets:
            cands = cands[:max_targets]
            logger.log(f"CANDIDATES capped -> {len(cands)}")

        # ---------- JOBS ----------
        logger.log("PHASE=JOBS: start")
        jobs = []
        for c in cands:
            if attack == "sniper":
                jobs.extend(build_sniper_targets(c))
            else:
                t = build_clusterbomb_target(
                    c, max_slots=5,
                    reuse_same_wordlists=bool(inputs.get("reuse_same_wordlists", True))
                )
                if t:
                    jobs.append(t)
        logger.log(f"JOBS prepared={len(jobs)}")

        # ---------- RUN ----------
        logger.log("PHASE=RUN: start")
        raw_json_paths, jobs_ok, jobs_fail, all_findings = [], 0, 0, []

        for idx, job in enumerate(jobs, start=1):
            meta = {
                "method": job.get("method", "GET"),
                "attack": attack,
                "param": job.get("param") or (
                    ",".join([n for (_loc, n) in job.get("locations", [])]) if "locations" in job else None
                ),
                "location": job.get("location") or (
                    ",".join([loc for (loc, _n) in job.get("locations", [])]) if "locations" in job else None
                ),
                "target_url": job["url"],
            }
            logger.log(f"[{idx}/{len(jobs)}] PHASE=RUN: job -> {meta}")

            out_json, rc = run_ffuf(
                job, wordlists, attack, rate, threads, timeout_sec, filters, matchers, extra_args,
                ffuf_bin, docker_image, workdir, artifacts_dir, logger, extra_docker_args
            )
            raw_json_paths.append(out_json)
            logger.log(f"[{idx}/{len(jobs)}] OUT_JSON={out_json} rc={rc} exists={os.path.exists(out_json)}")

            j = safe_json_load(out_json, default={"results": []}, logger=logger) or {"results": []}
            res = j.get("results", [])
            med = compute_anomaly_flags(res)
            chunk = [normalize_ffuf_result(r, meta) for r in res]
            if detect_reflection:
                chunk = mark_reflection_flags(chunk, True)
            chunk = assign_anomaly_and_sqli(chunk, med)
            all_findings.extend(chunk)

            if rc == 0:
                jobs_ok += 1
                logger.log(f"[{idx}/{len(jobs)}] DONE rc=0 results={len(res)} normalized={len(chunk)}")
            else:
                jobs_fail += 1
                logger.log(f"[{idx}/{len(jobs)}] ERROR rc={rc} (see {out_json} and ffuf-debug.log)")

        # ---------- POST ----------
        logger.log("PHASE=POST: writing artifacts")
        findings_path = os.path.join(ffuf_workspace, "findings.json")
        run_summary_path = os.path.join(artifacts_dir, "ffuf-run-summary.json")
        safe_json_dump(all_findings, findings_path, logger=logger)
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
                "normalized_findings": findings_path,
            },
            "rate": rate,
            "threads": threads,
            "timeout_sec": timeout_sec,
            "workdir": workdir,
        }
        safe_json_dump(run_summary, run_summary_path, logger=logger)

        status = "ok"
        msg = f"ffuf completed: jobs_ok={jobs_ok}, jobs_fail={jobs_fail}, hits={len(all_findings)}"
        if jobs_ok == 0 and jobs_fail > 0:
            status = "error"
            msg = "ffuf failed: all jobs errored (see artifacts/ffuf-debug.log)"

        logger.log(f"PHASE=SUMMARY: jobs_ok={jobs_ok} jobs_fail={jobs_fail} hits={len(all_findings)}")
        logger.log(f"Artifacts:\n - log={debug_log_path}\n - summary={run_summary_path}\n - findings={findings_path}")
        logger.log("PHASE=END")

        print(json.dumps({
            "status": status,
            "message": msg,
            "findings_count": len(all_findings),
            "jobs_ok": jobs_ok,
            "jobs_fail": jobs_fail,
            "artifacts": [
                {"path": debug_log_path, "type": "txt", "description": "ffuf debug log"},
                {"path": run_summary_path, "type": "json", "description": "Run summary"},
                {"path": findings_path, "type": "json", "description": "FFUF normalized findings"},
            ],
        }))
    except Exception as e:
        logger.log(f"FATAL: {e}")
        logger.log("TRACE:\n" + "".join(traceback.format_exc()[-2000:]))
        print(json.dumps({
            "status": "error",
            "message": str(e),
            "artifacts": [{"path": debug_log_path, "type": "txt", "description": "ffuf debug log (with traceback)"}],
        }))
    finally:
        logger.close()

if __name__ == "__main__":
    main()
