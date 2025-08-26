# VAPT Product Scaffold

VAPT Product Scaffold — Architecture & Guide
This repository is a modular VAPT engine you can run module-by-module today and chain into full pipelines later. It’s built to be plug-and-play, language-agnostic, and CI-friendly.
Folder Tree (at a glance)
export PYTHONPATH=/home/amitks/infosec-vapt-tool:$PYTHONPATH

vapt/
├─ apps/                              # user-facing + orchestration services
│  ├─ web-portal/                     # your admin UI (any framework)
│  ├─ api/                            # REST API to accept jobs & expose results
│  │  ├─ main.py                      # FastAPI entry; POST /jobs, GET /runs/{id}
│  │  ├─ routes/                      # (future) route modules
│  │  ├─ services/                    # (future) business logic (DB, auth, s3…)
│  │  └─ schemas/                     # request/response Pydantic models
│  └─ worker/                         # job runner that executes pipelines
│     ├─ worker.py                    # consumes queue; launches pipeline engine
│     └─ queue/                       # adapters (Redis/Rabbit/SQS)
│
├─ core/                              # engine & shared libraries
│  ├─ pipeline/                       # pipeline engine (stages, retries)
│  │  ├─ engine.py                    # runs pipeline -> executes modules
│  │  ├─ registry.py                  # discovers plugin manifests
│  │  └─ contracts.py                 # Pydantic models (RunConfig, Finding, Artifact)
│  ├─ plugins/                        # PLUGGABLE MODULES (scan/attack/report/etc.)
│  │  ├─ web/                         # web security modules
│  │  │  ├─ zap/
│  │  │  │  ├─ main.py                # module trigger (stdin JSON -> stdout JSON)
│  │  │  │  ├─ subtasks/              # internal steps (spider, ajax, active)
│  │  │  │  └─ manifest.yaml          # id, inputs, outputs, capabilities
│  │  │  ├─ nuclei/
│  │  │  │  ├─ main.py
│  │  │  │  ├─ subtasks/
│  │  │  │  └─ manifest.yaml
│  │  │  ├─ sqlmap/
│  │  │  ├─ ffuf/
│  │  │  └─ content-discovery/        # feroxbuster/dirsearch
│  │  ├─ mobile/
│  │  │  ├─ ios/mobsf/
│  │  │  └─ android/mobsf/
│  │  ├─ api/                         # OpenAPI/GraphQL/Schemathesis (future)
│  │  └─ oast/interactsh/             # out-of-band callbacks (future)
│  ├─ reporting/
│  │  ├─ aggregate.py                 # merge tool outputs -> unified findings[]
│  │  ├─ writers/
│  │  │  ├─ html_writer.py
│  │  │  ├─ sarif_writer.py
│  │  │  └─ json_writer.py
│  │  └─ templates/                   # HTML templates, logos, compliance annex
│  ├─ mapping/                        # CWE/OWASP/PCI/ISO/GDPR crosswalks
│  │  ├─ cwe.json
│  │  ├─ owasp_top10.json
│  │  └─ compliance_map.yaml
│  ├─ utils/                          # shared helpers (proc, io, redact, auth)
│  └─ validators/                     # schema validators for modules & pipelines
│
├─ pipelines/                         # declarative pipelines (plug-and-play)
│  ├─ web_default.yaml
│  ├─ web_active_plus_oast.yaml
│  ├─ api_fuzz.yaml
│  └─ mobile_basic.yaml
│
├─ configs/                           # runtime configs (env-agnostic)
│  ├─ policies/                       # scan policies (e.g., zap active policies)
│  ├─ wordlists/                      # optional local lists (can symlink SecLists)
│  ├─ nuclei/                         # nuclei config overrides
│  └─ auth/                           # login scripts, storageState, csrf names
│
├─ data/
│  ├─ runs/
│  │  └─ {run_id}/                    # one folder per run (immutable)
│  │     ├─ inputs/                   # scope, pipeline snapshot, redacted creds
│  │     ├─ workspace/                # tool working dirs
│  │     ├─ artifacts/                # raw tool outputs (JSON/HTML/TXT)
│  │     ├─ findings.json             # normalized findings
│  │     ├─ manifest.json             # tool versions, flags, start/end, hashes
│  │     └─ reports/                  # html, sarif, csv/xlsx
│  └─ cache/                          # nuclei templates, fingerprints, tmp
│
├─ infra/                             # deployment bits
│  ├─ docker/
│  ├─ k8s/
│  └─ ci/                             # CI pipelines (lint, unit, e2e, release)
│
├─ scripts/                           # dev scripts (bootstrap, doctor, local-run)
├─ docs/                              # architecture, module authoring guide, API docs
└─ pyproject.toml / requirements.txt
Why this architecture?
Separation of concerns
apps/ hosts the interfaces (API, worker, web portal).
core/ holds the engine logic and plugins (scanners, attacks, reporting).
pipelines/ describes what to run; core/ implements how to run.
Pluggable modules
Each tool lives in core/plugins/**/ with a manifest.yaml and a single trigger main.py.
Modules are language-agnostic: they read JSON on stdin and return JSON on stdout.
Swap or add tools (e.g., ZAP ↔︎ Burp Enterprise API, ffuf ↔︎ wfuzz) without touching the engine.
Reproducibility
Every run writes an immutable data/runs/{run_id}/manifest.json (tool versions, params, timestamps).
Artifacts and findings.json are preserved for audit, retest, and reporting.
Scales from CLI to product
Start by running modules individually; later, the worker and pipeline engine orchestrate end-to-end flows.
infra/ gives you a clean path to Docker/Kubernetes/CI.
Key Components
apps/api
Small FastAPI stub to submit jobs (pipelines + inputs) and query run state.
Replace in-memory store with DB/queue when you wire real workers.
apps/worker
Long-running process that consumes a queue and calls the pipeline engine.
Adapter folder for Redis/Rabbit/SQS so you can switch infra without code churn.
core/pipeline
contracts.py: Pydantic models for RunConfig, Finding, Artifact, etc.
registry.py: discovers plugins via their manifest.yaml.
engine.py: executes a list of modules (sequential placeholder; later: DAG, retries, budgets, parallelism).
core/plugins
Where the actual scanners live (web, mobile, api, oast).
Each module:
manifest.yaml → identity, inputs, outputs, capabilities.
main.py → the main trigger (reads a ModuleInput, emits a ModuleOutput).
subtasks/ → optional breakdown (e.g., ZAP spider, Ajax spider, active scan).
core/reporting
aggregate.py merges outputs into a unified findings[] list.
Writers: html_writer.py, sarif_writer.py, json_writer.py.
templates/ for branding, compliance annex, and print-friendly CSS.
mapping/
Static crosswalks (CWE, OWASP Top 10, PCI/ISO/GDPR) to enrich each finding with industry tags.
pipelines/
YAML recipes describing stages and which plugins to run.
Keep product presets here (e.g., web_default, web_active_plus_oast, api_fuzz).
configs/
Policy files, wordlists, Nuclei overrides, and auth recipes (login scripts, storageState, CSRF names).
data/
Single source of truth for run outputs. Everything needed to reproduce a run is here.
JSON I/O Contract (modules)
Input (stdin)
{
  "run_id": "2025-08-21T12-00Z-abc",
  "workdir": "data/runs/2025-08-21T12-00Z-abc/workspace",
  "inputs": { "target_url": "https://example.com" },
  "env": { }
}
Output (stdout)
{
  "status": "ok",
  "artifacts": [
    { "path": "data/runs/.../workspace/zap-baseline.json",
      "description": "ZAP baseline output",
      "content_type": "application/json" }
  ],
  "findings": [
    { "id": "XSS-REFLECTED",
      "title": "Reflected XSS",
      "severity": "high",
      "location": "https://example.com/search?q=",
      "tool": "zap",
      "rule_id": "12345",
      "cwe": "CWE-79",
      "owasp": "A03:2021" }
  ],
  "stats": { "duration_sec": 120 }
}
Keep modules pure: no global state, write artifacts only inside workdir, return results in JSON.
Quick Start
Create & activate env
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
Run API stub (optional)
uvicorn apps.api.main:app --reload
# POST /jobs with {"pipeline_id":"web_default","inputs":{"target_url":"https://example.com"}}
Run a module directly (individual testing)
python core/plugins/web/nuclei/main.py --stdin <<'JSON'
{"run_id":"dev1","workdir":"data/runs/dev1/workspace","inputs":{},"env":{}}
JSON
Generate a simple HTML report from findings.json
# python - <<'PY'
from core.reporting.writers.html_writer import write
import json, pathlib
p = pathlib.Path("data/runs/dev1/workspace/findings.json")
data = json.loads(p.read_text()) if p.exists() else {"findings":[]}
write(data, "data/runs/dev1/reports/report.html")
# PY
Design Principles
Plug & Play: Add modules without touching the engine.
Stateless Workers: Everything required for a run is in RunConfig + configs/.
Deterministic: Same inputs → same outputs. Pin template/tool versions in manifest.json.
Safety First: Enforce allow/deny lists; require scope acknowledgement; add rate limits.
Auditability: Keep raw artifacts and a human-readable report; export SARIF for CI.
Adding a New Plugin (example)
Create core/plugins/<domain>/<tool>/.
Add manifest.yaml:
id: web.mytool
version: "0.1.0"
type: scan
inputs: [ target_url ]
outputs:
  - artifacts: ["mytool.json"]
  - findings: true
capabilities: [ passive ]
Implement main.py:
Read JSON from stdin
Run the tool (or stub)
Save artifacts under workdir
Print a valid ModuleOutput JSON to stdout
Reference it in a pipeline under pipelines/*.yaml.


docker build -t whz/vapt-zap:0.1.0     core/plugins/web/zap
docker build -t whz/vapt-nuclei:0.1.0  core/plugins/web/nuclei
docker build -t whz/vapt-report-html:0.1.0 core/reporting/report_module


Week 1 Progress Overview:

Core Engine & Pipeline Setup:

Core Engine Configuration: Set up the core pipeline engine using RunConfig, ModuleInput/Output, Finding, Artifact, and ModuleResult in core/pipeline/contracts.py. Configured a sequential pipeline engine in core/pipeline/engine.py for processing jobs.

Plugin Registration & Discovery:

Dynamic Module Discovery: Implemented dynamic module discovery in core/pipeline/registry.py using manifest.yaml. This allows automatic registration and discovery of plugins located in core/plugins/**/manifest.yaml.

Job Queueing Setup:

In-memory Queue: Set up a basic job queueing system for worker execution, using an in-memory store for the initial version. A more robust solution (like Redis) is planned for future updates.

ZAP Baseline Integration:

ZAP Baseline Scan: Integrated the ZAP baseline scan for passive scanning. The wrapper was created, and the ZAP tool can be triggered via the CLI. After installing ZAP (docker or local), it generates real findings.

Nuclei Integration:

Nuclei Template Scanning: Integrated Nuclei for automated vulnerability scanning with templates. The Nuclei module was created, and it correctly parses the jsonl files, running against multiple templates.

Basic Reporting:

HTML Reporting: Implemented an HTML report generation system. The report is generated from findings, but the initial issue was that the findings were not being correctly captured in the HTML output.

Current Issue:

Currently, the Nuclei scan results are being generated but not properly reflected in the HTML report. Here’s a breakdown of the problem:

Nuclei Scan Output: The Nuclei module (web.nuclei.basic) runs successfully, and the findings are stored in a nuclei.jsonl file. However, the HTML report generation module (report.html) is not capturing these findings correctly and not displaying them in the generated HTML report.

Debugging Logs:

Nuclei runs without errors but reports no findings in its output.

The findings in the JSON file are empty, likely because Nuclei doesn’t find any vulnerabilities based on the current templates and target URL.

Potential Reasons:

Nuclei Templates: The templates used for scanning may not be sufficient or aligned with the target, resulting in no findings. The templates may need to be expanded, or more targeted templates should be used for the specific URL.

Pipeline Configuration: There could be a configuration issue in the pipeline setup where the Nuclei findings are not properly fed into the report generation system. The report.html module might not be processing the nuclei.jsonl file correctly.

Permissions/Write Path: There may be permission issues, particularly related to the Docker container's ability to write to the artifacts directory, preventing findings from being captured or displayed.

Proposed Solution:

Check Nuclei Findings:

Verify that the nuclei.jsonl file is being populated with valid findings and that Nuclei is properly scanning the URL. You can manually test the scanning by running the Nuclei tool outside the pipeline with specific templates and checking the output.

Validate Report Generation:

Ensure the main.py script is correctly handling the findings from nuclei.jsonl and generating the HTML report. If necessary, add debug logs to confirm the content of nuclei.jsonl and see how it’s processed for the HTML output.

Review Template Selection:

Check the Nuclei template set being used and ensure it covers the vulnerabilities relevant to the target site. You may need to modify the pipeline configuration to include high-signal templates, such as those targeting misconfigurations, common vulnerabilities, or outdated software.

Ensure Correct Permissions:

Confirm that Docker has write permissions for the artifacts directory (/artifacts), and that Nuclei’s output files are correctly placed in this directory.

Once these steps are followed, you should be able to see the findings in the HTML report generated at /artifacts/report.html. If the issue persists, more detailed logs or template adjustments might be required. Let me know if you need further guidance!




Week-2 · Day-8 — ZAP Full Scan + Debugging (Testfire)

Date: 2025-08-26
Scope: Enable ZAP active scanning, add rich debug logs, and verify runs against https://testfire.net.
Outputs: HTML/JSON reports + normalized findings + streaming debug log.

What changed (Changelog)

core/plugins/web/zap/main.py

Added mode: "full" support (kept baseline intact).

Docker fallback now defaults to ghcr.io/zaproxy/zaproxy:stable.

New debug log at artifacts/zap-debug.log (heartbeat + full command).

Hard timeout guard (derived from max_duration_min).

Normalized findings saved to workspace/zap/findings.json.

New inputs:

ajax_spider: bool

max_duration_min: int

risk_threshold: "informational"|"low"|"medium"|"high"

include_patterns: string[]

exclude_patterns: string[]

debug: bool (adds -d to wrapper)

extra_zap: string[] (optional, extra -z configs to ZAP)

Environment switches

ZAP_DOCKER_IMAGE (default: ghcr.io/zaproxy/zaproxy:stable)

ZAP_DOCKER_EXTRA_ARGS (e.g., --network host, or host gateway mapping)

Directory layout (per run)