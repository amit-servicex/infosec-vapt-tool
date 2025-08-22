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