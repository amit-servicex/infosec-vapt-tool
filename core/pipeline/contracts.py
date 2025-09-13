# from __future__ import annotations
# from pydantic import BaseModel, Field
# from typing import Any, Dict, List, Optional

# class Artifact(BaseModel):
#     path: str
#     description: Optional[str] = None
#     content_type: Optional[str] = None

# class Finding(BaseModel):
#     id: str
#     title: str
#     severity: str
#     description: Optional[str] = None
#     location: Optional[str] = None
#     evidence: Optional[Dict[str, Any]] = None
#     tool: Optional[str] = None
#     rule_id: Optional[str] = None
#     cwe: Optional[str] = None
#     owasp: Optional[str] = None

# class RunConfig(BaseModel):
#     run_id: str
#     pipeline_id: str
#     workdir: str
#     inputs: Dict[str, Any] = Field(default_factory=dict)
#     env: Dict[str, str] = Field(default_factory=dict)
#     allowlist: List[str] = Field(default_factory=list)
#     blocklist: List[str] = Field(default_factory=list)

# class ModuleResult(BaseModel):
#     status: str = "ok"
#     message: Optional[str] = None
#     artifacts: List[Artifact] = Field(default_factory=list)
#     findings: List[Finding] = Field(default_factory=list)
#     stats: Dict[str, Any] = Field(default_factory=dict)

# core/pipeline/contracts.py
from __future__ import annotations
from typing import Any, Dict, List, Optional, Literal
from datetime import datetime
from pydantic import BaseModel, Field

class Artifact(BaseModel):
    path: str
    description: Optional[str] = None
    content_type: Optional[str] = None

class Finding(BaseModel):
    id: str
    title: str
    severity: str
    description: Optional[str] = None
    location: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    tool: Optional[str] = None
    rule_id: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    sources: Optional[List[str]] = None       # for OAST etc.
    confidence: Optional[str] = None          # low/medium/high
    # optional helpers carried by some modules
    request_fp: Optional[str] = None

class RunConfig(BaseModel):
    # required by your code
    run_id: str
    pipeline_id: str
    workdir: str

    # commonly used/expected by engine & local_run
    pipeline_name: Optional[str] = None
    target: Optional[str] = None
    workspace_dir: Optional[str] = None
    artifacts_dir: Optional[str] = None
    inputs_dir: Optional[str] = None
    reports_dir: Optional[str] = None

    # per-module configuration from YAML (your engine looks up `extra.get(<module_id>)`)
    extra: Dict[str, Any] = Field(default_factory=dict)

    # generic input/env
    inputs: Dict[str, Any] = Field(default_factory=dict)
    env: Dict[str, str] = Field(default_factory=dict)

    # optional lists
    allowlist: List[str] = Field(default_factory=list)
    blocklist: List[str] = Field(default_factory=list)

    # optional pipeline visualization / bookkeeping
    modules: List[str] = Field(default_factory=list)

class ModuleResult(BaseModel):
    module_id: Optional[str] = None
    status: Literal["ok","error"] = "ok"
    message: Optional[str] = None
    error: Optional[str] = None
    artifacts: List[Artifact] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None

class PipelineResult(BaseModel):
    run_id: str
    pipeline_name: str
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    results: List[Dict[str, Any]] = Field(default_factory=list)  # keep loose for mixed modules
