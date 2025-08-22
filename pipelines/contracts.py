from __future__ import annotations
from typing import Any, Dict, List, Optional, Literal
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RunConfig(BaseModel):
    run_id: str
    target: str
    pipeline_name: str
    modules: List[str] = Field(..., description="Module IDs in execution order")
    timeout_sec: int = 3600
    workspace_dir: str
    artifacts_dir: str
    inputs_dir: str
    reports_dir: str
    extra: Dict[str, Any] = {}


class ModuleInput(BaseModel):
    run_id: str
    target: str
    workspace_dir: str
    artifacts_dir: str
    previous_outputs: Dict[str, Any] = {}
    config: Dict[str, Any] = {}


class Artifact(BaseModel):
    path: str
    type: Literal["json","html","txt","xml","bin"] = "json"
    description: Optional[str] = None


class Finding(BaseModel):
    id: str
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    tags: List[str] = []
    location: Optional[str] = None        # URL / endpoint
    evidence: Optional[Dict[str, Any]] = None
    cwe: Optional[List[str]] = None
    owasp: Optional[List[str]] = None
    tool: Optional[str] = None            # nuclei/zap/etc.


class ModuleResult(BaseModel):
    module_id: str
    started_at: datetime
    ended_at: datetime
    status: Literal["ok","error","skipped"] = "ok"
    error: Optional[str] = None
    findings: List[Finding] = []
    artifacts: List[Artifact] = []
    raw_output: Optional[Any] = None      # keep a compact preview


class PipelineResult(BaseModel):
    run_id: str
    pipeline_name: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    results: List[ModuleResult] = []
