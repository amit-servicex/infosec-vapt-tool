from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

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

class RunConfig(BaseModel):
    run_id: str
    pipeline_id: str
    workdir: str
    inputs: Dict[str, Any] = Field(default_factory=dict)
    env: Dict[str, str] = Field(default_factory=dict)
    allowlist: List[str] = Field(default_factory=list)
    blocklist: List[str] = Field(default_factory=list)

class ModuleResult(BaseModel):
    status: str = "ok"
    message: Optional[str] = None
    artifacts: List[Artifact] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)
