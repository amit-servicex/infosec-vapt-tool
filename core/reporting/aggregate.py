from __future__ import annotations
import json, pathlib
from typing import List, Dict, Any

def merge(outputs: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings, artifacts = [], []
    for out in outputs:
        findings.extend(out.get("findings", []))
        artifacts.extend(out.get("artifacts", []))
    return {"findings": findings, "artifacts": artifacts}
