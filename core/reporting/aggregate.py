import json
from pathlib import Path
from typing import List, Dict, Any

def merge_results(results_json_path: Path) -> List[Dict[str,Any]]:
    obj = json.loads(results_json_path.read_text())
    findings: List[Dict[str,Any]] = []
    for r in obj.get("results", []):
        for f in r.get("findings", []):
            findings.append(f)
    return findings
