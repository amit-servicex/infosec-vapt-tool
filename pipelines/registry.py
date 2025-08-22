from __future__ import annotations
from pathlib import Path
from typing import List, Optional
import yaml
from pydantic import BaseModel


PLUGIN_ROOT = Path(__file__).resolve().parents[1] / "plugins"


class ModuleSpec(BaseModel):
    id: str
    name: str
    entrypoint: str
    description: str = ""
    capabilities: list[str] = []


def _read_manifest(p: Path) -> Optional[ModuleSpec]:
    try:
        with open(p, "r") as f:
            data = yaml.safe_load(f)
        ep = (p.parent / data["entrypoint"]).resolve()
        return ModuleSpec(
            id=data["id"],
            name=data.get("name", data["id"]),
            entrypoint=str(ep),
            description=data.get("description",""),
            capabilities=data.get("capabilities", []),
        )
    except Exception:
        return None


def discover_modules() -> List[ModuleSpec]:
    specs: List[ModuleSpec] = []
    for manifest in PLUGIN_ROOT.rglob("manifest.yaml"):
        spec = _read_manifest(manifest)
        if spec:
            specs.append(spec)
    return specs
