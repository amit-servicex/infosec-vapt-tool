from __future__ import annotations
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
from pydantic import BaseModel

PLUGIN_ROOT = Path(__file__).resolve().parents[1] / "plugins"
_INDEX: Optional[Dict[str, "ModuleSpec"]] = None

class VolumeSpec(BaseModel):
    name: str
    mountPath: str

class ResourceSpec(BaseModel):
    cpu: Optional[str] = None
    memory: Optional[str] = None

class ModuleSpec(BaseModel):
    id: str                  # e.g. web.nuclei.basic
    name: str
    entrypoint: Optional[str] = None  # local process fallback
    description: str = ""
    capabilities: List[str] = []
    # Docker runtime fields (optional):
    runtime: Optional[str] = None     # "docker" | "process" | None
    image: Optional[str] = None
    cmd: Optional[List[str]] = None   # command inside container
    env: Optional[List[str]] = None   # ["KEY=value", ...]
    volumes: Optional[List[VolumeSpec]] = None
    resources: Optional[ResourceSpec] = None
    user: Optional[str] = None        # e.g., "1000:1000"
    workdir: Optional[str] = None     # e.g., "/app"
    network: Optional[str] = None     # e.g., "bridge" (default)

def _read_manifest(p: Path) -> Optional[ModuleSpec]:
    try:
        data = yaml.safe_load(p.read_text()) or {}
        entrypoint = data.get("entrypoint")
        ep = None
        if entrypoint:
            ep = str((p.parent / entrypoint).resolve())
        return ModuleSpec(
            id=data["id"],
            name=data.get("name", data["id"]),
            entrypoint=ep,
            description=data.get("description",""),
            capabilities=list(data.get("capabilities", [])),
            runtime=data.get("runtime"),
            image=data.get("image"),
            cmd=list(data.get("cmd", [])) if data.get("cmd") else None,
            env=list(data.get("env", [])) if data.get("env") else None,
            volumes=[VolumeSpec(**v) for v in data.get("volumes", [])] or None,
            resources=ResourceSpec(**data.get("resources", {})) if data.get("resources") else None,
            user=data.get("user"),
            workdir=data.get("workdir"),
            network=data.get("network"),
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

def load_index(force: bool = False) -> Dict[str, ModuleSpec]:
    global _INDEX
    if _INDEX is None or force:
        _INDEX = {s.id: s for s in discover_modules()}
    return _INDEX

def resolve_ids(ids: List[str]) -> List[ModuleSpec]:
    idx = load_index()
    out: List[ModuleSpec] = []
    for mid in ids:
        if mid not in idx:
            raise KeyError(f"Module ID not found in registry: {mid}")
        out.append(idx[mid])
    return out
