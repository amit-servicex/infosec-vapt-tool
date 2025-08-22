# core/pipeline/registry.py
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional
import yaml
from pydantic import BaseModel

# Root where plugin trees live: core/plugins/**/manifest.yaml
PLUGIN_ROOT = Path(__file__).resolve().parents[1] / "plugins"

# In-memory index of id -> ModuleSpec
_INDEX: Optional[Dict[str, "ModuleSpec"]] = None


class VolumeSpec(BaseModel):
    name: str
    mountPath: str


class ResourceSpec(BaseModel):
    cpu: Optional[str] = None
    memory: Optional[str] = None


class ModuleSpec(BaseModel):
    # Core identity
    id: str                   # e.g., "web.zap.baseline"
    name: str
    description: str = ""
    capabilities: List[str] = []

    # Local process runtime (fallback)
    entrypoint: Optional[str] = None  # absolute path to main.py

    # Optional Docker runtime metadata
    runtime: Optional[str] = None     # "docker" | "process" | None
    image: Optional[str] = None
    cmd: Optional[List[str]] = None
    env: Optional[List[str]] = None
    volumes: Optional[List[VolumeSpec]] = None
    resources: Optional[ResourceSpec] = None
    user: Optional[str] = None
    workdir: Optional[str] = None
    network: Optional[str] = None


def _read_manifest(path: Path) -> Optional[ModuleSpec]:
    try:
        data = yaml.safe_load(path.read_text()) or {}
        # Resolve entrypoint to an absolute path if provided
        ep = data.get("entrypoint")
        abs_ep = str((path.parent / ep).resolve()) if ep else None

        # Normalize list fields
        caps = list(data.get("capabilities", []) or [])
        cmd = list(data.get("cmd", []) or []) or None
        env = list(data.get("env", []) or []) or None
        vols = [VolumeSpec(**v) for v in (data.get("volumes") or [])] or None
        res = ResourceSpec(**(data.get("resources") or {})) if data.get("resources") else None

        return ModuleSpec(
            id=data["id"],
            name=data.get("name", data["id"]),
            description=data.get("description", ""),
            capabilities=caps,
            entrypoint=abs_ep,
            runtime=data.get("runtime"),
            image=data.get("image"),
            cmd=cmd,
            env=env,
            volumes=vols,
            resources=res,
            user=data.get("user"),
            workdir=data.get("workdir"),
            network=data.get("network"),
        )
    except Exception:
        # Bad manifest — skip it quietly
        return None


def discover_modules() -> List[ModuleSpec]:
    specs: List[ModuleSpec] = []
    for mf in PLUGIN_ROOT.rglob("manifest.yaml"):
        spec = _read_manifest(mf)
        if spec:
            specs.append(spec)
    return specs


def load_index(force: bool = False) -> Dict[str, ModuleSpec]:
    """Build or fetch a cached index of id -> ModuleSpec."""
    global _INDEX
    if _INDEX is None or force:
        _INDEX = {s.id: s for s in discover_modules()}
    return _INDEX


def resolve_ids(ids: List[str]) -> List[ModuleSpec]:
    """Resolve a list of module IDs to ModuleSpec objects (raises if any unknown)."""
    idx = load_index()
    out: List[ModuleSpec] = []
    missing: List[str] = []
    for mid in ids:
        spec = idx.get(mid)
        if not spec:
            missing.append(mid)
        else:
            out.append(spec)
    if missing:
        raise KeyError(f"Module IDs not found: {missing}")
    return out


# (Optional) Keep a helper for legacy callers that want just paths
def resolve_ids_to_paths(ids: List[str]) -> List[str]:
    return [s.entrypoint or "" for s in resolve_ids(ids)]
