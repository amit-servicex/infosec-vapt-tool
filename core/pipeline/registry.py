import pathlib, yaml
from typing import Dict

def discover(root: str) -> Dict[str, str]:
    rootp = pathlib.Path(root)
    out = {}
    for mf in rootp.rglob("manifest.yaml"):
        rel = mf.parent.relative_to(rootp).as_posix()
        module_id = rel.replace("/", ".")
        out[module_id] = str(mf)
    return out

def load_manifest(path: str) -> dict:
    return yaml.safe_load(open(path, "r", encoding="utf-8"))
