#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("--input")
    args = ap.parse_args()

    payload = {}
    if args.stdin:
        payload = json.loads(sys.stdin.read())
    elif args.input:
        payload = json.loads(open(args.input, "r", encoding="utf-8").read())

    workdir = pathlib.Path(payload.get("workdir", "./data/runs/dev"))
    workdir.mkdir(parents=True, exist_ok=True)

    out_file = workdir / "nuclei.json"
    out_file.write_text(json.dumps({"stub": True}), encoding="utf-8")

    sys.stdout.write(json.dumps({
        "status": "ok",
        "artifacts": [{"path": str(out_file), "description": "Nuclei output (stub)", "content_type": "application/json"}],
        "findings": [],
        "stats": {}
    }))

if __name__ == "__main__":
    main()
