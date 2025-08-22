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
    target = payload.get("inputs", {}).get("target_url", "https://example.com")

    out_file = workdir / "zap-baseline.json"
    out_file.write_text(json.dumps({"stub": True, "target": target}), encoding="utf-8")

    result = {
        "status": "ok",
        "artifacts": [{"path": str(out_file), "description": "ZAP baseline (stub)", "content_type": "application/json"}],
        "findings": [],
        "stats": {}
    }
    sys.stdout.write(json.dumps(result))

if __name__ == "__main__":
    main()
