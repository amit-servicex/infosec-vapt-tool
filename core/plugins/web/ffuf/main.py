#!/usr/bin/env python3
import argparse, json, pathlib, sys
def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--stdin", action="store_true"); ap.add_argument("--input"); args = ap.parse_args()
    payload = json.loads(sys.stdin.read()) if args.stdin else json.loads(open(args.input,"r").read())
    workdir = pathlib.Path(payload.get("workdir","./data/runs/dev")); workdir.mkdir(parents=True, exist_ok=True)
    f = workdir / "ffuf.txt"; f.write_text("[stub] ffuf results\n", encoding="utf-8")
    print(json.dumps({"status":"ok","artifacts":[{"path":str(f),"description":"ffuf results","content_type":"text/plain"}],"findings":[],"stats":{}}))
if __name__ == "__main__": main()
