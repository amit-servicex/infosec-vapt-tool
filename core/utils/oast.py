#!/usr/bin/env python3
import json, hashlib, pathlib, time

def request_fingerprint(method, url, params=None, headers=None, body=None):
    h = hashlib.sha256()
    h.update(method.upper().encode())
    h.update(url.encode())
    if params: h.update(json.dumps(params, sort_keys=True).encode())
    if headers: h.update(json.dumps(headers, sort_keys=True).encode())
    if body: h.update((body if isinstance(body, (bytes, bytearray)) else str(body)).encode())
    return h.hexdigest()[:16]

def bind_token(workdir, fp, token, extra=None):
    """Append (request_fp -> token) into workspace/oast/token_map.json"""
    p = pathlib.Path(workdir) / "oast" / "token_map.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {"bindings": []}
    if p.exists():
        try: data = json.loads(p.read_text())
        except Exception: pass
    data["bindings"].append({
        "fp": fp, "token": token, "ts": int(time.time()), "meta": (extra or {})
    })
    p.write_text(json.dumps(data, ensure_ascii=False))

def inject_marker_headers(headers: dict, token: str):
    headers = dict(headers or {})
    headers["X-OAST"] = token
    return headers

def inject_marker_params(params: dict, token: str):
    params = dict(params or {})
    params["oast"] = token
    return params
