def write(data, path):
  import json, pathlib
  pathlib.Path(path).write_text(json.dumps(data, indent=2), encoding='utf-8')
