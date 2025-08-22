def write(data, path):
  # TODO: map findings -> SARIF schema
  open(path,'w').write('{"version":"2.1.0","runs":[]}')
