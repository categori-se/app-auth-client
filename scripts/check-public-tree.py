import json, pathlib, re, subprocess
root=pathlib.Path(__file__).resolve().parents[1]
expected=json.loads((root/'public-files.json').read_text())
actual=subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().split('\0')[:-1]
assert sorted(actual)==expected, 'Export allowlist differs from tracked tree'
assert 'Apache License' in (root/'LICENSE').read_text()
patterns=[rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',rb'ghp_[A-Za-z0-9]{30,}',rb'github_pat_[A-Za-z0-9_]{40,}',rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',rb'/home/'+b'aaron/']
for name in actual:
 p=root/name
 assert p.is_file() and not p.is_symlink(), name
 raw=p.read_bytes()
 assert not any(re.search(pattern,raw) for pattern in patterns),name
 if p.name in ('package.json','ecosystem-module.json'):
  assert json.loads(raw)['license']=='Apache-2.0',name
print(f'Validated {len(actual)} allowlisted Apache-2.0 source files')
