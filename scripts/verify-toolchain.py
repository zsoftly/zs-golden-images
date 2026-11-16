#!/usr/bin/env python3
"""Verify the existing protected builder installation against reviewed pins."""
import hashlib, importlib.util, json, pathlib, stat, subprocess, sys
record = pathlib.Path('/etc/zs-golden-images/toolchain.json')
st = record.lstat()
if record.is_symlink() or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
    raise SystemExit('Toolchain manifest must be root-owned mode 0600')
installed = json.loads(record.read_text())
expected = json.load(open(sys.argv[1]))
if hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest() != installed.get('python_lock_sha256'):
    raise SystemExit('Installed Python dependency lock does not match reviewed source')
freeze = subprocess.check_output(['/opt/zs-golden-images/venv/bin/python', '-m', 'pip', 'freeze', '--all'])
if hashlib.sha256(freeze).hexdigest() != installed.get('python_inventory_sha256'):
    raise SystemExit('Installed Python dependency inventory changed since bootstrap')
collection_files = pathlib.Path(sys.argv[3])
spec = importlib.util.spec_from_file_location('collection_integrity', collection_files / 'collection_integrity.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
pins = json.loads((collection_files / 'collections.json').read_text())
if module.inventory('/opt/zs-golden-images/collections', pins) != installed.get('collections'):
    raise SystemExit('Installed Ansible collections differ from the reviewed toolchain')
for name, path in {
    'diskimage_builder': '/opt/zs-golden-images/venv/bin/disk-image-create',
    'distrobuilder': '/opt/zs-golden-images/bin/distrobuilder',
}.items():
    if installed.get(name) != expected[name]:
        raise SystemExit('Installed builder provenance does not match source pins')
    binary = pathlib.Path(path)
    for parent in [binary, *binary.parents]:
        info = parent.lstat()
        if parent.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise SystemExit('Builder executable path must be root-owned and protected')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != installed.get('executables', {}).get(name):
        raise SystemExit('Builder executable does not match its installation record')
