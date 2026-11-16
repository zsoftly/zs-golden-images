#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
[[ $# == 0 || ($# == 1 && $1 == --legacy) ]] || {
  printf '%s\n' 'Usage: validate.sh [--legacy]' >&2
  exit 1
}
python=${PYTHON:-python3}
for dependency in "$python" ansible-playbook shellcheck jq rg; do
  command -v "$dependency" >/dev/null || { printf '[FAIL] Missing tool: %s\n' "$dependency" >&2; exit 1; }
done
export PYTHONDONTWRITEBYTECODE=1
export ANSIBLE_ROLES_PATH="$PWD/ansible/roles"

shell_files=()
while IFS= read -r -d '' script; do
  bash -n "$script"
  shell_files+=("$script")
done < <(rg --files -0 -g '*.sh' -g 'builders/diskimage-builder/elements/*/root.d/*' -g 'builders/diskimage-builder/elements/*/post-root.d/*' -g 'builders/diskimage-builder/elements/*/cleanup.d/*' -g '!artifacts/**')
shellcheck "${shell_files[@]}"

for playbook in ansible/playbooks/*.yml; do
  ansible-playbook --syntax-check -i localhost, -e node=localhost "$playbook"
done

"$python" - <<'PY'
import ast
import json
from pathlib import Path

try:
    import yaml
    from jinja2 import Environment
except ImportError as exc:
    raise SystemExit("Validation needs PyYAML and Jinja2. Use the Python environment from requirements-dev.txt via PYTHON.") from exc

for directory in (Path("scripts"), Path("tests")):
    for source in directory.rglob("*.py"):
        ast.parse(source.read_text(), filename=str(source))
for directory in (Path("ansible"), Path("builders"), Path("config"), Path("audit"), Path(".github")):
    for source in directory.rglob("*"):
        if not source.is_file():
            continue
        try:
            if source.suffix in (".yml", ".yaml"):
                list(yaml.safe_load_all(source.read_text()))
            elif source.suffix == ".json":
                json.loads(source.read_text())
            elif source.suffix == ".j2":
                Environment().parse(source.read_text())
        except Exception as exc:
            raise SystemExit(f"{source}: {exc}") from exc
PY
for test_script in tests/*.sh; do bash "$test_script"; done
"$python" -m unittest discover -s tests -p 'test_*.py' -v

if [[ ${1:-} == --legacy ]]; then
  command -v packer >/dev/null || { printf '%s\n' '[FAIL] Legacy checks require Packer.' >&2; exit 1; }
  packer fmt -check -recursive packer profiles
  packer validate -syntax-only packer/proxmox
fi
git diff --check
printf '%s\n' '[OK] Offline validation passed. No image build or live acceptance test ran.'
