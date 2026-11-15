#!/usr/bin/env bash
set -euo pipefail
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'Usage: run-remediation.sh /absolute/candidate-inventory /absolute/private-settings.yml'
[[ ${GOLDEN_APPLY:-} == remediate ]] || fail 'Explicit disposable-VM remediation authorization is required.'
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ "$1" == /* && -f "$1" && "$2" == /* && -f "$2" ]] || fail 'Supply existing absolute private files.'
ANSIBLE_COLLECTIONS_PATH=/opt/zs-golden-images/collections ANSIBLE_ROLES_PATH="$repo/ansible/roles"
export ANSIBLE_COLLECTIONS_PATH ANSIBLE_ROLES_PATH
/opt/zs-golden-images/venv/bin/ansible-playbook -i "$1" "$repo/ansible/playbooks/50-remediate-vm.yml" -e "@$2" --tags level1-server
