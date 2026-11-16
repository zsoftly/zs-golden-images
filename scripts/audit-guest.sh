#!/usr/bin/env bash
set -euo pipefail
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
[[ $# == 3 ]] || fail 'Usage: audit-guest.sh profile /absolute/bundle /absolute/new-evidence-directory'
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
for dependency in jq git sha256sum systemd-detect-virt; do
  command -v "$dependency" >/dev/null || fail "Required guest tool missing: $dependency"
done
profile=$1
bundle=$2
output=$3
pin=$(jq -ce --arg p "$profile" '.profiles[$p] // error("Unsupported profile")' "$repo/audit/pins.json") || fail 'Unsupported profile or invalid pin file.'
[[ ${GOLDEN_APPLY:-} == audit ]] || fail 'Set GOLDEN_APPLY=audit only inside an authorized disposable image clone.'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 && $EUID == 0 ]] || fail 'Audit requires an amd64 Linux guest as root.'
[[ ! -e /etc/pve && $(systemd-detect-virt) == kvm ]] || fail 'Audit is restricted to KVM guests, never Proxmox hosts or containers.'
# This is a guest-only command. It has no inventory or remote execution path.
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == "$(jq -r .os_id <<< "$pin")" && ${VERSION_ID:-} == "$(jq -r .os_version <<< "$pin")" ]] || fail 'OS does not match profile.'
jq -e --arg p "$profile" '.profile == $p and
  (if .source_kind == "apt-snapshot" then .acceptance_source == "signed-release-metadata" and .target == "cloudstack-kvm" else .status == "experimental-unaccepted" end) and
  (.source_commit | test("^[0-9a-f]{40}$")) and
  ((if .source_kind == "apt-snapshot" then .source_manifest_sha256 else .source_image_sha256 end) | test("^[0-9a-f]{64}$"))' /etc/golden-image.json >/dev/null || fail 'Expected matching golden-image provenance; acceptance is recorded externally.'
[[ "$bundle" == /* && -d "$bundle/content/.git" && -f "$bundle/syver" ]] || fail 'Supply a prepared bundle.'
[[ $(git -C "$bundle/content" rev-parse HEAD) == "$(jq -r .audit_commit <<< "$pin")" ]] || fail 'Unexpected audit commit.'
tree_status=$(git -C "$bundle/content" status --porcelain --untracked-files=all --ignored) || fail 'Cannot verify audit content.'
[[ -z "$tree_status" ]] || fail 'Audit content must exactly match its pin without additional files.'
bundle=$(cd -- "$bundle" && pwd -P)
[[ $(sha256sum "$bundle/syver" | awk '{print $1}') == "$(jq -r .syver.sha256 "$repo/audit/pins.json")" ]] || fail 'Unexpected audit binary checksum.'
[[ "$output" == /* && ! -e "$output" && ! -L "$output" ]] || fail 'Evidence directory must be a new absolute path.'
parent=$(cd -- "$(dirname -- "$output")" && pwd -P)
[[ "$parent/" != "$repo/"* && "$parent/" != "$bundle/"* ]] || fail 'Keep private audit evidence outside the source and dependency trees.'
umask 077
mkdir -- "$output"
cp /etc/golden-image.json "$output/image.json"
# Inline values override upstream vars. No operator override path enables L2 or heavy tests.
vars=$(jq -c '.overrides + {system_type:"Server", benchmark_type:"CIS", benchmark_os:.os_id,
  benchmark_version:.benchmark_version, machine_uuid:"withheld", epoch:"withheld",
  os_locale:"C", os_release:.os_version, os_distribution:.os_id,
  auto_group:"disposable-build", os_hostname:"withheld"}' <<< "$pin")
printf '%s\n' "$vars" > "$output/overrides.json"
audit_status=0
(
  cd -- "$bundle/content"
  "$bundle/syver" -g "$(jq -r .entrypoint <<< "$pin")" --vars vars/CIS.yml \
    --vars-inline "$vars" validate --max-concurrent 2 --format json --format-options pretty
) > "$output/raw.json" 2> "$output/stderr.log" || audit_status=$?
printf '%s\n' "$audit_status" > "$output/audit-exit-code.txt"
report_status=0
"$repo/scripts/report-audit.sh" "$profile" "$output/raw.json" "$output/report" || report_status=$?
[[ "$report_status" == 2 ]] || fail 'Audit output could not be validated. Retain the private evidence for review.'
[[ "$audit_status" == 0 || "$audit_status" == 1 ]] || fail 'Audit process failed. Retain the private evidence for review.'
printf '%s\n' '[BLOCKED] Audit captured; remediation, coverage review, and guest acceptance remain required.'
exit 2
