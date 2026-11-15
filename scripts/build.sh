#!/usr/bin/env bash
set -euo pipefail

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
usage() { printf '%s\n' 'Usage: scripts/build.sh validate|seed|build debian-13|ubuntu-26.04 /absolute/site.json [inventory-for-seed]'; }
[[ $# -ge 3 && $# -le 4 ]] || { usage >&2; exit 1; }
action=$1
profile=$2
site=$3
case "$action" in validate|seed|build) ;; *) fail 'Unknown action.' ;; esac
case "$profile" in debian-13) : ;; ubuntu-26.04) : ;; *) fail 'Unsupported OS profile.' ;; esac
[[ "$site" == /* && -f "$site" ]] || fail 'Supply an absolute existing site JSON file outside the repository.'
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
site_dir=$(cd -- "$(dirname -- "$site")" && pwd -P)
[[ "$site_dir/" != "$repo/"* ]] || fail 'Private site input must stay outside the public repository.'
command -v jq >/dev/null || fail 'jq is required.'
jq -e '
  (keys | sort) == (["bridge","cpu_type","gateway","image_version","ip_address","nameserver","node","proxmox_url","proxmox_username","seed_cache_dir","seed_vm_id","source_image_sha256","source_image_url","ssh_host","storage_pool","template_vm_id","vlan_tag"] | sort) and
  (.seed_vm_id | type == "number") and (.template_vm_id | type == "number") and
  (.seed_vm_id >= 100 and .seed_vm_id <= 999999999 and .seed_vm_id == (.seed_vm_id|floor)) and
  (.template_vm_id >= 100 and .template_vm_id <= 999999999 and .template_vm_id == (.template_vm_id|floor)) and
  .seed_vm_id != .template_vm_id and
  ([del(.seed_vm_id,.template_vm_id)[] | type == "string"] | all) and
  ([del(.seed_vm_id,.template_vm_id)[] | test("[\\r\\n]") | not] | all) and
  (.source_image_sha256 | test("^[0-9a-f]{64}$")) and
  (.proxmox_url | test("^https://[^/]+/api2/json$")) and
  (.proxmox_username | test("^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+$")) and
  (.node | test("^[A-Za-z0-9][A-Za-z0-9-]*$")) and
  (.storage_pool | test("^[A-Za-z0-9][A-Za-z0-9_-]*$")) and
  (.cpu_type as $cpu | ["x86-64-v2", "x86-64-v2-AES", "x86-64-v3", "x86-64-v4"] | index($cpu) != null) and
  (.bridge | test("^[A-Za-z0-9][A-Za-z0-9_.-]*$")) and
  (.ssh_host == (.ip_address | split("/")[0])) and
  (.vlan_tag | test("^[0-9]+$")) and ((.vlan_tag|tonumber) >= 1 and (.vlan_tag|tonumber) <= 4094) and
  (.seed_cache_dir | test("^/([A-Za-z0-9_-][A-Za-z0-9._-]*/){2,}[A-Za-z0-9_-][A-Za-z0-9._-]*$"))
' "$site" >/dev/null || fail 'Invalid site inputs, extra fields, IDs, API URL, or missing checksum.'
image_url=$(jq -r .source_image_url "$site")
case "$profile" in
  debian-13)
    [[ "$image_url" =~ ^https://cloud\.debian\.org/images/cloud/trixie/[0-9]{8}-[0-9]+/debian-13-genericcloud-amd64(-[0-9-]+)?\.qcow2$ ]] || fail 'Use a dated Debian 13 genericcloud amd64 disk URL.'
    ;;
  ubuntu-26.04)
    [[ "$image_url" =~ ^https://cloud-images\.ubuntu\.com/releases/resolute/release-[0-9]{8}/ubuntu-26\.04-server-cloudimg-amd64\.img$ ]] || fail 'Use a dated Ubuntu 26.04 amd64 cloud disk URL.'
    ;;
esac
cd "$repo"
source_commit=$(git rev-parse HEAD)
if [[ "$action" != validate ]]; then
  [[ ${GOLDEN_APPLY:-} == "$action" ]] || fail "Set GOLDEN_APPLY=$action only for the reviewed isolated allocation."
  [[ -z $(git status --porcelain) ]] || fail 'Live operations require a clean committed source tree.'
fi
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/zs-golden-build.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
jq --arg commit "$source_commit" 'del(.seed_cache_dir) + {source_commit:$commit}' "$site" > "$work/site.pkrvars.json"
if [[ "$action" == seed ]]; then
  [[ $# == 4 && -f "$4" ]] || fail 'Seed import requires an explicit Ansible inventory.'
  jq --arg profile "$profile" '. + {os_profile:$profile}' "$site" > "$work/seed.json"
  ansible-playbook -i "$4" ansible/playbooks/00-import-seed.yml --extra-vars "@$work/seed.json"
  exit
fi
[[ $# == 3 ]] || fail 'An inventory argument is only accepted for seed import.'
command -v packer >/dev/null || fail 'Packer is required.'
packer init packer/proxmox
if [[ "$action" == validate ]]; then
  PROXMOX_TOKEN=validation-not-a-credential packer validate -var-file="profiles/$profile.pkrvars.hcl" -var-file="$work/site.pkrvars.json" packer/proxmox
else
  packer validate -var-file="profiles/$profile.pkrvars.hcl" -var-file="$work/site.pkrvars.json" packer/proxmox
fi
[[ "$action" == build ]] || exit 0
[[ -n ${PROXMOX_TOKEN:-} ]] || fail 'Export PROXMOX_TOKEN through the approved credential provider.'
[[ "$PROXMOX_TOKEN" =~ ^[A-Za-z0-9_-]+$ ]] || fail 'Unexpected API token characters.'
api_url=$(jq -r .proxmox_url "$site")
api_user=$(jq -r .proxmox_username "$site")
printf 'header = "Authorization: PVEAPIToken=%s=%s"\n' "$api_user" "$PROXMOX_TOKEN" > "$work/curl.conf"
curl --fail --silent --show-error --connect-timeout 10 --max-time 30 --config "$work/curl.conf" "$api_url/cluster/resources?type=vm" > "$work/guests.json"
jq -e --slurpfile site "$site" '
  $site[0] as $s |
  [.data[] | select(.vmid == $s.seed_vm_id)] as $seed |
  ($seed|length) == 1 and $seed[0].template == 1 and $seed[0].node == $s.node and
  ([.data[] | select(.vmid == $s.template_vm_id)] | length) == 0
' "$work/guests.json" >/dev/null || fail 'Seed missing/on another node, or destination VMID occupied.'
node=$(jq -r .node "$site")
seed_id=$(jq -r .seed_vm_id "$site")
curl --fail --silent --show-error --connect-timeout 10 --max-time 30 --config "$work/curl.conf" "$api_url/nodes/$node/qemu/$seed_id/config" > "$work/seed-config.json"
jq -e --slurpfile site "$site" --arg profile "$profile" '
  .data.description == ("zs-golden-seed profile=" + $profile + " sha256=" + $site[0].source_image_sha256) and
  (.data.scsi0 | startswith($site[0].storage_pool + ":")) and
  .data.onboot == 0 and .data.template == 1
' "$work/seed-config.json" >/dev/null || fail 'Seed provenance does not match the reviewed source checksum.'
mkdir -p artifacts
packer build -on-error=abort -var-file="profiles/$profile.pkrvars.hcl" -var-file="$work/site.pkrvars.json" packer/proxmox
