#!/usr/bin/env bash
set -euo pipefail
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
[[ $# == 5 ]] || fail 'Usage: configure-rootfs.sh configure|harden|cleanup profile target /absolute/rootfs /absolute/metadata.json'
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
phase=$1 profile=$2 target=$3 rootfs=$4 metadata=$5
[[ "$phase" == configure || "$phase" == harden || "$phase" == cleanup ]] || fail 'Unsupported phase.'
[[ "$profile" == debian-13 || "$profile" == ubuntu-26.04 ]] || fail 'Unsupported profile.'
[[ "$target" == cloudstack-kvm || "$target" == proxmox-lxc ]] || fail 'Unsupported target.'
[[ ${GOLDEN_APPLY:-} == build && $(uname -s) == Linux && $EUID == 0 ]] || fail 'Requires an explicitly authorized Linux builder as root.'
[[ ! -e /etc/pve && -f /etc/zs-golden-images/builder.json && ! -L /etc/zs-golden-images/builder.json ]] || fail 'Missing dedicated-builder marker or Proxmox host detected.'
[[ $(stat -c '%u:%a' /etc/zs-golden-images/builder.json) == 0:600 ]] || fail 'Builder marker must be root-owned mode 0600.'
jq -e '.purpose == "isolated-image-builder" and .region == "yow"' /etc/zs-golden-images/builder.json >/dev/null || fail 'Wrong builder purpose or region.'
workspace=$(jq -er .workspace /etc/zs-golden-images/builder.json)
[[ "$workspace" == /* && -d "$workspace" && ! -L "$workspace" ]] || fail 'Invalid builder workspace.'
workspace=$(cd -- "$workspace" && pwd -P)
[[ "$rootfs" == /* && -d "$rootfs" && ! -L "$rootfs" ]] || fail 'Root filesystem must be an absolute directory without a symlink.'
rootfs=$(cd -- "$rootfs" && pwd -P)
[[ "$rootfs" == "$workspace/"* && "$rootfs" != "$workspace" && -f "$rootfs/etc/os-release" && -x "$rootfs/usr/bin/python3" ]] || fail 'Root filesystem must be beneath the dedicated workspace and contain Python.'
[[ "$metadata" == /* && -f "$metadata" ]] || fail 'Supply an absolute source metadata file.'
jq -e '.source_commit | test("^[0-9a-f]{40}$")' "$metadata" >/dev/null || fail 'Invalid source commit.'
jq -e '.source_image_sha256 | test("^[0-9a-f]{64}$")' "$metadata" >/dev/null || fail 'Invalid source manifest digest.'
jq -e '.source_kind == "apt-snapshot" and (.source_image_url | startswith("https://")) and (.image_version | test("^[0-9]{8}(-[a-z0-9][a-z0-9.-]*)?$"))' "$metadata" >/dev/null || fail 'Invalid pinned source metadata.'
umask 077
state=$(mktemp -d "$workspace/.ansible-rootfs.XXXXXXXX")
trap 'rm -rf -- "$state"' EXIT
jq -n --arg root "$rootfs" '{all:{hosts:{image:{ansible_connection:"community.general.chroot",ansible_host:$root,ansible_python_interpreter:"/usr/bin/python3"}}}}' > "$state/inventory.json"
jq --arg phase "$phase" --arg profile "$profile" --arg target "$target" '{golden_phase:$phase,golden_profile:$profile,golden_target:$target,golden_source_commit:.source_commit,golden_source_image_sha256:.source_image_sha256,golden_source_image_url:.source_image_url,golden_source_kind:.source_kind,golden_image_version:.image_version}' "$metadata" > "$state/vars.json"
# DIB uses LC_ALL=C; scope the UTF-8 locale required by Ansible to this child.
ANSIBLE_COLLECTIONS_PATH=/opt/zs-golden-images/collections ANSIBLE_ROLES_PATH="$repo/ansible/roles" LANG=C.UTF-8 LC_ALL=C.UTF-8 /opt/zs-golden-images/venv/bin/ansible-playbook -i "$state/inventory.json" "$repo/ansible/playbooks/30-configure-rootfs.yml" -e "@$state/vars.json"
if [[ "$phase" == cleanup ]]; then
  # Run after Ansible exits so removing its temporary files cannot disrupt a module.
  chroot "$rootfs" /bin/sh -s <<'CLEAN_ANSIBLE'
set -eu
test ! -L /root
test ! -L /root/.ansible
if mountpoint -q /root/.ansible; then exit 1; fi
if [ -d /root/.ansible ]; then
  find /root/.ansible -xdev -depth -delete
fi
CLEAN_ANSIBLE
fi
# Receipt is external to the image and exists only after all phase work succeeds.
metadata_sha=$(sha256sum "$metadata" | awk '{print $1}')
jq -n --arg phase "$phase" --arg profile "$profile" --arg target "$target" --arg sha "$metadata_sha" \
  '{phase:$phase,profile:$profile,target:$target,metadata_sha256:$sha,status:"completed"}' > "$metadata.$phase.json"
