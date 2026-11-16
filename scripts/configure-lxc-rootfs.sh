#!/usr/bin/env bash
set -euo pipefail
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
[[ $# == 3 ]] || fail 'Usage: configure-lxc-rootfs.sh profile /absolute/rootfs /absolute/metadata.json (inside a private mount namespace)'
profile=$1 rootfs=$2 metadata=$3
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ ${GOLDEN_APPLY:-} == build && $(uname -s) == Linux && $EUID == 0 ]] || fail 'Requires an authorized Linux builder as root.'
[[ "$profile" == debian-13 || "$profile" == ubuntu-26.04 ]] || fail 'Unsupported profile.'
[[ $(readlink /proc/self/ns/mnt) != "$(readlink /proc/1/ns/mnt)" ]] || fail 'Run through unshare --mount --propagation private.'
[[ ! -e /etc/pve && -f /etc/zs-golden-images/builder.json && ! -L /etc/zs-golden-images/builder.json ]] || fail 'Missing dedicated-builder marker or Proxmox host detected.'
[[ $(stat -c '%u:%a' /etc/zs-golden-images/builder.json) == 0:600 ]] || fail 'Builder marker must be root-owned mode 0600.'
python3 - "$rootfs" <<'PY'
import json, pathlib, sys
marker = json.loads(pathlib.Path('/etc/zs-golden-images/builder.json').read_text())
root = pathlib.Path(sys.argv[1])
workspace = pathlib.Path(marker['workspace'])
if marker.get('purpose') != 'isolated-image-builder' or marker.get('region') != 'yow':
    raise SystemExit('Wrong dedicated-builder purpose or region')
if not root.is_absolute() or root.is_symlink() or not root.is_dir() or root.resolve() != root or not root.is_relative_to(workspace) or root == workspace:
    raise SystemExit('Root filesystem must be beneath the protected workspace')
for name in ('dev', 'proc', 'sys', 'run'):
    path = root / name
    if path.is_symlink() or not path.is_dir():
        raise SystemExit('Chroot mount targets must be existing real directories')
PY
# No mount in this namespace can propagate back to the builder, including on failure.
mount --make-rprivate /
mounted=()
cleanup() {
  local index
  for ((index=${#mounted[@]}-1; index>=0; index--)); do
    umount -- "${mounted[index]}" || true
  done
}
trap cleanup EXIT
mount -t tmpfs -o mode=0755,nosuid tmpfs "$rootfs/dev"
mounted+=("$rootfs/dev")
for device in null zero random urandom tty; do
  touch "$rootfs/dev/$device"
  mount --bind "/dev/$device" "$rootfs/dev/$device"
  mounted+=("$rootfs/dev/$device")
done
mkdir -p "$rootfs/dev/pts" "$rootfs/dev/shm"
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts "$rootfs/dev/pts"
mounted+=("$rootfs/dev/pts")
ln -s pts/ptmx "$rootfs/dev/ptmx"
ln -s /proc/self/fd "$rootfs/dev/fd"
ln -s /proc/self/fd/0 "$rootfs/dev/stdin"
ln -s /proc/self/fd/1 "$rootfs/dev/stdout"
ln -s /proc/self/fd/2 "$rootfs/dev/stderr"
chmod 1777 "$rootfs/dev/shm"
mount -t proc -o nosuid,nodev,noexec proc "$rootfs/proc"
mounted+=("$rootfs/proc")
mount -t sysfs -o ro,nosuid,nodev,noexec sysfs "$rootfs/sys"
mounted+=("$rootfs/sys")
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$rootfs/run"
mounted+=("$rootfs/run")
for phase in configure harden cleanup; do
  "$repo/scripts/configure-rootfs.sh" "$phase" "$profile" proxmox-lxc "$rootfs" "$metadata"
done
