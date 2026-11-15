#!/usr/bin/env bash
set -euo pipefail

[[ $(uname -s) == Linux && $EUID -eq 0 ]] || { echo '[FAIL] Cleanup requires a Linux build guest as root.' >&2; exit 1; }
[[ ! -d /etc/pve && -f /run/zs-golden-image-build && -f /etc/golden-image.json ]] || { echo '[FAIL] Missing build authorization or running on a Proxmox host.' >&2; exit 1; }
[[ $(systemd-detect-virt) == kvm ]] || { echo '[FAIL] Cleanup requires a KVM guest.' >&2; exit 1; }
grep -Eq '^[0-9a-f]{40}$' /run/zs-golden-image-build || exit 1
cloud-init status --wait
apt-get clean
cloud-init clean --logs --seed --machine-id --configs network
if [[ -d /var/lib/dbus ]]; then
  rm -f /var/lib/dbus/machine-id
  ln -s /etc/machine-id /var/lib/dbus/machine-id
fi
printf 'localhost\n' > /etc/hostname
printf '127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n' > /etc/hosts
rm -f /etc/ssh/ssh_host_* /root/.ssh/authorized_keys /root/.bash_history /root/.zsh_history
for guest_home in /home/*; do
  [[ -d "$guest_home" ]] || continue
  rm -f "$guest_home/.ssh/authorized_keys" "$guest_home/.bash_history" "$guest_home/.zsh_history"
done
find /var/lib/dhcp -type f -name '*.leases' -delete 2>/dev/null || [[ ! -d /var/lib/dhcp ]]
find /var/lib/NetworkManager -type f -name '*.lease' -delete 2>/dev/null || [[ ! -d /var/lib/NetworkManager ]]
find /tmp /var/tmp -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
journalctl --relinquish-var
if [[ -e /var/log/journal || -L /var/log/journal ]]; then
  [[ -d /var/log/journal && ! -L /var/log/journal ]] || { echo '[FAIL] Persistent journal path is not a regular directory.' >&2; exit 1; }
  find /var/log/journal -mindepth 1 -delete
  [[ -z $(find /var/log/journal -mindepth 1 -print -quit) ]] || { echo '[FAIL] Persistent journals remain after cleanup.' >&2; exit 1; }
fi
find /var/log -type f -not -path '/var/log/journal/*' -exec truncate -s 0 {} +
rm -f /run/zs-golden-image-build
sync
printf '%s\n' '[OK] Build identity removed. Packer will stop the guest and capture an experimental template.'
