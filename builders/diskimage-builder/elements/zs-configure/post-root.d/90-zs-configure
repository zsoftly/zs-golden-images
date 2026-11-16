#!/usr/bin/env bash
set -euo pipefail
: "${ZS_SOURCE:?}" "${ZS_PROFILE:?}" "${ZS_METADATA:?}" "${TMP_MOUNT_PATH:?}"
"$ZS_SOURCE/scripts/configure-rootfs.sh" configure "$ZS_PROFILE" cloudstack-kvm "$TMP_MOUNT_PATH" "$ZS_METADATA"
"$ZS_SOURCE/scripts/configure-rootfs.sh" harden "$ZS_PROFILE" cloudstack-kvm "$TMP_MOUNT_PATH" "$ZS_METADATA"
