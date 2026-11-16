#!/usr/bin/env bash
set -euo pipefail
: "${ZS_SOURCE:?}" "${ZS_PROFILE:?}" "${ZS_METADATA:?}" "${TMP_MOUNT_PATH:?}"
"$ZS_SOURCE/scripts/configure-rootfs.sh" cleanup "$ZS_PROFILE" cloudstack-kvm "$TMP_MOUNT_PATH" "$ZS_METADATA"
