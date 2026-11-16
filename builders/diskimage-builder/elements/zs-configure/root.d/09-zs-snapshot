#!/usr/bin/env bash
set -euo pipefail
: "${TARGET_ROOT:?}" "${ZS_METADATA:?}" "${GOLDEN_APPLY:?}"
[[ "$GOLDEN_APPLY" == build && "$TARGET_ROOT" != / && -d "$TARGET_ROOT/etc/apt/apt.conf.d" ]]
# Native Ubuntu root stage updates APT before later element hooks can run.
# All build sources are authenticated, digest-pinned snapshots; cleanup removes this setting.
printf '%s\n' 'Acquire::Check-Valid-Until "false";' > "$TARGET_ROOT/etc/apt/apt.conf.d/99-zs-snapshot-validity"
