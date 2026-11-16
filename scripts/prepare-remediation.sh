#!/usr/bin/env bash
set -euo pipefail
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'Usage: prepare-remediation.sh profile /absolute/new-role-directory'
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
profile=$1 output=$2
pin=$(jq -ce --arg p "$profile" '.profiles[$p].remediation_candidate // error("Unsupported profile")' "$repo/audit/pins.json") || fail 'Unsupported profile.'
[[ "$output" == /* && ! -e "$output" && ! -L "$output" ]] || fail 'Use a new absolute output directory.'
parent=$(cd -- "$(dirname -- "$output")" && pwd -P)
[[ "$parent/" != "$repo/"* ]] || fail 'Keep third-party role checkouts outside the public repository.'
umask 077
git clone --no-checkout -- "$(jq -r .repository <<< "$pin")" "$output"
git -C "$output" checkout --detach "$(jq -r .commit <<< "$pin")"
[[ $(git -C "$output" rev-parse HEAD) == "$(jq -r .commit <<< "$pin")" ]] || fail 'Role revision mismatch.'
printf '%s\n' '[OK] Pinned runtime role prepared. No remediation was executed.'
