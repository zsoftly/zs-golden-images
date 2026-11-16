#!/usr/bin/env bash
set -euo pipefail
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'Usage: prepare-audit.sh debian-13|ubuntu-26.04 /absolute/new-bundle'
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
profile=$1
destination=$2
jq -e --arg profile "$profile" '.profiles[$profile] != null' "$repo/audit/pins.json" >/dev/null || fail 'Unsupported profile.'
[[ "$destination" == /* && ! -e "$destination" && ! -L "$destination" ]] || fail 'Bundle must be a new absolute path.'
parent=$(cd -- "$(dirname -- "$destination")" && pwd -P)
[[ "$parent/" != "$repo/"* ]] || fail 'Keep downloaded audit dependencies outside the public checkout.'
umask 077
mkdir -- "$destination"
url=$(jq -r --arg p "$profile" '.profiles[$p].audit_repository' "$repo/audit/pins.json")
commit=$(jq -r --arg p "$profile" '.profiles[$p].audit_commit' "$repo/audit/pins.json")
git clone --quiet --no-checkout -- "$url" "$destination/content"
git -C "$destination/content" checkout --quiet --detach "$commit"
[[ $(git -C "$destination/content" rev-parse HEAD) == "$commit" ]] || fail 'Audit commit mismatch.'
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 15 --max-time 300 \
  "$(jq -r .syver.url "$repo/audit/pins.json")" -o "$destination/syver"
actual=$(shasum -a 256 "$destination/syver" | awk '{print $1}')
[[ "$actual" == "$(jq -r .syver.sha256 "$repo/audit/pins.json")" ]] || fail 'Syver checksum mismatch. Do not execute this bundle.'
chmod 0700 "$destination/syver"
printf '%s\n' '[OK] Pinned audit bundle prepared. No audit or remediation was run.'
