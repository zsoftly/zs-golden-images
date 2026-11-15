#!/usr/bin/env bash
set -euo pipefail
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
[[ $# == 3 || $# == 4 ]] || fail 'Usage: report-audit.sh profile raw.json /absolute/new-report-directory [exceptions.json]'
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
profile=$1
raw=$2
output=$3
pin=$(jq -ce --arg p "$profile" '.profiles[$p] // error("Unsupported profile")' "$repo/audit/pins.json") || fail 'Unsupported profile or invalid pin file.'
[[ "$output" == /* && ! -e "$output" && ! -L "$output" ]] || fail 'Report directory must be a new absolute path.'
parent=$(cd -- "$(dirname -- "$output")" && pwd -P)
[[ "$parent/" != "$repo/"* ]] || fail 'Keep evidence outside the public checkout.'
umask 077
mkdir -- "$output"
exceptions='[]'
[[ $# != 4 ]] || exceptions=$(jq -c . "$4") || fail 'Invalid exception JSON.'
# Slurp enforces exactly one JSON document, not a concatenated stream.
jq -s -e 'length == 1' "$raw" >/dev/null || fail 'Expected exactly one JSON document.'
jq --arg profile "$profile" --argjson pin "$pin" --argjson exceptions "$exceptions" \
  --arg today "$(date -u +%F)" -f "$repo/audit/report.jq" "$raw" > "$output/report.json" || fail 'Invalid audit results or exceptions.'
jq -r '"Requested audit: \(.requested_profile), benchmark \(.requested_benchmark_version)",
  "Raw input provenance: unverified. Requested pins do not identify the producer of this file.",
  "Coverage: incomplete. Promotion: BLOCKED.",
  "Returned checks (not benchmark control counts): \(.total_checks)",
  (.counts | to_entries[] | "\(.key): \(.value)"),
  (.omissions[] | "Omitted: \(.)"),
  (.blockers[] | "Blocker: \(.)"),
  (.checks[] | "\(.disposition): \(.resource_type)/\(.resource_id)/\(.property) [original=\(.outcome)]" )' \
  "$output/report.json" > "$output/report.txt"
printf '%s\n' '[BLOCKED] Evidence written. Incomplete coverage prevents promotion.'
# No current report constitutes a successful acceptance gate, including all-pass input.
exit 2
