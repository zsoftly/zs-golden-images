#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/zs-audit-tests.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
count=0
run_case() {
  local name=$1 expected=$2 status=0
  "$repo/scripts/report-audit.sh" debian-13 "$work/raw.json" "$work/$name" "${3:-$work/exceptions.json}" > "$work/log" 2>&1 || status=$?
  [[ $status == "$expected" ]] || { cat "$work/log"; printf 'Failed: %s (exit %s)\n' "$name" "$status"; exit 1; }
  count=$((count + 1))
}
printf '[]\n' > "$work/exceptions.json"
cat > "$work/base.json" <<'JSON'
{"results":[{"resource-type":"command","resource-id":"test","property":"exit-status","result":0,"skipped":false,"successful":true,"err":null}],"summary":{"test-count":1,"failed-count":0,"skipped-count":0}}
JSON
cp "$work/base.json" "$work/raw.json"
run_case passed_but_incomplete 2
jq -e '.promotion_allowed == false and .coverage == "incomplete" and .counts.passed == 1' "$work/passed_but_incomplete/report.json" >/dev/null
jq '.results[0].result=1 | .summary."failed-count"=1' "$work/base.json" > "$work/raw.json"
run_case failed 2
jq -e '.counts.failed == 1' "$work/failed/report.json" >/dev/null
jq '.results[0].result=3' "$work/base.json" > "$work/raw.json"
run_case unknown_successful_true 2
jq -e '.counts.unknown == 1 and .counts.passed == 0' "$work/unknown_successful_true/report.json" >/dev/null
jq '.results[0].result=2 | .results[0].skipped=true | .summary."skipped-count"=1' "$work/base.json" > "$work/raw.json"
run_case skipped 2
jq -e '.counts.skipped == 1' "$work/skipped/report.json" >/dev/null
jq '.results[0].err="timeout"' "$work/base.json" > "$work/raw.json"
run_case error 2
jq -e '.counts.error == 1' "$work/error/report.json" >/dev/null
printf '{"results":[],"summary":{"test-count":0,"failed-count":0,"skipped-count":0}}\n' > "$work/raw.json"
run_case empty 1
printf 'broken\n' > "$work/raw.json"
run_case malformed 1
jq '.summary."test-count"=2' "$work/base.json" > "$work/raw.json"
run_case count_mismatch 1
cat "$work/base.json" "$work/base.json" > "$work/raw.json"
run_case multiple_documents 1
jq '.results[0].result=1 | .summary."failed-count"=1' "$work/base.json" > "$work/raw.json"
printf '[{"resource-type":"command","resource-id":"test","property":"exit-status","reason":"temporary build access","expires":"2099-01-01"}]\n' > "$work/exceptions.json"
run_case excepted 2
jq -e '.counts.excepted == 1 and .checks[0].outcome == "failed" and .promotion_allowed == false' "$work/excepted/report.json" >/dev/null
jq '.[0].expires="2000-01-01"' "$work/exceptions.json" > "$work/expired.json"
run_case expired_exception 1 "$work/expired.json"
jq '.[0].expires="2099-02-30"' "$work/exceptions.json" > "$work/invalid-date.json"
run_case invalid_calendar_date 1 "$work/invalid-date.json"
jq '.results[0].result=3' "$work/base.json" > "$work/raw.json"
run_case unknown_with_exception 2
jq -e '.counts.unknown == 1 and .counts.excepted == 0 and .counts.not_applicable == 0' "$work/unknown_with_exception/report.json" >/dev/null
printf '[]\n' > "$work/exceptions.json"
jq '.results[0].result=77' "$work/base.json" > "$work/raw.json"
run_case unrecognized_enum 2
jq -e '.counts.unknown == 1 and .counts.passed == 0' "$work/unrecognized_enum/report.json" >/dev/null
jq '.results += .results | .summary."test-count"=2' "$work/base.json" > "$work/raw.json"
run_case duplicate_checks 1
status=0
"$repo/scripts/report-audit.sh" unsupported "$work/base.json" "$work/unsupported" > "$work/log" 2>&1 || status=$?
[[ $status == 1 && ! -e "$work/unsupported" ]]
count=$((count + 1))
jq '.profile="ubuntu-26.04" | .audit_commit="old-producer" | .benchmark_version="0.0.0"' "$work/base.json" > "$work/raw.json"
run_case old_wrong_profile_provenance 2
jq -e '.raw_provenance == "unverified" and .requested_profile == "debian-13" and
  has("audit_commit") == false and has("benchmark_version") == false and has("profile") == false and
  .promotion_allowed == false' "$work/old_wrong_profile_provenance/report.json" >/dev/null
printf '[OK] %s audit report scenarios passed.\n' "$count"
