def require($condition; $message): if $condition then . else error($message) end;
def valid_date:
  . as $d | try (($d + "T00:00:00Z" | fromdateiso8601 | strftime("%Y-%m-%d")) == $d) catch false;
def key: [."resource-type", ."resource-id", .property];
require(type == "object"; "Expected one audit object") |
require((.results | type == "array" and length > 0); "Empty or missing audit results") |
require((.summary | type == "object"); "Missing summary") |
require((all(.results[]; (.result | type == "number") and (.skipped | type == "boolean") and has("err") and (key | all(.[]; type == "string" and length > 0)))); "Malformed result") |
require((.summary."test-count" == (.results|length)) and
  (.summary."failed-count" == ([.results[] | select(.result == 1)] | length)) and
  (.summary."skipped-count" == ([.results[] | select(.skipped)] | length)); "Summary disagrees with results") |
require(([.results[]|key]|unique|length) == (.results|length); "Duplicate check identities") |
require(($exceptions|type == "array") and all($exceptions[];
  (keys|sort) == (["resource-type","resource-id","property","reason","expires"]|sort) and
  (key | all(.[]; type == "string" and length > 0)) and
  (.reason|type == "string" and length > 0) and
  (.expires|type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and (.expires|valid_date) and .expires >= $today); "Invalid or expired exception") |
require(([$exceptions[]|key]|unique|length) == ($exceptions|length); "Duplicate exception") |
.results as $raw |
require(all($exceptions[]; key as $k | any($raw[]; key == $k)); "Exception refers to an absent check") |
{
  schema_version: 1, requested_profile: $profile, requested_benchmark_version: $pin.benchmark_version,
  requested_audit_commit: $pin.audit_commit, raw_provenance: "unverified", requested_level: "L1 server",
  coverage: "incomplete", promotion_allowed: false,
  omissions: $pin.omissions,
  blockers: ["Independent benchmark coverage and manual evidence are not reviewed", "Guest acceptance and remediation are not complete"],
  checks: [.results[] |
    . as $result | key as $k |
    (if .err != null then "error"
     elif .result == 0 and .skipped == false then "passed"
     elif .result == 1 and .skipped == false then "failed"
     elif .result == 2 and .skipped == true then "skipped"
     else "unknown" end) as $status |
    ([$exceptions[] | select(key == $k)] | first) as $exception |
    {resource_type:."resource-type", resource_id:."resource-id", property,
     outcome:$status, exception:$exception,
     disposition:(if $exception != null and $status == "failed" then "excepted" else $status end)}]
} |
.counts = (.checks | group_by(.disposition) | map({key:.[0].disposition,value:length}) | from_entries) |
.counts = ({passed:0,failed:0,skipped:0,error:0,unknown:0,excepted:0,not_applicable:0} + .counts) |
.total_checks = (.checks|length)
