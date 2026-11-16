def https_snapshot($snapshot): type == "string" and test("^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9/_-]+$") and endswith("/" + $snapshot);
def sha256: type == "string" and test("^[0-9a-f]{64}$");
type == "object" and
(keys|sort) == (["version","workspace","mirror_url","security_mirror_url","snapshot_id","source_date_epoch","inrelease_sha256"]|sort) and
(.version|type == "string" and test("^[0-9]{8}(-[a-z0-9][a-z0-9.-]*)?$")) and
(.workspace|type == "string" and test("^/([A-Za-z0-9_-][A-Za-z0-9._-]*/){2,}[A-Za-z0-9_-][A-Za-z0-9._-]*$") and (split("/")|all(. != "." and . != ".."))) and
(.snapshot_id|type == "string" and test("^[0-9]{8}T[0-9]{6}Z$")) and
(.snapshot_id as $s | (.mirror_url|https_snapshot($s)) and (.security_mirror_url|https_snapshot($s))) and
(.source_date_epoch|type == "number" and . > 0 and . == floor) and
(.inrelease_sha256|type == "object" and (keys|sort) == ["base","security","updates"] and all(.[]; sha256))
