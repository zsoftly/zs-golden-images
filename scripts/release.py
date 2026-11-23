#!/usr/bin/env python3
"""Validate, sign and publish approved artifacts."""

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[1]
PROFILES = {"debian-13", "ubuntu-26.04"}
TARGETS = {"cloudstack-kvm": ".qcow2", "proxmox-kvm": ".qcow2", "proxmox-lxc": ".tar.xz"}
COMMON_CHECKS = {
    "boot", "clone_identity", "network", "dns", "time", "ansible_idempotency",
    "patching", "reboot", "workload", "rollback", "secret_scan",
    "vulnerability_scan", "cis_coverage", "cis_remediation", "wazuh_readiness",
}
TARGET_CHECKS = {
    "cloudstack-kvm": {"cloud_init", "guest_agent", "cloudstack_compatibility"},
    "proxmox-kvm": {"cloud_init", "guest_agent", "proxmox_compatibility"},
    "proxmox-lxc": {"unprivileged_lxc", "container_provisioning", "proxmox_compatibility"},
}
MAX_OBJECT = 5_000_000_000
GITHUB_REPOSITORY = "zsoftly/zs-golden-images"
GITHUB_MAX_ASSET = 2 * 1024**3


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def regular(path):
    path = Path(path).absolute()
    require(path.is_file() and not path.is_symlink(), f"Expected regular file: {path}")
    return path


def load(path):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, f"Duplicate JSON key: {key}")
            obj[key] = value
        return obj
    return json.loads(regular(path).read_text(), object_pairs_hook=unique)


def run(argv):
    return subprocess.run([str(item) for item in argv], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def fingerprint(value):
    require(bool(re.fullmatch(r"[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value)),
            "Use a full trusted OpenPGP fingerprint")
    return value.upper()


def verify_signature(data, signature, expected, home):
    expected = fingerprint(expected)
    output = run(["gpg", "--batch", "--homedir", home, "--status-fd", "1",
                  "--verify", regular(signature), regular(data)])
    signatures = [line.split()[2:] for line in output.splitlines()
                  if line.startswith("[GNUPG:] VALIDSIG ")]
    require(len(signatures) == 1 and expected in (signatures[0][0], signatures[0][-1]),
            "Signature does not match the explicitly trusted fingerprint")
    require(not any(f"[GNUPG:] {bad} " in output for bad in
                    ("EXPKEYSIG", "EXPSIG", "REVKEYSIG", "BADSIG", "ERRSIG")),
            "Expired, revoked or invalid signature")


def candidate(path):
    path = regular(path)
    data = load(path)
    require(isinstance(data, dict), "Candidate must be a JSON object")
    require(data.get("schema_version") == 1, "Unsupported candidate schema")
    require(data.get("profile") in PROFILES and data.get("target") in TARGETS,
            "Unsupported profile or target")
    require(isinstance(data.get("version"), str) and
            re.fullmatch(r"[0-9]{8}(?:-[a-z0-9][a-z0-9.-]{0,31})?", data["version"]) and
            ".." not in data["version"] and not data["version"].endswith((".", ".lock")),
            "Version must be a tag-safe YYYYMMDD or YYYYMMDD-revision")
    datetime.datetime.strptime(data["version"][:8], "%Y%m%d")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", data.get("source_commit", ""))),
            "Missing source commit")
    item = data.get("artifact", {})
    artifact = regular(path.parent / item.get("path", ""))
    require(artifact.name.endswith(TARGETS[data["target"]]), "Wrong artifact extension")
    require(artifact.stat().st_size > 0 and digest(artifact) == item.get("sha256"),
            "Artifact missing, empty or checksum mismatch")
    return data, artifact


def inspect_artifact(path, target):
    if TARGETS[target] == ".qcow2":
        info = json.loads(run(["qemu-img", "info", "--output=json", "-f", "qcow2", path]))
        require(info.get("format") == "qcow2" and info.get("virtual-size", 0) > 0,
                "Not a QCOW2 disk")
        require(not info.get("backing-filename") and not info.get("data-file") and
                not info.get("format-specific", {}).get("data", {}).get("data-file"),
                "Release disk must be self-contained")
        require(not info.get("snapshots"), "Release disk must not contain internal snapshots")
        run(["qemu-img", "check", "-f", "qcow2", path])
    else:
        required = {"etc/machine-id", "etc/golden-image.json", "etc/resolv.conf"}
        os_release = False
        seen = set()
        with tarfile.open(path, "r:xz") as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                require(not name.is_absolute() and ".." not in name.parts,
                        "Unsafe archive member path")
                require(str(name) not in seen, "Duplicate archive member")
                seen.add(str(name))
                if name == PurePosixPath("."):
                    require(member.isdir() and (member.uid, member.gid, member.mode) == (0, 0, 0o755),
                            "LXC archive root must be a root-owned mode 0755 directory")
                if str(name) in {"etc/os-release", "usr/lib/os-release"} and member.isfile():
                    os_release = True
                if str(name) in {"etc/resolv.conf", "etc/resolv.conf.ORIG"}:
                    require(member.isfile() and member.size == 0,
                            "Image resolver configuration must be a regular empty file")
                if str(name) in required:
                    require(member.isfile(), f"Required image identity is not a file: {name}")
                    if str(name) == "etc/machine-id":
                        require(member.size == 0, "Image contains a machine ID")
                    required.remove(str(name))
                require(not str(name).startswith("etc/ssh/ssh_host_"),
                        "Image contains an SSH host key")
                require(str(name) not in {"root/.ssh/authorized_keys", "var/ossec/etc/client.keys"},
                        "Image contains an access or enrollment identity")
        require("." in seen, "LXC archive lacks its root directory entry")
        require(not required and os_release, "Archive lacks required OS/image identity files")


def cis_benchmark(profile):
    version = load(REPO / "audit/pins.json")["profiles"][profile]["benchmark_version"]
    return {"family": "CIS", "profile": profile, "version": version, "level": 1, "system_type": "Server"}


def verify_cis_coverage(data, checks, reports):
    coverage = checks["cis_coverage"]["evidence"]
    require(len(coverage) == 1, "Supply one reviewed CIS coverage report")
    report_hash = coverage[0]
    report = reports[report_hash]
    require(isinstance(report, dict) and report.get("coverage") == "complete" and
            report.get("raw_provenance") == "verified" and report.get("promotion_allowed") is True,
            "CIS coverage evidence must be JSON with complete, verified coverage and promotion allowed")
    benchmark = cis_benchmark(data["profile"])
    require(report.get("benchmark") == benchmark and
            type(report["benchmark"]["level"]) is int and
            report.get("target") == data["target"] and report.get("artifact_sha256") == data["artifact"]["sha256"],
            "CIS Level 1 report must match the pinned benchmark, target and image digest")
    inventory_hash = report.get("control_inventory_sha256")
    inventory = reports.get(inventory_hash)
    require(inventory_hash != report_hash and isinstance(inventory, dict) and
            inventory.get("benchmark") == benchmark, "Missing reviewed CIS Level 1 control inventory")
    controls = inventory.get("control_ids")
    require(isinstance(controls, list) and controls and
            all(isinstance(item, str) and item.strip() == item and item for item in controls) and
            len(set(controls)) == len(controls), "Invalid CIS control inventory")
    results = report.get("controls")
    require(isinstance(results, dict) and set(results) == set(controls),
            "CIS coverage report must assess every reviewed control")
    for control_id, result in results.items():
        require(isinstance(result, dict), f"Invalid CIS result: {control_id}")
        status = result.get("status")
        require(status in {"passed", "not_applicable", "host_inherited"},
                f"CIS control must pass or have an assessed disposition: {control_id}")
        if status == "host_inherited":
            require(data["target"] == "proxmox-lxc", f"Host inheritance is limited to LXC: {control_id}")
        proof = result.get("evidence_sha256")
        require(proof in reports and proof not in {report_hash, inventory_hash},
                f"CIS control is missing bound supporting evidence: {control_id}")
        if status != "passed":
            require(isinstance(result.get("rationale"), str) and result["rationale"].strip(),
                    f"CIS disposition requires a rationale: {control_id}")
    require(any(result["status"] == "passed" for result in results.values()),
            "CIS assessment has no passing guest controls")


def approval(candidate_path, approval_path, signature, reviewer, home):
    data, artifact = candidate(candidate_path)
    verify_signature(approval_path, signature, reviewer, home)
    accepted = load(approval_path)
    require(isinstance(accepted, dict), "Approval must be a JSON object")
    require(accepted.get("schema_version") == 1, "Unsupported approval schema")
    require(accepted.get("candidate_sha256") == digest(candidate_path),
            "Approval is for another candidate manifest")
    require(accepted.get("artifact_sha256") == digest(artifact),
            "Approval is for another artifact")
    expires = datetime.date.fromisoformat(accepted.get("expires", ""))
    require(expires >= datetime.datetime.now(datetime.timezone.utc).date(), "Approval expired")
    evidence = accepted.get("evidence", [])
    require(isinstance(evidence, list) and evidence, "No test evidence")
    hashes = set()
    reports = {}
    for item in evidence:
        file = regular(Path(approval_path).parent / item["path"])
        require(digest(file) == item.get("sha256"), "Test evidence checksum mismatch")
        require(item["sha256"] not in hashes, "Duplicate evidence identity")
        hashes.add(item["sha256"])
        try:
            report = load(file)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            if isinstance(error, json.JSONDecodeError):
                require(not re.search(r"^(?:Coverage:\s*incomplete\b|Promotion:\s*BLOCKED\b|"
                                      r"Raw input provenance:\s*unverified\b)", error.doc,
                                      re.MULTILINE | re.IGNORECASE),
                        "Incomplete or unverified audit evidence cannot approve release")
            if file.suffix == ".json":
                raise
            report = None
        reports[item["sha256"]] = report
        if isinstance(report, dict):
            require(report.get("coverage") != "incomplete" and
                    report.get("promotion_allowed") is not False and
                    report.get("raw_provenance") != "unverified",
                    "Incomplete or unverified audit evidence cannot approve release")
    checks = accepted.get("checks", {})
    required = COMMON_CHECKS | TARGET_CHECKS[data["target"]]
    require(set(checks) == required, "Missing or unexpected acceptance checks")
    for name, result in checks.items():
        require(result.get("status") == "passed" and isinstance(result.get("evidence"), list)
                and result["evidence"] and set(result["evidence"]) <= hashes,
                f"Acceptance check has no passing bound evidence: {name}")
    verify_cis_coverage(data, checks, reports)
    scan = accepted.get("vulnerability_scan", {})
    require(isinstance(scan.get("tool"), str) and scan["tool"] and
            isinstance(scan.get("version"), str) and scan["version"] and
            bool(re.fullmatch(r"[0-9a-f]{64}", scan.get("database_sha256", ""))) and
            scan.get("report_sha256") in checks["vulnerability_scan"]["evidence"],
            "Missing scanner identity, database hash or bound report")
    database_date = datetime.date.fromisoformat(scan.get("database_updated", ""))
    age = (datetime.datetime.now(datetime.timezone.utc).date() - database_date).days
    require(0 <= age <= 7, "Scanner database must be no older than seven days")
    require(type(scan.get("critical")) is int and scan["critical"] == 0 and
            type(scan.get("high")) is int and scan["high"] == 0,
            "Release policy requires zero critical and high findings")
    inspect_artifact(artifact, data["target"])
    return data, artifact, accepted


def new_directory(path):
    path = Path(path)
    require(path.is_absolute() and not path.exists() and not path.is_symlink(),
            "Output must be a new absolute directory")
    require(path.parent.is_dir(), "Output parent must already exist")
    require(not path.parent.resolve().is_relative_to(REPO), "Keep artifacts outside checkout")
    path.mkdir(mode=0o700)
    return path


def prepare(args):
    data, artifact, accepted = approval(args.candidate, args.approval, args.approval_signature,
                                        args.reviewer, args.gpg_home)
    output = new_directory(args.output)
    name = f"zs-{data['profile']}-{data['target']}-{data['version']}{TARGETS[data['target']]}"
    shutil.copyfile(artifact, output / name)
    require(digest(output / name) == data["artifact"]["sha256"], "Artifact changed while copying")
    metadata = {key: data[key] for key in ("schema_version", "profile", "target", "version", "source_commit")}
    metadata.update(artifact={"path": name, "sha256": digest(output / name)},
                    cis_level_1=cis_benchmark(data["profile"]),
                    candidate_sha256=digest(args.candidate), approval_sha256=digest(args.approval),
                    evidence_sha256=sorted(item["sha256"] for item in accepted["evidence"]),
                    reviewer_fingerprint=fingerprint(args.reviewer),
                    release_fingerprint=fingerprint(args.signer))
    (output / "release.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    sums = "".join(f"{digest(output / file)}  {file}\n" for file in sorted([name, "release.json"]))
    (output / "SHA256SUMS").write_text(sums)
    run(["gpg", "--batch", "--homedir", args.gpg_home, "--local-user", fingerprint(args.signer),
         "--armor", "--output", output / "SHA256SUMS.asc", "--detach-sign", output / "SHA256SUMS"])
    verify_release(output, args.signer, args.gpg_home)
    print(f"[OK] Signed release prepared at {output}; nothing published")


def verify_release(directory, signer, home):
    directory = Path(directory)
    verify_signature(directory / "SHA256SUMS", directory / "SHA256SUMS.asc", signer, home)
    entries = {}
    for line in regular(directory / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        require(match is not None and match[2] not in entries, "Invalid checksum entry")
        require(digest(regular(directory / match[2])) == match[1], "Release checksum mismatch")
        entries[match[2]] = match[1]
    data, artifact = candidate(directory / "release.json")
    require(artifact.parent.resolve() == directory.resolve() and
            data["artifact"]["path"] == artifact.name, "Artifact must be inside release directory")
    require(set(entries) == {"release.json", artifact.name}, "Unexpected release checksum members")
    require(set(p.name for p in directory.iterdir()) == set(entries) | {"SHA256SUMS", "SHA256SUMS.asc"},
            "Release directory contains unexpected files")
    require(data.get("release_fingerprint") == fingerprint(signer), "Release signer mismatch")
    return data


def publish(args):
    require(os.environ.get("GOLDEN_APPLY") == "publish", "Set GOLDEN_APPLY=publish only after release approval")
    directory = Path(args.directory)
    data = verify_release(directory, args.signer, args.gpg_home)
    config = load(args.destination)
    require(set(config) == {"endpoint_url", "bucket", "prefix", "region", "canada_storage_approved", "conditional_writes_verified"},
            "Unexpected destination keys")
    endpoint = urlsplit(config["endpoint_url"])
    require(endpoint.scheme == "https" and endpoint.hostname and not endpoint.username and
            not endpoint.password and not endpoint.query and not endpoint.fragment,
            "Destination requires an authenticated HTTPS endpoint without embedded credentials")
    require(config["canada_storage_approved"] is True and config["conditional_writes_verified"] is True,
            "Infra must confirm Canadian storage and conditional writes before publication")
    require(bool(re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", config["bucket"])), "Invalid bucket")
    prefix = config["prefix"]
    require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/_-]*", prefix)) and
            "//" not in prefix, "Invalid prefix")
    require(bool(re.fullmatch(r"[a-z0-9-]+", config["region"])), "Invalid region")
    key = f"{prefix.rstrip('/')}/{data['profile']}/{data['target']}/{data['version']}"
    base = ["aws", "--endpoint-url", config["endpoint_url"], "--region", config["region"], "s3api"]
    versioning = json.loads(run(base + ["get-bucket-versioning", "--bucket", config["bucket"]]))
    require(versioning.get("Status") == "Enabled", "Bucket versioning must be enabled")
    files = [data["artifact"]["path"], "release.json", "SHA256SUMS", "SHA256SUMS.asc"]
    expected = {line.split("  ")[1]: line.split("  ")[0]
                for line in (directory / "SHA256SUMS").read_text().splitlines()}
    expected.update({name: digest(directory / name) for name in ("SHA256SUMS", "SHA256SUMS.asc")})
    # Reverify after capturing the exact signed set. Server-side checksums bind uploaded bytes.
    require(verify_release(directory, args.signer, args.gpg_home) == data,
            "Release metadata changed before upload")
    require(all((directory / file).stat().st_size <= MAX_OBJECT for file in files),
            "Single-object uploader supports artifacts up to 5 GiB; larger releases need reviewed multipart support")
    # Conditional writes fail closed on a collision. Never delete partial uploads or move a latest pointer.
    for name in files:
        file = regular(directory / name)
        require(digest(file) == expected[name], "Release changed before upload")
        size = file.stat().st_size
        checksum = base64.b64encode(bytes.fromhex(expected[name])).decode("ascii")
        result = json.loads(run(base + ["put-object", "--bucket", config["bucket"], "--key", f"{key}/{name}",
                            "--body", file, "--if-none-match", "*", "--checksum-algorithm", "SHA256",
                            "--checksum-sha256", checksum]))
        require(result.get("ChecksumSHA256") == checksum and
                isinstance(result.get("VersionId"), str) and result["VersionId"] not in {"", "null"},
                "Storage did not confirm uploaded checksum and version")
        observed = json.loads(run(base + ["head-object", "--bucket", config["bucket"],
                                       "--key", f"{key}/{name}", "--version-id", result["VersionId"],
                                       "--checksum-mode", "ENABLED"]))
        require(observed.get("ChecksumSHA256") == checksum and
                observed.get("VersionId") == result["VersionId"] and observed.get("ContentLength") == size,
                "Published object readback does not match release")
    print(f"[OK] Published version {data['version']}; consumers must verify SHA256SUMS.asc before use")


def github_api(endpoint, *flags):
    return json.loads(run(["gh", "api", "--hostname", "github.com", *flags,
                           f"repos/{GITHUB_REPOSITORY}/{endpoint}"]))


def github_list(endpoint):
    return [item for page in github_api(endpoint, "--paginate", "--slurp") for item in page]


def github_release_assets(release_id, expected, complete=False):
    actual = {}
    for asset in github_list(f"releases/{release_id}/assets"):
        name = asset["name"]
        require(name in expected and name not in actual, "Unexpected GitHub release asset")
        size, checksum = expected[name]
        require(not (asset["state"] == "starter" and asset["size"] == 0),
                f"GitHub left an empty upload placeholder for {name}. Remove it from the draft before retrying.")
        require(asset["state"] == "uploaded" and asset["size"] == size and
                asset.get("digest") == f"sha256:{checksum}",
                f"GitHub asset size or digest mismatch: {name}")
        actual[name] = asset
    require(not complete or actual.keys() == expected.keys(), "GitHub release is missing verified assets")
    return actual


def github_tag(tag, commit, published=False):
    refs = github_api(f"git/matching-refs/tags/{tag}")
    exact = [ref["object"] for ref in refs if ref["ref"] == f"refs/tags/{tag}"]
    require(len(exact) == 1 if published else len(exact) <= 1, "Unexpected GitHub tag state")
    require(all(ref["type"] == "commit" and ref["sha"] == commit for ref in exact),
            "GitHub tag points to a different source commit")
    return bool(exact)


def publish_github(args):
    require(os.environ.get("GOLDEN_APPLY") == "publish", "Set GOLDEN_APPLY=publish only after release approval")
    directory = Path(args.directory).resolve()
    require("#" not in str(directory), "GitHub release directory must not contain a label separator (#)")
    data = verify_release(directory, args.signer, args.gpg_home)
    require(data.get("cis_level_1") == cis_benchmark(data["profile"]),
            "Prepare a release with verified CIS Level 1 evidence before GitHub publication")
    tag = f"zs-{data['profile']}-{data['target']}-{data['version']}"
    run(["git", "check-ref-format", f"refs/tags/{tag}"])
    commit = data["source_commit"]
    files = (data["artifact"]["path"], "release.json", "SHA256SUMS", "SHA256SUMS.asc")
    expected = {}
    for name in files:
        path = regular(directory / name)
        size = path.stat().st_size
        require(size < GITHUB_MAX_ASSET, f"GitHub release asset must be smaller than 2 GiB: {name}")
        expected[name] = (size, digest(path))
    require(verify_release(directory, args.signer, args.gpg_home) == data, "Release changed during verification")

    require(github_api(f"commits/{commit}")["sha"] == commit, "Signed source commit is absent from GitHub")
    releases = [item for item in github_list("releases") if item["tag_name"] == tag]
    require(len(releases) <= 1, "More than one GitHub release uses this tag")
    tag_exists = github_tag(tag, commit)
    if not releases:
        require(not args.publish_draft, "Stage and verify a complete draft before publishing")
        require(not tag_exists, "A GitHub tag already exists for this version")
        release = github_api("releases", "-X", "POST", "-f", f"tag_name={tag}",
                             "-f", f"target_commitish={commit}", "-f", f"name={tag}",
                             "-f", "body=Verify the signed SHA256SUMS before importing the image.",
                             "-F", "draft=true", "-f", "make_latest=false")
    else:
        release = releases[0]
    require(release["tag_name"] == tag and release["target_commitish"] == commit,
            "Existing GitHub release conflicts with the signed draft")
    release_id = release["id"]
    require(type(release_id) is int and release_id > 0, "Invalid GitHub release identity")
    if release["draft"] is False:
        require(args.publish_draft, "This GitHub release is already public")
        require(release.get("immutable") is True, "Existing GitHub release is mutable")
        github_tag(tag, commit, published=True)
        github_release_assets(release_id, expected, complete=True)
        print(f"[OK] Verified existing public release https://github.com/{GITHUB_REPOSITORY}/releases/tag/{tag}")
        return
    require(release["draft"] is True, "Unexpected GitHub draft state")

    if not args.publish_draft:
        actual = github_release_assets(release_id, expected)
        for name in files:
            if name in actual:
                continue
            path = regular(directory / name)
            require((path.stat().st_size, digest(path)) == expected[name], "Release changed before upload")
            run(["gh", "release", "upload", tag, path, "--repo", f"github.com/{GITHUB_REPOSITORY}"])
        github_release_assets(release_id, expected, complete=True)
        print(f"[OK] Verified draft release {tag}")
        return

    try:
        settings = github_api("immutable-releases")
    except subprocess.CalledProcessError as error:
        raise ValueError("Cannot verify GitHub immutable releases. Check the repository setting and admin read access.") from error
    require(settings.get("enabled") is True, "Enable GitHub immutable releases before publishing")
    github_tag(tag, commit)
    github_release_assets(release_id, expected, complete=True)
    published = github_api(f"releases/{release_id}", "-X", "PATCH", "-F", "draft=false", "-f", "make_latest=false")
    require(published["id"] == release_id and published["tag_name"] == tag and published["draft"] is False and
            published.get("immutable") is True, "GitHub did not confirm immutable publication")
    github_tag(tag, commit, published=True)
    github_release_assets(release_id, expected, complete=True)
    print(f"[OK] Published https://github.com/{GITHUB_REPOSITORY}/releases/tag/{tag}")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="Offline artifact structure checks; not live acceptance")
    inspect.add_argument("candidate")
    check = commands.add_parser("check", help="Verify signed approval and bound acceptance evidence")
    prep = commands.add_parser("prepare", help="Check acceptance, copy artifact, checksum and sign")
    for cmd in (check, prep):
        cmd.add_argument("candidate")
        cmd.add_argument("approval")
        cmd.add_argument("approval_signature")
        cmd.add_argument("--reviewer", required=True)
    prep.add_argument("output")
    verify = commands.add_parser("verify", help="Verify a release before import, including rollback versions")
    pub = commands.add_parser("publish", help="Conditionally publish a signed version; never modify platform templates")
    github = commands.add_parser("publish-github", help="Stage or publish a signed GitHub release")
    github.add_argument("--publish-draft", action="store_true", help="Publish a previously staged and verified draft")
    for cmd in (verify, pub, github):
        cmd.add_argument("directory")
    pub.add_argument("destination")
    for cmd in (prep, verify, pub, github):
        cmd.add_argument("--signer", required=True)
    for cmd in (check, prep, verify, pub, github):
        cmd.add_argument("--gpg-home", required=True)
    args = parser.parse_args()
    if args.command == "inspect":
        data, artifact = candidate(args.candidate)
        inspect_artifact(artifact, data["target"])
        print("[OK] Offline artifact structure passed; live acceptance still required")
    elif args.command == "check":
        approval(args.candidate, args.approval, args.approval_signature, args.reviewer, args.gpg_home)
        print("[OK] Signed approval and bound evidence verified")
    elif args.command == "prepare":
        prepare(args)
    elif args.command == "verify":
        verify_release(args.directory, args.signer, args.gpg_home)
        print("[OK] Release signature and checksums verified")
    elif args.command == "publish-github":
        publish_github(args)
    else:
        publish(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError,
            tarfile.TarError) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        sys.exit(1)
