#!/usr/bin/env python3
"""Validate, sign and publish approved artifacts using GnuPG and the AWS CLI."""

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
TARGETS = {"cloudstack-kvm": ".qcow2", "proxmox-lxc": ".tar.xz"}
COMMON_CHECKS = {
    "boot", "clone_identity", "network", "dns", "time", "ansible_idempotency",
    "patching", "reboot", "workload", "rollback", "secret_scan",
    "vulnerability_scan", "cis_coverage", "cis_remediation", "wazuh_readiness",
}
TARGET_CHECKS = {
    "cloudstack-kvm": {"cloud_init", "guest_agent", "cloudstack_compatibility"},
    "proxmox-lxc": {"unprivileged_lxc", "container_provisioning", "proxmox_compatibility"},
}
MAX_OBJECT = 5_000_000_000


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
            re.fullmatch(r"[0-9]{8}(?:-[a-z0-9][a-z0-9.-]{0,31})?", data["version"]),
            "Version must be YYYYMMDD or YYYYMMDD-revision")
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
    if target == "cloudstack-kvm":
        info = json.loads(run(["qemu-img", "info", "--output=json", "-f", "qcow2", path]))
        require(info.get("format") == "qcow2" and info.get("virtual-size", 0) > 0,
                "Not a QCOW2 disk")
        require(not info.get("backing-filename") and not info.get("data-file") and
                not info.get("format-specific", {}).get("data", {}).get("data-file"),
                "Release disk must be self-contained")
        require(not info.get("snapshots"), "Release disk must not contain internal snapshots")
        run(["qemu-img", "check", "-f", "qcow2", path])
    else:
        required = {"etc/machine-id", "etc/golden-image.json"}
        os_release = False
        seen = set()
        with tarfile.open(path, "r:xz") as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                require(not name.is_absolute() and ".." not in name.parts,
                        "Unsafe archive member path")
                require(str(name) not in seen, "Duplicate archive member")
                seen.add(str(name))
                if str(name) in {"etc/os-release", "usr/lib/os-release"} and member.isfile():
                    os_release = True
                if str(name) in required:
                    require(member.isfile(), f"Required image identity is not a file: {name}")
                    if str(name) == "etc/machine-id":
                        require(member.size == 0, "Image contains a machine ID")
                    required.remove(str(name))
                require(not str(name).startswith("etc/ssh/ssh_host_"),
                        "Image contains an SSH host key")
                require(str(name) not in {"root/.ssh/authorized_keys", "var/ossec/etc/client.keys"},
                        "Image contains an access or enrollment identity")
        require(not required and os_release, "Archive lacks required OS/image identity files")


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
    for item in evidence:
        file = regular(Path(approval_path).parent / item["path"])
        require(digest(file) == item.get("sha256"), "Test evidence checksum mismatch")
        require(item["sha256"] not in hashes, "Duplicate evidence identity")
        hashes.add(item["sha256"])
        if file.suffix == ".json":
            report = load(file)
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
    for cmd in (verify, pub):
        cmd.add_argument("directory")
    pub.add_argument("destination")
    for cmd in (prep, verify, pub):
        cmd.add_argument("--signer", required=True)
    for cmd in (check, prep, verify, pub):
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
    else:
        publish(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError,
            tarfile.TarError) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        sys.exit(1)
