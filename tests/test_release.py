"""Offline release safety tests. No image builders or network calls are used."""

import argparse
import copy
from contextlib import redirect_stdout
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("release", Path(__file__).parents[1] / "scripts/release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.artifact = self.root / "rootfs.tar.xz"
        self.archive()
        self.candidate = self.root / "candidate.json"
        self.data = {"schema_version": 1, "profile": "debian-13", "target": "proxmox-lxc",
                     "version": "20261115-1", "source_commit": "a" * 40,
                     "artifact": {"path": str(self.artifact), "sha256": release.digest(self.artifact)},
                     "inputs": {"snapshot": "fixture"}}
        self.write(self.candidate, self.data)
        self.evidence = self.root / "evidence.json"
        self.write(self.evidence, {"fixture": "test-only", "coverage": "complete",
                                   "raw_provenance": "verified", "promotion_allowed": True})
        evidence_hash = release.digest(self.evidence)
        today = datetime.datetime.now(datetime.timezone.utc).date()
        self.accepted = {
            "schema_version": 1, "candidate_sha256": release.digest(self.candidate),
            "artifact_sha256": release.digest(self.artifact), "expires": str(today),
            "evidence": [{"path": "evidence.json", "sha256": evidence_hash}],
            "checks": {name: {"status": "passed", "evidence": [evidence_hash]}
                       for name in release.COMMON_CHECKS | release.TARGET_CHECKS["proxmox-lxc"]},
            "vulnerability_scan": {"tool": "fixture", "version": "1", "database_sha256": "b" * 64,
                                   "database_updated": str(today), "report_sha256": evidence_hash,
                                   "critical": 0, "high": 0},
        }
        self.approval = self.root / "approval.json"
        self.write(self.approval, self.accepted)
        self.signature = self.root / "approval.asc"
        self.signature.write_text("fixture")
        self.fingerprint = "A" * 40

    def write(self, path, value):
        path.write_text(json.dumps(value))

    def archive(self, extra=None, omit=()):
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        contents = {".": root, "etc/os-release": b"ID=debian\nVERSION_ID=13\n", "etc/machine-id": b"",
                    "etc/golden-image.json": b"{}", "etc/resolv.conf": b""}
        contents.update(extra or {})
        for name in omit:
            del contents[name]
        with tarfile.open(self.artifact, "w:xz") as archive:
            for name, value in contents.items():
                member = tarfile.TarInfo(name)
                if isinstance(value, tarfile.TarInfo):
                    archive.addfile(value)
                else:
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))

    def replace_evidence(self, value, name="evidence.json", text=False):
        self.evidence = self.root / name
        if text:
            self.evidence.write_text(value)
        else:
            self.write(self.evidence, value)
        evidence_hash = release.digest(self.evidence)
        self.accepted["evidence"] = [{"path": name, "sha256": evidence_hash}]
        for check in self.accepted["checks"].values():
            check["evidence"] = [evidence_hash]
        self.accepted["vulnerability_scan"]["report_sha256"] = evidence_hash
        self.write(self.approval, self.accepted)

    def check(self):
        with patch.object(release, "verify_signature"):
            return release.approval(self.candidate, self.approval, self.signature,
                                    self.fingerprint, self.root)

    def test_approval_checks_bound_evidence(self):
        self.assertEqual(self.check()[0]["target"], "proxmox-lxc")

    def test_candidate_changed_after_approval(self):
        self.data["version"] = "20261115-2"
        self.write(self.candidate, self.data)
        with self.assertRaisesRegex(ValueError, "another candidate"):
            self.check()

    def test_artifact_tamper(self):
        self.artifact.write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.check()

    def test_evidence_tamper(self):
        self.evidence.write_text("changed")
        with self.assertRaisesRegex(ValueError, "evidence checksum"):
            self.check()

    def test_missing_live_check(self):
        del self.accepted["checks"]["reboot"]
        self.write(self.approval, self.accepted)
        with self.assertRaisesRegex(ValueError, "acceptance checks"):
            self.check()

    def test_failed_check(self):
        self.accepted["checks"]["rollback"]["status"] = "failed"
        self.write(self.approval, self.accepted)
        with self.assertRaisesRegex(ValueError, "rollback"):
            self.check()

    def test_incomplete_audit_is_rejected(self):
        self.write(self.evidence, {"coverage": "incomplete", "promotion_allowed": False})
        new_hash = release.digest(self.evidence)
        self.accepted["evidence"][0]["sha256"] = new_hash
        self.write(self.approval, self.accepted)
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.check()

    def test_renamed_incomplete_json_is_rejected_for_any_check(self):
        report = self.root / "boot-evidence.txt"
        self.write(report, {"coverage": "incomplete", "promotion_allowed": False})
        report_hash = release.digest(report)
        self.accepted["evidence"].append({"path": report.name, "sha256": report_hash})
        self.accepted["checks"]["boot"]["evidence"] = [report_hash]
        self.write(self.approval, self.accepted)
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.check()

    def test_text_audit_cannot_satisfy_cis_coverage(self):
        self.replace_evidence("Reviewer attests to complete CIS coverage.\n", "report.txt", text=True)
        with self.assertRaisesRegex(ValueError, "CIS coverage"):
            self.check()

    def test_blocked_text_audit_is_rejected_for_any_check(self):
        report = self.root / "boot-evidence.txt"
        report.write_text("Requested audit: fixture\nCoverage: incomplete. Promotion: BLOCKED.\n")
        report_hash = release.digest(report)
        self.accepted["evidence"].append({"path": report.name, "sha256": report_hash})
        self.accepted["checks"]["boot"]["evidence"] = [report_hash]
        self.write(self.approval, self.accepted)
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.check()

    def test_cis_coverage_requires_explicit_complete_verified_acceptance(self):
        complete = {"coverage": "complete", "raw_provenance": "verified", "promotion_allowed": True}
        for field in complete:
            with self.subTest(missing=field):
                report = complete.copy()
                del report[field]
                self.replace_evidence(report)
                with self.assertRaisesRegex(ValueError, "CIS coverage"):
                    self.check()

    def test_complete_cis_json_is_accepted_without_json_extension(self):
        self.replace_evidence({"coverage": "complete", "raw_provenance": "verified",
                               "promotion_allowed": True}, "reviewed-coverage.txt")
        self.assertEqual(self.check()[0]["target"], "proxmox-lxc")

    def test_duplicate_keys_in_renamed_evidence_are_rejected(self):
        self.replace_evidence('{"coverage":"incomplete","coverage":"complete"}',
                              "report.txt", text=True)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.check()

    def test_stale_scanner_database(self):
        self.accepted["vulnerability_scan"]["database_updated"] = "2020-01-01"
        self.write(self.approval, self.accepted)
        with self.assertRaisesRegex(ValueError, "seven days"):
            self.check()

    def test_high_vulnerabilities_block(self):
        self.accepted["vulnerability_scan"]["high"] = 1
        self.write(self.approval, self.accepted)
        with self.assertRaisesRegex(ValueError, "zero critical"):
            self.check()

    def test_expired_approval(self):
        self.accepted["expires"] = "2020-01-01"
        self.write(self.approval, self.accepted)
        with self.assertRaisesRegex(ValueError, "expired"):
            self.check()

    def test_unsafe_archive(self):
        self.archive({"../../escape": b"bad"})
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            release.inspect_artifact(self.artifact, "proxmox-lxc")

    def test_identity_left_in_archive(self):
        self.archive({"etc/machine-id": b"old-identity"})
        with self.assertRaisesRegex(ValueError, "machine ID"):
            release.inspect_artifact(self.artifact, "proxmox-lxc")

    def test_lxc_archive_root_must_allow_guest_user_traversal(self):
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        root.mode = 0o700
        self.archive({".": root})
        with self.assertRaisesRegex(ValueError, "root-owned mode 0755"):
            release.inspect_artifact(self.artifact, "proxmox-lxc")

    def test_lxc_archive_requires_explicit_root_permissions(self):
        self.archive(omit=(".",))
        with self.assertRaisesRegex(ValueError, "root directory entry"):
            release.inspect_artifact(self.artifact, "proxmox-lxc")

    def test_inherited_resolver_content_is_rejected(self):
        for name in ("etc/resolv.conf", "etc/resolv.conf.ORIG"):
            with self.subTest(path=name):
                self.archive({name: b"nameserver 192.0.2.53\nsearch builder.example.invalid\n"})
                with self.assertRaisesRegex(ValueError, "resolver"):
                    release.inspect_artifact(self.artifact, "proxmox-lxc")

    def test_resolver_must_be_a_regular_file(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(type=kind):
                resolver = tarfile.TarInfo("etc/resolv.conf")
                resolver.type = kind
                resolver.linkname = "../run/systemd/resolve/stub-resolv.conf"
                self.archive({"etc/resolv.conf": resolver})
                with self.assertRaisesRegex(ValueError, "resolver"):
                    release.inspect_artifact(self.artifact, "proxmox-lxc")

    def test_missing_neutral_resolver_is_rejected(self):
        self.archive(omit=("etc/resolv.conf",))
        with self.assertRaisesRegex(ValueError, "required"):
            release.inspect_artifact(self.artifact, "proxmox-lxc")

    def test_duplicate_json_keys(self):
        self.candidate.write_text('{"schema_version":1,"schema_version":2}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            release.load(self.candidate)

    def test_qcow_external_data_rejected(self):
        with patch.object(release, "run", return_value=json.dumps({"format": "qcow2", "virtual-size": 1,
                     "format-specific": {"data": {"data-file": "/outside"}}})):
            with self.assertRaisesRegex(ValueError, "self-contained"):
                release.inspect_artifact(self.artifact, "cloudstack-kvm")

    def test_output_never_overwrites(self):
        with self.assertRaisesRegex(ValueError, "new absolute"):
            release.new_directory(self.root)

    def test_wrong_signer(self):
        with patch.object(release, "run", return_value="[GNUPG:] VALIDSIG " + "B" * 40 + " 2026 0 0 4 0 1 10 00\n"):
            with self.assertRaisesRegex(ValueError, "trusted fingerprint"):
                release.verify_signature(self.approval, self.signature, self.fingerprint, self.root)

    def test_publish_requires_explicit_operation(self):
        with patch.dict(os.environ, {"GOLDEN_APPLY": ""}):
            with self.assertRaisesRegex(ValueError, "GOLDEN_APPLY"):
                release.publish(argparse.Namespace())

    def publication(self, command):
        directory = self.root / "release"
        directory.mkdir()
        for name in ("image.tar.xz", "release.json", "SHA256SUMS", "SHA256SUMS.asc"):
            (directory / name).write_text(name)
        (directory / "SHA256SUMS").write_text("".join(
            f"{release.digest(directory / name)}  {name}\n" for name in ("image.tar.xz", "release.json")))
        dest = self.root / "destination.json"
        self.write(dest, {"endpoint_url": "https://objects.example.invalid", "bucket": "images-test",
                          "prefix": "golden", "region": "ca-test-1", "canada_storage_approved": True,
                          "conditional_writes_verified": True})
        data = copy.deepcopy(self.data)
        data["artifact"]["path"] = "image.tar.xz"
        args = argparse.Namespace(directory=directory, destination=dest, signer=self.fingerprint, gpg_home=self.root)
        with patch.dict(os.environ, {"GOLDEN_APPLY": "publish"}), \
                patch.object(release, "verify_release", return_value=data), patch.object(release, "run", side_effect=command):
            with redirect_stdout(io.StringIO()):
                release.publish(args)

    def test_conditional_uploads_and_signature_last(self):
        calls = []
        uploaded = {}
        def command(argv):
            calls.append(argv)
            if "get-bucket-versioning" in argv:
                return '{"Status":"Enabled"}'
            if "put-object" in argv:
                uploaded["checksum"] = argv[argv.index("--checksum-sha256") + 1]
                uploaded["size"] = Path(argv[argv.index("--body") + 1]).stat().st_size
            return json.dumps({"ChecksumSHA256": uploaded["checksum"], "VersionId": "fixture-version",
                               "ContentLength": uploaded["size"]})
        self.publication(command)
        self.assertEqual(len(calls), 9)
        for call in calls[1::2]:
            self.assertEqual(call[call.index("--if-none-match") + 1], "*")
            self.assertIn("--checksum-sha256", call)
        self.assertTrue(calls[-2][calls[-2].index("--key") + 1].endswith("SHA256SUMS.asc"))

    def test_readback_failure_prevents_completion(self):
        calls = []
        def command(argv):
            calls.append(argv)
            if "get-bucket-versioning" in argv:
                return '{"Status":"Enabled"}'
            if "put-object" in argv:
                return json.dumps({"ChecksumSHA256": argv[argv.index("--checksum-sha256") + 1],
                                   "VersionId": "fixture-version"})
            return '{}'
        with self.assertRaisesRegex(ValueError, "readback"):
            self.publication(command)
        self.assertEqual(len(calls), 3)

    def test_mutation_before_upload_rejected(self):
        def command(argv):
            if "get-bucket-versioning" in argv:
                return '{"Status":"Enabled"}'
            if "put-object" in argv:
                Path(argv[argv.index("--body") + 1]).parent.joinpath("release.json").write_text("changed")
                return json.dumps({"ChecksumSHA256": argv[argv.index("--checksum-sha256") + 1],
                                   "VersionId": "fixture-version"})
            return json.dumps({"ChecksumSHA256": release.base64.b64encode(
                bytes.fromhex(release.digest(self.root / "release/image.tar.xz"))).decode(),
                "VersionId": "fixture-version", "ContentLength": len("image.tar.xz")})
        with self.assertRaisesRegex(ValueError, "changed before upload"):
            self.publication(command)

    def test_collision_never_retries_or_deletes(self):
        calls = []
        def command(argv):
            calls.append(argv)
            if "get-bucket-versioning" in argv:
                return '{"Status":"Enabled"}'
            raise subprocess.CalledProcessError(1, argv, stderr="412 PreconditionFailed")
        with self.assertRaises(subprocess.CalledProcessError):
            self.publication(command)
        self.assertEqual(len(calls), 2)
        self.assertFalse(any("delete-object" in item for item in calls))

    @unittest.skipUnless(shutil.which("gpg"), "GnuPG unavailable")
    def test_real_gpg_sign_verify_and_tamper(self):
        home = self.root / "gnupg"
        home.mkdir(mode=0o700)
        release.run(["gpg", "--batch", "--homedir", home, "--passphrase", "", "--quick-generate-key",
                     "Release Fixture <fixture@example.invalid>", "ed25519", "sign", "1d"])
        key = next(line.split(":")[9] for line in release.run(
            ["gpg", "--batch", "--homedir", home, "--with-colons", "--list-secret-keys"]).splitlines()
                   if line.startswith("fpr:"))
        self.signature.unlink()
        release.run(["gpg", "--batch", "--homedir", home, "--local-user", key, "--armor", "--output",
                     self.signature, "--detach-sign", self.approval])
        args = argparse.Namespace(candidate=self.candidate, approval=self.approval,
                                  approval_signature=self.signature, reviewer=key, signer=key,
                                  gpg_home=home, output=self.root / "signed")
        with redirect_stdout(io.StringIO()):
            release.prepare(args)
        release.verify_release(args.output, key, home)
        (args.output / "release.json").write_text("tampered")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            release.verify_release(args.output, key, home)


if __name__ == "__main__":
    unittest.main()
