"""Input and live-operation boundary checks; no upstream builder is executed."""
import copy
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


class PipelineInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zs-pipeline-test-")
        self.site = Path(self.temp.name) / "private.json"
        self.data = {
            "version": "20261115-r1",
            "workspace": "/var/lib/zs-golden-images/builds",
            "mirror_url": "https://mirror.example.invalid/debian/20261115T000000Z",
            "security_mirror_url": "https://mirror.example.invalid/debian-security/20261115T000000Z",
            "snapshot_id": "20261115T000000Z",
            "source_date_epoch": int(datetime.datetime(2026, 11, 15, tzinfo=datetime.timezone.utc).timestamp()),
            "inrelease_sha256": {name: "a" * 64 for name in ("base", "updates", "security")},
        }

    def tearDown(self):
        self.temp.cleanup()

    def run_pipeline(self, data=None, profile="debian-13", target="cloudstack-kvm", action="validate", site=None):
        self.site.write_text(json.dumps(self.data if data is None else data))
        env = dict(os.environ)
        env.pop("GOLDEN_APPLY", None)
        return subprocess.run(
            [str(REPO / "scripts/pipeline.sh"), action, profile, target, str(site or self.site)],
            env=env, text=True, capture_output=True, check=False,
        )

    def test_all_four_profiles_and_targets_validate_without_builder(self):
        for profile in ("debian-13", "ubuntu-26.04"):
            for target in ("cloudstack-kvm", "proxmox-lxc"):
                with self.subTest(profile=profile, target=target):
                    data = copy.deepcopy(self.data)
                    if profile == "ubuntu-26.04":
                        data["security_mirror_url"] = data["mirror_url"]
                    result = self.run_pipeline(data, profile=profile, target=target)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("live build and acceptance have not run", result.stdout)
                    self.assertEqual(list(Path(self.temp.name).iterdir()), [self.site])

    def test_build_requires_separate_explicit_live_gate(self):
        result = self.run_pipeline(action="build")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GOLDEN_APPLY=build", result.stderr)
        self.assertEqual(list(Path(self.temp.name).iterdir()), [self.site])

    def test_unknown_profile_and_target_fail(self):
        self.assertNotEqual(self.run_pipeline(profile="debian-12").returncode, 0)
        self.assertNotEqual(self.run_pipeline(target="production").returncode, 0)

    def test_missing_hash_extra_fields_and_moving_snapshot_fail(self):
        changes = [
            {"inrelease_sha256": {"base": "a" * 64, "updates": "a" * 64}},
            {"proxmox_url": "https://production.example.invalid"},
            {"mirror_url": "https://mirror.example.invalid/current"},
            {"snapshot_id": "latest"},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.assertNotEqual(self.run_pipeline(self.data | change).returncode, 0)

    def test_credentials_in_url_and_untrusted_protocol_fail(self):
        for url in ("https://user:secret@mirror.invalid/20261115T000000Z", "http://mirror.invalid/20261115T000000Z"):
            self.assertNotEqual(self.run_pipeline(self.data | {"mirror_url": url}).returncode, 0)

    def test_unsafe_workspace_and_version_fail(self):
        for workspace in ("/", "/var/lib/../etc", "/var/lib/name with spaces", "/tmp/../../root"):
            self.assertNotEqual(self.run_pipeline(self.data | {"workspace": workspace}).returncode, 0)
        self.assertNotEqual(self.run_pipeline(self.data | {"version": "20261115/../replace"}).returncode, 0)

    def test_calendar_and_timestamp_mismatch_fail(self):
        self.assertNotEqual(self.run_pipeline(self.data | {"source_date_epoch": 1}).returncode, 0)
        data = self.data | {"snapshot_id": "20260230T000000Z", "mirror_url": "https://mirror.invalid/20260230T000000Z", "security_mirror_url": "https://mirror.invalid/20260230T000000Z"}
        self.assertNotEqual(self.run_pipeline(data).returncode, 0)

    def test_site_symlink_fails(self):
        link = Path(self.temp.name) / "link.json"
        link.symlink_to(self.site)
        self.assertNotEqual(self.run_pipeline(site=link).returncode, 0)

    def test_ubuntu_requires_combined_snapshot(self):
        self.assertNotEqual(self.run_pipeline(profile="ubuntu-26.04").returncode, 0)

    def test_native_pack_cannot_restore_build_repositories_or_run_actions(self):
        definition = {"image": {"distribution": "debian"}, "packages": {"manager": "apt", "update": True, "cleanup": True, "repositories": [{"url": "private-snapshot"}], "sets": [{"action": "install", "packages": ["python3"]}]}, "actions": [{"trigger": "post-files", "action": "mutation"}], "files": [{"generator": "dump"}]}
        result = subprocess.run(["jq", "-f", str(REPO / "builders/distrobuilder/pack.jq")], input=json.dumps(definition), text=True, capture_output=True, check=True)
        packed = json.loads(result.stdout)
        self.assertEqual(packed["packages"], {"manager": "apt", "update": False, "cleanup": False, "sets": [], "repositories": []})
        self.assertNotIn("actions", packed)
        self.assertNotIn("files", packed)
        self.assertEqual(packed["image"], definition["image"])

    def test_snapshot_expiry_override_is_written_only_inside_rootfs(self):
        root = Path(self.temp.name) / "rootfs"
        apt = root / "etc/apt/apt.conf.d"
        apt.mkdir(parents=True)
        hook = REPO / "builders/diskimage-builder/elements/zs-configure/root.d/09-zs-snapshot.sh"
        env = dict(os.environ, TARGET_ROOT=str(root), ZS_METADATA=str(self.site), GOLDEN_APPLY="build")
        result = subprocess.run([str(hook)], env=env, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((apt / "99-zs-snapshot-validity").read_text(), 'Acquire::Check-Valid-Until "false";\n')
        env["TARGET_ROOT"] = "/"
        self.assertNotEqual(subprocess.run([str(hook)], env=env, capture_output=True, check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
