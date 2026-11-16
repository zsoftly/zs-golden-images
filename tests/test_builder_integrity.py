"""Integrity and native-builder boundary regressions without a live image build."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


REPO = Path(__file__).resolve().parents[1]
FILES = REPO / "ansible/roles/builder/files"
SPEC = importlib.util.spec_from_file_location("collection_integrity", FILES / "collection_integrity.py")
INTEGRITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INTEGRITY)


class CollectionIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "ansible_collections/community/general"
        self.root.mkdir(parents=True)
        (self.root / "MANIFEST.json").write_text(json.dumps({"collection_info": {"namespace": "community", "name": "general", "version": "12.5.0"}}))
        (self.root / "plugin.py").write_text("pass\n")
        self.pins = [{"name": "community.general", "version": "12.5.0", "sha256": "a" * 64}]

    def tearDown(self):
        self.temp.cleanup()

    def measured(self):
        return INTEGRITY.inventory(self.base, self.pins, require_root=False)

    def test_modified_and_added_plugin_files_change_inventory(self):
        original = self.measured()
        (self.root / "plugin.py").write_text("raise RuntimeError()\n")
        self.assertNotEqual(original, self.measured())
        (self.root / "plugin.py").write_text("pass\n")
        (self.root / "new_plugin.py").write_text("pass\n")
        self.assertNotEqual(original, self.measured())

    def test_bytecode_and_executable_mode_changes_are_detected(self):
        original = self.measured()
        (self.root / "plugin.py").chmod(0o755)
        self.assertNotEqual(original, self.measured())
        (self.root / "plugin.py").chmod(0o644)
        (self.root / "__pycache__").mkdir()
        (self.root / "__pycache__/plugin.cpython-314.pyc").write_bytes(b"changed bytecode")
        self.assertNotEqual(original, self.measured())

    def test_internal_links_are_measured_and_external_links_rejected(self):
        link = self.root / "link.py"
        link.symlink_to("plugin.py")
        original = self.measured()
        link.unlink()
        link.symlink_to("MANIFEST.json")
        self.assertNotEqual(original, self.measured())
        link.unlink()
        link.symlink_to(self.base / "outside.py")
        (self.base / "outside.py").write_text("pass\n")
        with self.assertRaisesRegex(ValueError, "escapes"):
            self.measured()

    def test_changed_collection_identity_is_rejected(self):
        self.pins[0]["version"] = "12.4.0"
        with self.assertRaisesRegex(ValueError, "identity"):
            self.measured()


class NativeBuilderPolicy(unittest.TestCase):
    def test_lxc_mount_cleanup_runs_in_reverse_order_after_phase_failure(self):
        # Exercise the actual mount/phase/trap body with inert mount commands;
        # private namespace creation itself requires the authorized Linux host.
        source = (REPO / "scripts/configure-lxc-rootfs.sh").read_text()
        body = source[source.index("mount --make-rprivate /"):]
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "rootfs"
            for name in ("dev", "proc", "sys", "run"):
                (root / name).mkdir(parents=True)
            commands = base / "bin"
            commands.mkdir()
            for name in ("mount", "umount"):
                path = commands / name
                path.write_text('#!/bin/sh\nprintf "' + name + ':%s\\n" "$*" >> "$MOUNT_LOG"\n')
                path.chmod(0o755)
            scripts = base / "scripts"
            scripts.mkdir()
            configure = scripts / "configure-rootfs.sh"
            configure.write_text('#!/bin/sh\nprintf "phase:%s\\n" "$1" >> "$MOUNT_LOG"\nif [ "$1" = harden ]; then exit 23; fi\n')
            configure.chmod(0o755)
            log = base / "mount.log"
            runner = 'set -euo pipefail\nrepo=$1; rootfs=$2; profile=debian-13; metadata=$3\n' + body
            result = subprocess.run(["bash", "-c", runner, "mount-test", str(base), str(root), str(base / "metadata.json")], env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"], MOUNT_LOG=str(log)), text=True, capture_output=True)
            self.assertEqual(result.returncode, 23, result.stderr)
            calls = log.read_text().splitlines()
            self.assertEqual([line for line in calls if line.startswith("phase:")], ["phase:configure", "phase:harden"])
            mounts = [line.rsplit(" ", 1)[1] for line in calls if line.startswith("mount:") and "--make-rprivate" not in line]
            unmounts = [line.removeprefix("umount:-- ") for line in calls if line.startswith("umount:")]
            self.assertEqual(unmounts, list(reversed(mounts)))

    def test_both_archive_keyrings_are_installed_and_explicitly_selected(self):
        tasks = yaml.safe_load((REPO / "ansible/roles/builder/tasks/main.yml").read_text())
        packages = next(task["ansible.builtin.apt"]["name"] for task in tasks if "ansible.builtin.apt" in task)
        self.assertIn("debian-archive-keyring", packages)
        self.assertIn("ubuntu-keyring", packages)
        self.assertIn("gpgv", packages)
        pipeline = (REPO / "scripts/pipeline.sh").read_text()
        self.assertIn("debian-archive-keyring.gpg", pipeline)
        self.assertIn("ubuntu-archive-keyring.gpg", pipeline)
        self.assertIn('[[ -s "$archive_keyring" && -r "$archive_keyring" ]]', pipeline)
        # The pinned minimal root hooks call removed apt-key when this is set.
        self.assertNotIn("DIB_APT_KEYRING", pipeline)
        self.assertIn('"DIB_DEBOOTSTRAP_EXTRA_ARGS=--include=ca-certificates --force-check-gpg --keyring=$archive_keyring"', pipeline)
        self.assertIn("--force-check-gpg", pipeline)
        self.assertIn('gpgv --keyring "$archive_keyring"', pipeline)
        self.assertIn("skip_verification:false,keys:[$archive_keys]", pipeline)

    def test_collection_pins_match_requirements_and_install_is_offline(self):
        pins = json.loads((FILES / "collections.json").read_text())
        requirements = yaml.safe_load((REPO / "ansible/requirements.yml").read_text())["collections"]
        self.assertEqual({p["name"]: p["version"] for p in pins}, {p["name"]: str(p["version"]) for p in requirements})
        tasks = (REPO / "ansible/roles/builder/tasks/main.yml").read_text()
        for option in ("--offline", "--no-deps", "--force", "sha256:{{ item.sha256 }}"):
            self.assertIn(option, tasks)
        pipeline = (REPO / "scripts/pipeline.sh").read_text()
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", pipeline)
        self.assertIn("module.inventory('/opt/zs-golden-images/collections', pins)", pipeline)

    def test_lxc_configuration_uses_private_mounts_before_native_pack(self):
        pipeline = (REPO / "scripts/pipeline.sh").read_text()
        self.assertIn('unshare --mount --propagation private --fork "$repo/scripts/configure-lxc-rootfs.sh"', pipeline)
        self.assertLess(pipeline.index("configure-lxc-rootfs.sh"), pipeline.index('"$distrobuilder" pack-lxc'))
        helper = (REPO / "scripts/configure-lxc-rootfs.sh").read_text()
        self.assertIn("mount --make-rprivate /", helper)
        self.assertIn("trap cleanup EXIT", helper)
        self.assertIn("mount -t proc", helper)
        self.assertIn("mount -t sysfs -o ro", helper)
        self.assertIn('tmpfs "$rootfs/run"', helper)
        self.assertIn('mount --bind "/dev/$device"', helper)
        self.assertIn("configure harden cleanup", helper)


if __name__ == "__main__":
    unittest.main()
