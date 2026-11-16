"""Integrity and native-builder boundary regressions without a live image build."""
import importlib.util
import importlib.metadata
import hashlib
import shutil
import sys
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
    def test_vm_build_selects_sudo_that_preserves_architecture(self):
        # Exercise the pipeline's actual preflight against sudo implementations
        # that preserve or discard ARCH, without privilege changes or DIB.
        source = (REPO / "scripts/pipeline.sh").read_text()
        start = source.index('if [[ "$target" == cloudstack-kvm ]]; then', source.index('epoch=$(jq'))
        body = source[start:source.index('common_env=(', start)]
        for classic, preserves, target, success in (
            (True, False, "cloudstack-kvm", True),
            (False, True, "cloudstack-kvm", True),
            (False, False, "cloudstack-kvm", False),
            (False, False, "proxmox-lxc", True),
        ):
            with self.subTest(classic=classic, preserves=preserves, target=target):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    binaries = root / "bin"
                    binaries.mkdir()
                    run = root / "run"
                    run.mkdir()
                    for name, keep in [("sudo", preserves)] + ([("sudo.ws", True)] if classic else []):
                        executable = binaries / name
                        executable.write_text('#!/bin/sh\n[ "$1" = -n ] && [ "$2" = -E ] || exit 9\nshift 2\n' + ('' if keep else 'unset ARCH\n') + 'exec "$@"\n')
                        executable.chmod(0o755)
                    original = (binaries / "sudo").read_bytes()
                    runner = 'set -euo pipefail\nfail() { echo "$*" >&2; exit 1; }\nrun=$1; target=$2; epoch=1234567890\n' + body.replace('/usr/bin/', str(binaries) + '/')
                    result = subprocess.run(["bash", "-c", runner, "sudo-test", str(run), target], text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, success, result.stderr)
                    self.assertEqual((binaries / "sudo").read_bytes(), original)
                    if target == "cloudstack-kvm":
                        self.assertEqual((run / "host-bin/sudo").resolve(), (binaries / ("sudo.ws" if classic else "sudo")).resolve())
                    else:
                        self.assertFalse((run / "host-bin").exists())
                    if not success:
                        self.assertIn("requires sudo -E", result.stderr)

    def test_native_definition_scopes_temporary_paths_to_chroot_only(self):
        source = (REPO / "scripts/pipeline.sh").read_text()
        start = source.index('  jq -n --arg distro "$distribution"')
        definition = source[start:source.index('  "${common_env[@]}" "$distrobuilder" build-dir', start)]
        common_env = next(line for line in source.splitlines() if line.startswith('common_env=('))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tmp").mkdir()
            (root / "archive-keys.asc").write_text("test fixture key material\n")
            setup = ('set -euo pipefail\nrun=$1; distribution=debian; release=trixie; version=20261116-r2; '
                     'mirror=https://snapshot.invalid/debian; security_mirror=https://snapshot.invalid/security; '
                     "profile_json='{\"components\":[\"main\"]}'; epoch=1\n")
            result = subprocess.run(["bash", "-c", setup + common_env + "\n" + definition + '\n"${common_env[@]}" env',
                                     "definition-test", str(root)], capture_output=True, text=True, check=True)
            host_environment = dict(line.split("=", 1) for line in result.stdout.splitlines())
            for name in ("TMPDIR", "TMP_DIR"):
                self.assertEqual(host_environment[name], str(root / "tmp"))
            generated = json.loads((root / "lxc.json").read_text())
            expected = {"TMPDIR": "/tmp", "TMP_DIR": "/tmp"}
            self.assertEqual({item["key"]: item["value"] for item in generated["environment"]["variables"]}, expected)
            self.assertFalse(generated["environment"].get("clear_defaults", False))
            packed = subprocess.run(["jq", "-f", str(REPO / "builders/distrobuilder/pack.jq"), str(root / "lxc.json")],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(packed.stdout)["environment"], generated["environment"])
            play = yaml.safe_load((REPO / "ansible/playbooks/30-configure-rootfs.yml").read_text())[0]
            self.assertEqual(play["environment"], expected)

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


class BuildPhaseEvidence(unittest.TestCase):
    def test_candidate_gate_rejects_missing_failed_and_foreign_phase_receipts(self):
        source = (REPO / "scripts/pipeline.sh").read_text()
        start = source.index('metadata_sha=$(sha256sum "$run/metadata.json"')
        body = source[start:source.index('artifact_sha=', start)]
        for fault in (None, "missing", "failed", "metadata", "profile", "target", "phase"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                metadata = root / "metadata.json"
                metadata.write_text('{"image_version":"20261116-r3"}\n')
                expected = hashlib.sha256(metadata.read_bytes()).hexdigest()
                for phase in ("configure", "harden", "cleanup"):
                    receipt = {"phase": phase, "profile": "debian-13", "target": "cloudstack-kvm",
                               "metadata_sha256": expected, "status": "completed"}
                    if phase == "harden" and fault:
                        if fault == "missing":
                            continue
                        key = {"failed": "status", "metadata": "metadata_sha256"}.get(fault, fault)
                        receipt[key] = "wrong"
                    metadata.with_name(metadata.name + "." + phase + ".json").write_text(json.dumps(receipt))
                command = 'set -euo pipefail\nfail() { echo "$*" >&2; exit 1; }\nrun=$1; repo=$2; profile=debian-13; target=cloudstack-kvm\n' + body
                result = subprocess.run(["bash", "-c", command, "phase-gate", str(root), str(REPO)], capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, fault is None, result.stderr)
                if fault is None:
                    self.assertEqual([item["phase"] for item in json.loads((root / "build-phases.json").read_text())],
                                     ["configure", "harden", "cleanup"])

    def test_adapter_records_only_successful_phases_after_cleanup(self):
        source = (REPO / "scripts/configure-rootfs.sh").read_text()
        body = source[source.index('ANSIBLE_COLLECTIONS_PATH=/opt/zs-golden-images/collections ANSIBLE_ROLES_PATH='):]
        for phase in ("configure", "harden", "cleanup"):
            for failing in ("", "ansible", "chroot"):
                with self.subTest(phase=phase, failing=failing), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    metadata = root / "metadata.json"
                    metadata.write_text('{}\n')
                    for executable in ("ansible", "chroot"):
                        path = root / executable
                        path.write_text('#!/bin/sh\n[ "$FAIL_PHASE_STEP" != "' + executable + '" ] || exit 23\n')
                        path.chmod(0o755)
                    body_run = body.replace('/opt/zs-golden-images/venv/bin/ansible-playbook', str(root / 'ansible'))
                    command = 'set -euo pipefail\nrepo=$1; state=$1; rootfs=$1; metadata=$1/metadata.json; phase=$2; profile=debian-13; target=cloudstack-kvm\n' + body_run
                    result = subprocess.run(["bash", "-c", command, "phase-adapter", str(root), phase],
                                            env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], FAIL_PHASE_STEP=failing),
                                            capture_output=True, text=True)
                    success = failing == "" or (failing == "chroot" and phase != "cleanup")
                    self.assertEqual(result.returncode == 0, success, result.stderr)
                    receipt = root / ("metadata.json." + phase + ".json")
                    self.assertEqual(receipt.exists(), success)
                    if success:
                        self.assertEqual(json.loads(receipt.read_text())["metadata_sha256"], hashlib.sha256(metadata.read_bytes()).hexdigest())


@unittest.skipUnless(sys.platform == "linux", "Actual DIB runner requires Linux GNU find; exercised on the dedicated builder")
class DibHookDiscovery(unittest.TestCase):
    def test_pinned_upstream_runner_selects_every_hook_and_rejects_shell_suffix(self):
        # Execute upstream's real selector, never a copied filename regular expression.
        expected = json.loads((REPO / "builders/pins.json").read_text())["diskimage_builder"]["version"]
        self.assertEqual(importlib.metadata.version("diskimage-builder"), expected)
        spec = importlib.util.find_spec("diskimage_builder")
        runner = Path(spec.origin).parent / "lib/dib-run-parts"
        env = dict(os.environ)
        env.pop("RUN_PARTS_REGEX", None)
        element = REPO / "builders/diskimage-builder/elements/zs-configure"
        for stage in ("root.d", "post-root.d", "cleanup.d"):
            hooks = sorted((element / stage).iterdir())
            result = subprocess.run(["bash", str(runner), "--list", str(element / stage)],
                                    env=env, capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.splitlines(), [str(hook) for hook in hooks])
            with tempfile.TemporaryDirectory() as temp:
                legacy = Path(temp) / (hooks[0].name + ".sh")
                shutil.copy2(hooks[0], legacy)
                result = subprocess.run(["bash", str(runner), "--list", temp],
                                        env=env, capture_output=True, text=True, check=True)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
