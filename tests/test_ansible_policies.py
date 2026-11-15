"""Render public policies and exercise adapter rejection without running a build."""
import json
import os
import base64
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

import jinja2
import yaml

ROOT = Path(__file__).resolve().parents[1]


def tasks(role):
    return yaml.safe_load((ROOT / 'ansible/roles' / role / 'tasks/main.yml').read_text())


def task(role, name):
    return next(item for item in tasks(role) if item['name'] == name)


class ImagePolicyTests(unittest.TestCase):
    def test_ssh_include_rewrite_is_stable_on_second_pass(self):
        data = task('image_harden', 'Place drop-in policies before every existing SSH setting')['ansible.builtin.copy']
        env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        env.filters['b64decode'] = lambda value: base64.b64decode(value).decode()
        env.filters['regex_replace'] = lambda value, pattern, replacement: re.sub(pattern, replacement, value)
        template = env.from_string(data['content'])
        def render(content):
            return template.render(golden_sshd_original={'content': base64.b64encode(content.encode()).decode()})
        original = 'PasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\n'
        first = render(original)
        self.assertTrue(first.startswith('Include /etc/ssh/sshd_config.d/*.conf\n'))
        self.assertNotEqual(first, original)
        self.assertEqual(render(first), first)
        self.assertEqual(first.count('Include /etc/ssh/sshd_config.d/*.conf'), 1)

    def test_pam_missing_enforcement_changes_once_then_skips(self):
        item = task('image_harden', 'Enable password-quality and history profiles')
        self.assertEqual(item['changed_when'], "'changed' in golden_pam_update.stdout_lines")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / 'common-password'
            policy.write_text('password requisite pam_unix.so\n')
            calls = root / 'calls'
            updater = root / 'pam-auth-update'
            updater.write_text('#!/bin/sh\nprintf call >> "$CALLS"\n'
                               'printf "password requisite pam_pwquality.so\\npassword requisite pam_pwhistory.so remember=24 enforce_for_root use_authtok\\n" > "$POLICY"\n')
            updater.chmod(0o700)
            hasher = root / 'sha256sum'
            hasher.write_text('#!/usr/bin/env python3\nimport hashlib,sys\n'
                              'print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())\n')
            hasher.chmod(0o700)
            env = {**os.environ, 'PATH': directory + os.pathsep + os.environ['PATH'],
                   'POLICY': str(policy), 'CALLS': str(calls), 'GOLDEN_PAM_REFRESH': 'false'}
            script = item['ansible.builtin.shell'].replace('/etc/pam.d/common-password', shlex.quote(str(policy)))
            first = subprocess.run(['/bin/sh', '-c', script], env=env, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout.strip(), 'changed')
            second = subprocess.run(['/bin/sh', '-c', script], env=env, capture_output=True, text=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(second.stdout, '')
            self.assertEqual(calls.read_text(), 'call')

    def test_ssh_root_policy_is_target_specific(self):
        data = task('image_harden', 'Install the key-only SSH baseline')['ansible.builtin.copy']
        env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        for target, policy in [('cloudstack-kvm', 'no'), ('proxmox-lxc', 'prohibit-password')]:
            rendered = env.from_string(data['content']).render(
                golden_target=target, role_path=str(ROOT / 'ansible/roles/image_harden'),
                lookup=lambda plugin, path: Path(path).read_text())
            self.assertIn(f'PermitRootLogin {policy}\n', rendered)
            self.assertIn('PasswordAuthentication no\n', rendered)
            self.assertIn('PermitEmptyPasswords no\n', rendered)

    def test_provenance_never_embeds_private_mirror(self):
        data = task('image_configure', 'Record source manifest provenance')['ansible.builtin.copy']
        env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        env.filters['to_nice_json'] = json.dumps
        result = json.loads(env.from_string(data['content']).render(
            golden_profile='debian-13', golden_target='cloudstack-kvm', golden_image_version='20261115',
            golden_source_kind='apt-snapshot', golden_source_commit='a'*40,
            golden_source_image_sha256='b'*64, golden_source_image_url='https://private.invalid/snapshot'))
        self.assertEqual(result['source_manifest_sha256'], 'b'*64)
        self.assertEqual(result['status'], 'experimental-unaccepted')
        self.assertNotIn('source_image_url', result)
        self.assertNotIn('source_image_sha256', result)

    def test_lxc_coverage_never_claims_kernel_controls(self):
        data = task('image_harden', 'Record explicit incomplete hardening coverage')['ansible.builtin.copy']
        env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        env.filters['to_nice_json'] = json.dumps
        report = json.loads(env.from_string(data['content']).render(golden_target='proxmox-lxc'))
        self.assertFalse(report['cis_complete'])
        self.assertFalse(report['promotion_allowed'])
        self.assertIn('kernel-modules', report['host_owned'])
        self.assertNotIn('vm-sysctl-baseline', report['configured'])
        self.assertIn('root-key-only-until-instance-admin-provisioned', report['provisioning_exceptions'])

    def test_runtime_apt_sources_are_public_and_signed(self):
        data = task('image_cleanup', 'Configure signed public update repositories')['ansible.builtin.copy']
        env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        for profile, suite in [('debian-13', 'trixie'), ('ubuntu-26.04', 'resolute')]:
            result = env.from_string(data['content']).render(golden_profile=profile)
            self.assertIn(suite+'-security', result)
            self.assertEqual(result.count('Signed-By:'), 2)
            self.assertNotIn('trusted=yes', result)
            self.assertNotIn('Check-Valid-Until: no', result)

    def test_adapter_rejects_invalid_phase_before_execution(self):
        result = subprocess.run([str(ROOT / 'scripts/configure-rootfs.sh'), 'oops', 'debian-13',
                                 'cloudstack-kvm', '/tmp/root', '/tmp/meta'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unsupported phase', result.stderr)

    def test_adapter_requires_explicit_live_authorization(self):
        env = os.environ.copy()
        env.pop('GOLDEN_APPLY', None)
        result = subprocess.run([str(ROOT / 'scripts/configure-rootfs.sh'), 'configure', 'debian-13',
                                 'cloudstack-kvm', '/tmp/root', '/tmp/meta'], env=env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('explicitly authorized', result.stderr)

    def test_chroot_adapter_uses_installed_ansible_collection(self):
        source = (ROOT / 'scripts/configure-rootfs.sh').read_text()
        self.assertIn('ANSIBLE_COLLECTIONS_PATH=/opt/zs-golden-images/collections', source)
        self.assertIn('/opt/zs-golden-images/venv/bin/ansible-playbook', source)

    def test_managed_readiness_binds_the_local_identity(self):
        block = task('runtime_checks', 'Verify managed Wazuh readiness')['block']
        names = [item['name'] for item in block]
        bind = next(t for t in block if t['name'] == 'Bind manager verification to this guest identity')
        self.assertEqual(bind['ansible.builtin.assert']['that'],
                         'golden_wazuh_local_identity.stdout == golden_wazuh_agent_id')
        self.assertTrue(bind['no_log'])
        self.assertLess(names.index('Bind manager verification to this guest identity'),
                        names.index('Read manager-confirmed agent status'))

    def test_python_install_uses_hashed_lock_without_dynamic_dependencies(self):
        install = task('builder', 'Install exact hashed Python dependencies')['ansible.builtin.pip']
        self.assertEqual(install['extra_args'], '--require-hashes --only-binary=:all:')
        dib = task('builder', 'Install diskimage-builder without resolving or rebuilding dependencies')['ansible.builtin.pip']
        self.assertEqual(dib['extra_args'], '--no-deps --no-build-isolation')
        lock = (ROOT / 'ansible/requirements-builder.lock').read_text()
        self.assertIn('ansible-core==2.20.4', lock)
        self.assertIn('pbr==7.1.3', lock)
        self.assertIn('--hash=sha256:', lock)

    def test_candidate_carries_verified_toolchain_inventory(self):
        pipeline = (ROOT / 'scripts/pipeline.sh').read_text()
        self.assertIn("installed.get('python_lock_sha256')", pipeline)
        self.assertIn("installed.get('python_inventory_sha256')", pipeline)
        self.assertIn('toolchain:$toolchain[0]', pipeline)

    def test_cloud_init_runtime_wait_has_deadline(self):
        self.assertEqual(task('runtime_checks', 'Require completed cloud-init on VMs')['timeout'], 180)

    def test_native_builder_uses_upstream_build_tags(self):
        build = task('builder', 'Build the pinned native executable')
        self.assertEqual(build['environment']['GOFLAGS'],
                         '-tags=containers_image_storage_stub,containers_image_docker_daemon_stub,containers_image_openpgp')

    def test_vm_remediation_requires_server_level_one_tags(self):
        play = yaml.safe_load((ROOT / 'ansible/playbooks/50-remediate-vm.yml').read_text())[0]
        guards = play['pre_tasks'][0]['ansible.builtin.assert']['that']
        self.assertIn("ansible_run_tags == ['level1-server']", guards)
        self.assertTrue(all(t['tags'] == 'always' for t in play['pre_tasks']))
        self.assertIn('--tags level1-server', (ROOT / 'scripts/run-remediation.sh').read_text())
        guard = next(t for t in play['pre_tasks'] if t['name'] == 'Verify remediation source is unmodified')
        self.assertIn('golden_cis_status.rc != 0', guard['failed_when'])

    def test_lxc_root_access_removed_only_after_new_connection(self):
        play = yaml.safe_load((ROOT / 'ansible/playbooks/45-provision-lxc-admin.yml').read_text())[0]
        names = [item['name'] for item in play['tasks']]
        self.assertLess(names.index('Verify a fresh administrator SSH connection and root capability'),
                        names.index('Disable temporary root SSH only after recovery proof'))
        check = next(item for item in play['tasks'] if item['name'].startswith('Verify a fresh'))
        argv = check['ansible.builtin.command']['argv']
        self.assertIn('ControlPath=none', argv)
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn('sudo -n /usr/bin/id -u && /usr/bin/cat /etc/machine-id', argv)
        self.assertIn('golden_admin_candidate_identity.content | b64decode | trim', check['failed_when'])
        self.assertTrue(check['no_log'])


if __name__ == '__main__':
    unittest.main()
