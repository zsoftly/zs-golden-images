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
        self.assertEqual(result['acceptance_source'], 'signed-release-metadata')
        self.assertNotIn('status', result)
        self.assertNotIn('source_image_url', result)
        self.assertNotIn('source_image_sha256', result)

    def test_lxc_coverage_never_claims_kernel_controls(self):
        data = task('image_harden', 'Record explicit incomplete hardening coverage')['ansible.builtin.copy']
        env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        env.filters['to_nice_json'] = json.dumps
        report = json.loads(env.from_string(data['content']).render(golden_target='proxmox-lxc'))
        self.assertFalse(report['cis_complete'])
        self.assertEqual(report['acceptance_source'], 'signed-release-metadata')
        self.assertNotIn('promotion_allowed', report)
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

    def test_vm_dns_and_metadata_have_one_runtime_owner(self):
        data = task('image_configure', 'Configure metadata sources for CloudStack')['ansible.builtin.copy']
        config = yaml.safe_load(data['content'])
        self.assertEqual(config['datasource_list'], ['CloudStack', 'ConfigDrive', 'None'])
        self.assertEqual(config['system_info']['network'],
                         {'renderers': ['netplan'], 'activators': ['netplan']})
        deps = (ROOT / 'builders/diskimage-builder/elements/zs-configure/element-deps').read_text().splitlines()
        self.assertIn('cloud-init', deps)
        self.assertNotIn('cloud-init-datasources', deps)
        env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        package_template = task('image_configure', 'Install shared image packages without starting services')['ansible.builtin.apt']['name']
        service_template = task('image_configure', 'Enable services for the next guest boot only')['loop']
        for target in ('cloudstack-kvm', 'proxmox-lxc'):
            packages = yaml.safe_load(env.from_string(package_template).render(golden_target=target))
            services = yaml.safe_load(env.from_string(service_template).render(golden_target=target))
            for package in ('netplan.io', 'systemd-resolved'):
                self.assertEqual(package in packages, target == 'cloudstack-kvm')
            for service in ('systemd-networkd', 'systemd-resolved'):
                self.assertEqual(service in services, target == 'cloudstack-kvm')

    def test_build_dns_is_preserved_privately_around_package_installation(self):
        names = [item['name'] for item in tasks('image_configure')]
        preserve = task('image_configure', 'Preserve build DNS before installing the runtime resolver')
        restore = task('image_configure', 'Restore build DNS until final image cleanup')
        self.assertTrue(preserve['no_log'])
        self.assertTrue(restore['no_log'])
        self.assertFalse(restore['ansible.builtin.copy']['follow'])
        self.assertEqual(preserve['when'], "golden_target == 'cloudstack-kvm'")
        self.assertEqual(restore['when'], preserve['when'])
        install = names.index('Install shared image packages without starting services')
        self.assertLess(names.index(preserve['name']), install)
        self.assertGreater(names.index(restore['name']), install)

    def test_cleanup_removes_private_resolvers_without_following_symlinks(self):
        item = task('image_cleanup', 'Remove inherited resolver configuration after package operations')
        self.assertEqual(tasks('image_cleanup')[-1]['name'], item['name'])
        for target in ('cloudstack-kvm', 'proxmox-lxc'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                etc = root / 'etc'
                etc.mkdir()
                run = root / 'run'
                (run / 'systemd' / 'resolve').mkdir(parents=True)
                private = root / 'private-resolver'
                private.write_text('nameserver 192.0.2.1\nsearch private.invalid\n')
                (etc / 'resolv.conf').symlink_to(private)
                (etc / 'resolv.conf.ORIG').write_text(private.read_text())
                if target == 'cloudstack-kvm':
                    (etc / '.resolv.conf.systemd-resolved.bak').write_text(private.read_text())
                    (run / 'systemd' / 'resolve' / 'stub-resolv.conf').write_text(private.read_text())
                mountpoint = root / 'mountpoint'
                mountpoint.write_text('#!/bin/sh\nexit 1\n')
                mountpoint.chmod(0o700)
                script = item['ansible.builtin.shell'].replace('/etc', shlex.quote(str(etc))).replace(' /run', ' ' + shlex.quote(str(run)))
                result = subprocess.run(['/bin/sh', '-c', script], text=True, capture_output=True,
                                        env={**os.environ, 'PATH': directory + os.pathsep + os.environ['PATH'],
                                             'GOLDEN_TARGET': target})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(private.read_text(), 'nameserver 192.0.2.1\nsearch private.invalid\n')
                self.assertFalse((etc / 'resolv.conf.ORIG').exists())
                if target == 'cloudstack-kvm':
                    self.assertEqual(os.readlink(etc / 'resolv.conf'), '../run/systemd/resolve/stub-resolv.conf')
                    self.assertFalse((etc / '.resolv.conf.systemd-resolved.bak').exists())
                    self.assertFalse((run / 'systemd' / 'resolve' / 'stub-resolv.conf').exists())
                else:
                    self.assertFalse((etc / 'resolv.conf').is_symlink())
                    self.assertEqual((etc / 'resolv.conf').read_bytes(), b'')

    def test_build_dns_restore_replaces_symlink_without_modifying_its_target(self):
        restore = task('image_configure', 'Restore build DNS until final image cleanup')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'stub-resolv.conf'
            target.write_text('nameserver 127.0.0.53\n')
            resolver = root / 'resolv.conf'
            resolver.symlink_to(target)
            arguments = dict(restore['ansible.builtin.copy'])
            arguments.pop('owner')
            arguments.pop('group')
            arguments['dest'] = str(resolver)
            arguments['content'] = 'nameserver 192.0.2.1\n'
            minimal = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                        'tasks': [{'ansible.builtin.copy': arguments, 'no_log': True}]}]
            path = root / 'play.yml'
            path.write_text(yaml.safe_dump(minimal))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(resolver.is_symlink())
            self.assertEqual(resolver.read_text(), 'nameserver 192.0.2.1\n')
            self.assertEqual(target.read_text(), 'nameserver 127.0.0.53\n')

    def test_vm_resolver_cleanup_guards_parents_and_mounts_without_following_leaf_links(self):
        item = task('image_cleanup', 'Remove inherited resolver configuration after package operations')
        cases = ('leaf-links', 'linked-etc', 'linked-run', 'linked-systemd', 'linked-resolve',
                 'mounted-etc', 'mounted-run', 'mounted-systemd', 'mounted-resolve', 'mounted-stub', 'mounted-backup')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                etc = root / 'etc'
                etc.mkdir()
                run = root / 'run'
                resolve = run / 'systemd' / 'resolve'
                resolve.mkdir(parents=True)
                private = root / 'private'
                private.mkdir()
                secret = private / 'stub-resolv.conf'
                secret.write_text('nameserver 192.0.2.1\nsearch private.invalid\n')
                resolver = etc / 'resolv.conf'
                resolver.write_text(secret.read_text())
                backup = etc / '.resolv.conf.systemd-resolved.bak'
                stub = resolve / 'stub-resolv.conf'
                if case == 'leaf-links':
                    backup.symlink_to(secret)
                    stub.symlink_to(secret)
                elif case.startswith('linked-'):
                    parent = {'etc': etc, 'run': run, 'systemd': run / 'systemd', 'resolve': resolve}[case[7:]]
                    parent.rename(root / 'original-parent')
                    parent.symlink_to(private)
                else:
                    backup.write_text(secret.read_text())
                    stub.write_text(secret.read_text())
                mounted = {'etc': etc, 'run': run, 'systemd': run / 'systemd', 'resolve': resolve,
                           'stub': stub, 'backup': backup}.get(case[8:]) if case.startswith('mounted-') else None
                mountpoint = root / 'mountpoint'
                mountpoint.write_text('#!/bin/sh\n' + ('test "$2" = ' + shlex.quote(str(mounted)) + '\n' if mounted else 'exit 1\n'))
                mountpoint.chmod(0o700)
                script = item['ansible.builtin.shell'].replace('/etc', shlex.quote(str(etc))).replace(' /run', ' ' + shlex.quote(str(run)))
                result = subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True,
                                        env={**os.environ, 'PATH': directory + os.pathsep + os.environ['PATH'],
                                             'GOLDEN_TARGET': 'cloudstack-kvm'})
                self.assertEqual(result.returncode == 0, case == 'leaf-links', result.stderr)
                self.assertEqual(secret.read_text(), 'nameserver 192.0.2.1\nsearch private.invalid\n')
                if case == 'leaf-links':
                    self.assertFalse(backup.is_symlink())
                    self.assertFalse(stub.is_symlink())
                elif case != 'linked-etc':
                    self.assertEqual(resolver.read_text(), secret.read_text())

    def test_cleanup_refuses_a_mounted_resolver_before_removing_it(self):
        item = task('image_cleanup', 'Remove inherited resolver configuration after package operations')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resolver = root / 'resolv.conf'
            resolver.write_text('nameserver 192.0.2.1\n')
            mountpoint = root / 'mountpoint'
            mountpoint.write_text('#!/bin/sh\nexit 0\n')
            mountpoint.chmod(0o700)
            script = item['ansible.builtin.shell'].replace('/etc/resolv.conf', shlex.quote(str(resolver)))
            result = subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True,
                                    env={**os.environ, 'PATH': directory + os.pathsep + os.environ['PATH'],
                                         'GOLDEN_TARGET': 'cloudstack-kvm'})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(resolver.read_text(), 'nameserver 192.0.2.1\n')

    def test_ansible_state_cleanup_removes_residue_and_refuses_linked_root(self):
        source = (ROOT / 'scripts/configure-rootfs.sh').read_text()
        self.assertLess(source.index('/opt/zs-golden-images/venv/bin/ansible-playbook'),
                        source.index("<<'CLEAN_ANSIBLE'"))
        script = source.split("<<'CLEAN_ANSIBLE'\n", 1)[1].split('\nCLEAN_ANSIBLE', 1)[0]
        for linked in (False, True):
            with self.subTest(linked=linked), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                home = root / 'root'
                home.mkdir()
                external = root / 'private'
                external.mkdir()
                (external / 'keep').write_text('unchanged')
                if linked:
                    (home / '.ansible').symlink_to(external)
                else:
                    (home / '.ansible' / 'tmp').mkdir(parents=True)
                    (home / '.ansible' / 'tmp' / 'module').write_text('temporary')
                    (home / '.ansible' / 'outside').symlink_to(external)
                mountpoint = root / 'mountpoint'
                mountpoint.write_text('#!/bin/sh\nexit 1\n')
                mountpoint.chmod(0o700)
                result = subprocess.run(['/bin/sh', '-c', script.replace('/root', shlex.quote(str(home)))],
                                        capture_output=True, text=True,
                                        env={**os.environ, 'PATH': directory + os.pathsep + os.environ['PATH']})
                self.assertEqual(result.returncode != 0, linked, result.stderr)
                self.assertEqual((external / 'keep').read_text(), 'unchanged')
                if not linked:
                    self.assertFalse((home / '.ansible').exists())

    def test_audit_accepts_external_acceptance_provenance_without_accepting_lxc(self):
        source = (ROOT / 'scripts/audit-guest.sh').read_text()
        expression = source.split("jq -e --arg p \"$profile\" '", 1)[1].split("' /etc/golden-image.json", 1)[0]
        provenance = {'profile': 'debian-13', 'source_commit': 'a' * 40, 'source_kind': 'apt-snapshot',
                      'source_manifest_sha256': 'b' * 64, 'target': 'cloudstack-kvm',
                      'acceptance_source': 'signed-release-metadata'}
        for update, accepted in [({}, True), ({'target': 'proxmox-lxc'}, False),
                                 ({'acceptance_source': 'self-approved'}, False),
                                 ({'source_commit': 'invalid'}, False)]:
            with self.subTest(update=update):
                result = subprocess.run(['jq', '-e', '--arg', 'p', 'debian-13', expression],
                                        input=json.dumps({**provenance, **update}), text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_remediation_control_choices_set_real_ansible_facts(self):
        play = yaml.safe_load((ROOT / 'ansible/playbooks/50-remediate-vm.yml').read_text())[0]
        setting = next(item for item in play['pre_tasks'] if item['name'] == 'Apply reviewed per-control selections')
        minimal = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                    'vars': {'golden_cis_rule_settings': {'deb13cis_rule_5_2_4': False,
                                                        'deb13cis_rule_1_1_1_1': True}},
                    'tasks': [setting, {'ansible.builtin.assert': {'that': [
                        'not deb13cis_rule_5_2_4', 'deb13cis_rule_1_1_1_1']}}]}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'play.yml'
            path.write_text(yaml.safe_dump(minimal))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

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
