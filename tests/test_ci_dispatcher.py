"""Exercise CI input and approval boundaries without privilege or image builds."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from unittest.mock import patch
from types import SimpleNamespace

import yaml

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('dispatcher', REPO / 'ansible/roles/builder/files/dispatch_candidate.py')
DISPATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DISPATCH)


class DispatcherBoundary(unittest.TestCase):
    def setUp(self):
        self.request = ('debian-13', 'cloudstack-kvm')
        self.approval = {'profile': 'debian-13', 'target': 'cloudstack-kvm', 'version': '20261116-r9',
                         'source_commit': 'a' * 40, 'site_path': '/private/approved.json', 'expires_at': 200}

    def test_only_sixteen_exact_stage_arguments_are_accepted(self):
        for profile in ('debian-13', 'ubuntu-26.04'):
            for target in ('cloudstack-kvm', 'proxmox-kvm', 'proxmox-lxc'):
                for stage in DISPATCH.STAGES:
                    self.assertEqual(DISPATCH.arguments([stage, profile, target]), (stage, profile, target))
        for args in ([], [*self.request], ['publish', *self.request], ['build', *self.request, 'extra'], ['build', 'debian-13;id', 'cloudstack-kvm']):
            with self.subTest(args=args), self.assertRaises(ValueError):
                DISPATCH.arguments(args)

    def test_operator_approval_binds_profile_target_expiry_and_source(self):
        self.assertEqual(DISPATCH.approved_request(self.approval, self.request, 100), Path('/private/approved.json'))
        for update in ({'profile': 'ubuntu-26.04'}, {'target': 'proxmox-lxc'}, {'expires_at': 100},
                       {'expires_at': True}, {'version': '../../replace'}, {'source_commit': 'main'},
                       {'command': 'id'}, {'site_path': 'relative.json'}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                DISPATCH.approved_request(self.approval | update, self.request, 100)

    def test_sources_are_derived_from_approved_snapshot_and_cannot_reach_private_hosts(self):
        site = {'mirror_url': 'https://snapshot.debian.org/archive/debian/20261114T000000Z',
                'security_mirror_url': 'https://snapshot.debian.org/archive/debian-security/20261114T000000Z',
                'inrelease_sha256': dict.fromkeys(('base', 'updates', 'security'), 'b' * 64)}
        sources = DISPATCH.source_records('debian-13', site)
        self.assertEqual(len(sources), 3)
        self.assertTrue(sources[2]['url'].endswith('/dists/trixie-security/InRelease'))
        for bad in ('http://snapshot.debian.org/archive/debian', 'https://127.0.0.1/data',
                    'https://snapshot.debian.org.evil.invalid/data', 'https://user@10.0.0.1/data'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                DISPATCH.source_records('debian-13', site | {'mirror_url': bad})

    def test_cleanup_only_stops_named_units_and_rejects_running_descendants(self):
        unit = 'zs-golden-build-ci-test.service'
        with tempfile.TemporaryDirectory() as temp:
            events = Path(temp) / 'cgroup.events'
            events.write_text('populated 1\nfrozen 0\n')
            states = [{'LoadState': 'loaded', 'ActiveState': 'active'}, {'LoadState': 'loaded', 'ActiveState': 'inactive'}]
            with patch.object(DISPATCH, 'unit_state', side_effect=states), patch.object(DISPATCH.subprocess, 'run') as call, \
                 patch.object(DISPATCH.Path, 'exists', return_value=True), patch.object(DISPATCH.Path, 'read_text', return_value=events.read_text()):
                with self.assertRaisesRegex(ValueError, 'populated'):
                    DISPATCH.cleanup([unit], '/github.slice/github-runner.slice')
                self.assertEqual(call.call_args.args[0], ['systemctl', 'stop', unit])

    def test_fleet_budget_drift_fails_before_creating_work(self):
        state = {'LoadState': 'loaded', 'ActiveState': 'active', 'ControlGroup': '/github.slice/github-runner.slice',
                 'MemoryHigh': str(24 * 1024 ** 3), 'MemoryMax': str(26 * 1024 ** 3), 'MemorySwapMax': str(2 * 1024 ** 3)}
        with patch.object(DISPATCH, 'unit_state', return_value=state):
            self.assertEqual(DISPATCH.fleet_slice(), state['ControlGroup'])
        for change in ({'MemoryMax': 'infinity'}, {'LoadState': 'not-found'}, {'MemorySwapMax': 'max'}, {'ControlGroup': '/system.slice'}):
            with self.subTest(change=change), patch.object(DISPATCH, 'unit_state', return_value=state | change):
                with self.assertRaises(ValueError):
                    DISPATCH.fleet_slice()

    def test_orphaned_or_racing_parent_is_rejected(self):
        with patch.object(DISPATCH.os, 'getppid', return_value=1):
            with self.assertRaisesRegex(ValueError, 'already orphaned'):
                DISPATCH.parent_death_guard()
        with patch.object(DISPATCH.os, 'getppid', side_effect=[123, 1]), patch.object(DISPATCH.ctypes, 'CDLL') as libc:
            libc.return_value.prctl.return_value = 0
            with self.assertRaisesRegex(ValueError, 'parent changed'):
                DISPATCH.parent_death_guard()

    def test_every_probe_unit_shares_the_guard_and_fleet_slice(self):
        play = yaml.safe_load((REPO / 'ansible/playbooks/21-verify-ci-egress.yml').read_text())[0]
        common = next(task['ansible.builtin.set_fact']['golden_unit_properties'] for task in play['tasks']
                      if 'golden_unit_properties' in task.get('ansible.builtin.set_fact', {}))
        resolver = next(task['ansible.builtin.command']['argv'] for task in play['tasks'] if task['name'].startswith('Resolve source'))
        fixture = next(task for task in play['tasks'] if task['name'].startswith('Prove DNS'))['block'][0]['ansible.builtin.command']['argv']
        for argv in (common, resolver, fixture):
            for option in ('--property=Slice=github-runner.slice', '--property=BindsTo={{ golden_ci_guard_unit }}',
                           '--property=After={{ golden_ci_guard_unit }}', '--property=KillMode=control-group', '--property=TimeoutStopSec=15'):
                self.assertIn(option, argv)
        props = DISPATCH.lifetime_properties('guard.service')
        self.assertIn('--property=Slice=github-runner.slice', props)
        self.assertIn('--property=BindsTo=guard.service', props)

    def test_guard_requires_a_pidfd_and_cannot_restart(self):
        tasks = yaml.safe_load((REPO / 'ansible/roles/builder/tasks/main.yml').read_text())
        packages = next(task['ansible.builtin.apt']['name'] for task in tasks if 'ansible.builtin.apt' in task)
        self.assertIn('procps', packages)
        with patch.object(DISPATCH.os, 'getpid', return_value=999), patch.object(DISPATCH.Path, 'write_text'), \
             patch.object(DISPATCH.subprocess, 'run') as call, \
             patch.object(DISPATCH, 'unit_state', return_value={'ActiveState': 'active', 'MainPID': '123'}), \
             patch.object(DISPATCH.Path, 'glob', return_value=[Path('/proc/123/fdinfo/3')]), \
             patch.object(DISPATCH.Path, 'read_text', return_value='Pid:\t999\n'):
            DISPATCH.start_guard('guard.service', Path('/private/pid'))
            argv = call.call_args.args[0]
            self.assertIn('--property=Restart=no', argv)
            self.assertIn('--property=StartLimitIntervalSec=infinity', argv)
            self.assertIn('--property=StartLimitBurst=1', argv)
            self.assertIn('--property=Slice=github-runner.slice', argv)
            self.assertEqual(argv[-3:], ['/usr/bin/pidwait', '-F', Path('/private/pid')])

    def test_nonroot_or_writable_execution_ancestry_is_rejected(self):
        for info in (SimpleNamespace(st_uid=1001, st_mode=0o100755),
                     SimpleNamespace(st_uid=0, st_mode=0o100775),
                     SimpleNamespace(st_uid=0, st_mode=0o120777)):
            with self.subTest(info=info), patch.object(DISPATCH.Path, 'lstat', return_value=info):
                with self.assertRaisesRegex(ValueError, 'Unprotected'):
                    DISPATCH.protected(Path('/protected/dispatcher'))

    def test_isolated_entry_point_ignores_pythonpath_injection(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'json.py').write_text('raise RuntimeError("injected module executed")\n')
            result = subprocess.run([sys.executable, '-I', str(REPO / 'ansible/roles/builder/files/dispatch_candidate.py'), 'invalid'],
                                    env=dict(os.environ, PYTHONPATH=temp), capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr.strip(), 'Candidate request failed; inspect private operator evidence.')
            self.assertEqual(result.stdout, '')
        self.assertTrue((REPO / 'ansible/roles/builder/files/dispatch_candidate.py').read_text().startswith('#!/usr/bin/python3 -I\n'))


class StageReceipts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.approval = {'profile': 'debian-13', 'target': 'cloudstack-kvm', 'version': '20261116-r1',
                         'source_commit': 'a' * 40, 'site_path': '/private/site.json', 'expires_at': 200}
        self.identity, self.binding = DISPATCH.operation_identity(self.approval, b'{"fixture":true}')
        self.operation = self.root / self.binding
        self.operation.mkdir()
        DISPATCH.write_new(self.operation / 'identity.json', {'identity': self.identity, 'binding': self.binding})
        self.log = self.root / 'private.log'
        self.log.write_text('fixture evidence')
        self.candidate = {'candidate': '/workspace/candidate.json', 'candidate_sha256': 'b' * 64,
                          'artifact': '/workspace/disk.qcow2', 'artifact_sha256': 'c' * 64}
        self.protected = patch.object(DISPATCH, 'protected', side_effect=lambda p: p)
        self.protected.start()
        self.addCleanup(self.protected.stop)

    def receipt(self, stage):
        DISPATCH.finalize_receipt(self.operation, stage, self.binding, None if stage == 'preflight' else self.candidate, [self.log])

    def test_binding_survives_expiry_renewal_but_not_approved_input_change(self):
        self.assertEqual(DISPATCH.operation_identity(self.approval | {'expires_at': 300}, b'{"fixture":true}')[1], self.binding)
        for key, value in [('version', '20261116-r2'), ('source_commit', 'd' * 40), ('site_path', '/other.json'),
                           ('profile', 'ubuntu-26.04'), ('target', 'proxmox-lxc')]:
            with self.subTest(key=key):
                self.assertNotEqual(DISPATCH.operation_identity(self.approval | {key: value}, b'{"fixture":true}')[1], self.binding)
        self.assertNotEqual(DISPATCH.operation_identity(self.approval, b'{ "fixture":true}')[1], self.binding)
        with self.assertRaisesRegex(ValueError, 'expired'):
            DISPATCH.approved_request(self.approval, ('debian-13', 'cloudstack-kvm'), 201)

    def test_stage_order_and_successful_reuse_are_bound_to_artifact(self):
        with self.assertRaisesRegex(ValueError, 'Previous stage'):
            DISPATCH.check_receipts(self.operation, 'build', self.binding, self.candidate)
        self.receipt('preflight')
        self.assertIsNone(DISPATCH.check_receipts(self.operation, 'build', self.binding, self.candidate))
        for stage in ('build', 'inspect', 'smoke'):
            self.receipt(stage)
            self.assertEqual(DISPATCH.check_receipts(self.operation, stage, self.binding, self.candidate)['stage'], stage)
        with self.assertRaisesRegex(ValueError, 'candidate binding'):
            DISPATCH.check_receipts(self.operation, 'smoke', self.binding, self.candidate | {'artifact_sha256': 'f' * 64})

    def test_evidence_and_dependency_receipt_tamper_fail_closed(self):
        self.receipt('preflight'); self.receipt('build')
        self.log.write_text('modified')
        with self.assertRaisesRegex(ValueError, 'evidence changed'):
            DISPATCH.check_receipts(self.operation, 'build', self.binding, self.candidate)
        self.log.write_text('fixture evidence')
        path = self.operation / 'preflight.json'
        data = json.loads(path.read_text()); data['completed_at'] += 1
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'identity/order'):
            DISPATCH.check_receipts(self.operation, 'build', self.binding, self.candidate)

    def test_failed_inspect_attempt_does_not_preclude_retry(self):
        self.receipt('preflight'); self.receipt('build')
        (self.root / 'failed-attempt.txt').write_text('inspection failed')
        self.assertIsNone(DISPATCH.check_receipts(self.operation, 'inspect', self.binding, self.candidate))
        self.receipt('inspect')
        self.assertEqual(DISPATCH.check_receipts(self.operation, 'inspect', self.binding, self.candidate)['status'], 'passed')

    def test_atomic_publish_never_replaces_or_exposes_partial_receipt(self):
        path = self.root / 'result.json'
        real_open = Path.open
        class InterruptedFile:
            def __init__(self, file): self.file = file
            def __enter__(self): return self
            def __exit__(self, *args): self.file.close()
            def write(self, value):
                self.file.write(value[:5]); self.file.flush()
                raise OSError('injected interrupted write')
        def interrupted(file, *args, **kwargs):
            result = real_open(file, *args, **kwargs)
            return InterruptedFile(result) if file.name.endswith('.tmp') else result
        with patch.object(Path, 'open', interrupted), self.assertRaises(OSError):
            DISPATCH.write_new(path, {'complete': True})
        self.assertFalse(path.exists())
        self.assertFalse(list(self.root.glob('*.tmp')))
        DISPATCH.write_new(path, {'complete': True})
        with self.assertRaises(FileExistsError):
            DISPATCH.write_new(path, {'replace': True})
        self.assertEqual(json.loads(path.read_text()), {'complete': True})

    def test_private_stage_units_bind_lifetime_slice_and_resource_caps(self):
        environment = dict.fromkeys(('PATH', 'HOME', 'LANG', 'PYTHONDONTWRITEBYTECODE', 'ANSIBLE_CONFIG',
                                     'ANSIBLE_ROLES_PATH', 'ANSIBLE_COLLECTIONS_PATH'), 'fixture')
        with patch.dict(os.environ, environment):
            argv = DISPATCH.unit_command('test.service', 'guard.service', self.root, ['/bin/true'], 300, private=True)
        for prop in ('PrivateNetwork=yes', 'PrivateMounts=yes', 'MemoryMax=8G', 'Slice=github-runner.slice',
                     'BindsTo=guard.service', 'After=guard.service', 'KillMode=control-group', 'RuntimeMaxSec=300'):
            self.assertIn('--property=' + prop, argv)

    def test_candidate_bytes_and_artifact_are_independently_revalidated(self):
        workspace = self.root / 'workspace'; workspace.mkdir()
        run = workspace / 'candidate'; run.mkdir()
        artifact = run / 'disk.qcow2'; artifact.write_bytes(b'fixture-not-a-real-image')
        candidate = run / 'candidate.json'
        data = {**self.identity, 'schema_version': 1, 'artifact': {'path': str(artifact), 'sha256': DISPATCH.digest(artifact)}}
        candidate.write_text(json.dumps(data))
        first = DISPATCH.candidate_binding(candidate, self.identity, workspace)
        candidate.write_text(json.dumps(data, indent=2))
        second = DISPATCH.candidate_binding(candidate, self.identity, workspace)
        self.assertNotEqual(first['candidate_sha256'], second['candidate_sha256'])
        self.assertEqual(first['artifact_sha256'], second['artifact_sha256'])
        artifact.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'artifact changed'):
            DISPATCH.candidate_binding(candidate, self.identity, workspace)


class DispatchLifecycle(unittest.TestCase):
    """Run the real orchestration with synthetic files and no system services."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.prefix = self.root / 'prefix'
        self.project, self.state, self.workspace = self.prefix / 'project', self.prefix / 'ci', self.root / 'workspace'
        for path in (self.project, self.state / 'evidence', self.state / 'operations', self.workspace,
                     self.prefix / 'venv', self.prefix / 'collections', self.prefix / 'bin', self.root / 'requests', self.root / 'native-evidence'):
            path.mkdir(parents=True, exist_ok=True)
        (self.state / 'ansible.cfg').write_text('[defaults]\n')
        self.site = self.root / 'site.json'
        self.site.write_text(json.dumps({'version': '20261116-r1', 'workspace': str(self.workspace),
            'mirror_url': 'https://snapshot.debian.org/archive/debian/20261114T000000Z',
            'security_mirror_url': 'https://snapshot.debian.org/archive/debian-security/20261114T000000Z',
            'inrelease_sha256': dict.fromkeys(('base', 'updates', 'security'), 'a' * 64)}))
        self.native_path = self.root / 'native.json'; self.native_path.write_text('{}')
        self.config = self.root / 'ci.json'
        self.config.write_text(json.dumps({'project': str(self.project), 'state': str(self.state), 'workspace': str(self.workspace),
            'native_site': str(self.native_path), 'lxc_id_base': 300000, 'min_free_bytes': 1}))
        self.approval = {'profile': 'debian-13', 'target': 'cloudstack-kvm', 'version': '20261116-r1',
                         'source_commit': 'a' * 40, 'site_path': str(self.site), 'expires_at': int(time.time()) + 3600}
        self.approval_path = self.root / 'requests/debian-13-cloudstack-kvm.json'
        self.approval_path.write_text(json.dumps(self.approval))
        self.binding = DISPATCH.operation_identity(self.approval, self.site.read_bytes())[1]
        self.operation = self.state / 'operations' / self.binding
        self.candidate = self.workspace / 'debian-13-cloudstack-kvm-20261116-r1/candidate.json'
        self.native = SimpleNamespace(workspace=self.workspace, project=self.project, tool_prefix=self.prefix,
            evidence=self.root / 'native-evidence', source_commit='a' * 40, site_path=self.native_path,
            runner_service='actions.runner.fixture.service')
        sys.path.insert(0, str(REPO / 'tests/native'))
        import common
        import lxc_smoke  # Make only the reviewed local fixture modules available.
        sys.path.pop(0)
        self.native_module = common

    def invoke(self, stage, cleanup_failure=False, build=None):
        def state(unit):
            return {'Id': unit, 'LoadState': 'loaded', 'ActiveState': 'active'} if unit == self.native.runner_service else {'LoadState': 'not-found'}
        def log(argv, path, timeout, expected=0):
            path.write_text('synthetic stage result')
        real_digest, real_fstat, real_resolve = DISPATCH.digest, os.fstat, Path.resolve
        def digest(path):
            return 'f' * 64 if str(path) == '/etc/zs-golden-images/toolchain.json' else real_digest(path)
        def fstat(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
        with ExitStack() as stack:
            for name, value in [('PREFIX', self.prefix), ('CONFIG', self.config), ('REQUESTS', self.root / 'requests')]:
                stack.enter_context(patch.object(DISPATCH, name, value))
            stack.enter_context(patch.dict(os.environ))
            stack.enter_context(patch.object(DISPATCH.sys, 'platform', 'linux'))
            for owner, name, kwargs in [
                (DISPATCH.os, 'geteuid', {'return_value': 0}), (DISPATCH.os, 'fstat', {'side_effect': fstat}),
                (DISPATCH.os, 'dup2', {}), (DISPATCH.os, 'chdir', {}), (DISPATCH, 'parent_death_guard', {}),
                (DISPATCH, 'protected', {'side_effect': lambda p: p}), (DISPATCH, 'protected_tree', {}),
                (DISPATCH, 'fleet_slice', {'return_value': '/github.slice/github-runner.slice'}),
                (DISPATCH, 'digest', {'side_effect': digest}), (DISPATCH, 'unit_state', {'side_effect': state}),
                (DISPATCH, 'start_guard', {}), (DISPATCH, 'logged', {'side_effect': log}),
                (DISPATCH.shutil, 'disk_usage', {'return_value': SimpleNamespace(free=10**12)}),
                (DISPATCH.shutil, 'which', {'return_value': '/usr/bin/true'}),
                (DISPATCH.Path, 'is_char_device', {'return_value': True}),
                (DISPATCH.Path, 'resolve', {'autospec': True, 'side_effect': lambda p, **kw: p if str(p) == '/root' else real_resolve(p, **kw)}),
                (self.native_module, 'load_site', {'return_value': self.native}),
                (DISPATCH.subprocess, 'check_output', {'side_effect': lambda argv, **kw: '' if 'status' in argv else 'a' * 40}),
                (DISPATCH.signal, 'signal', {}),
                (DISPATCH, 'cleanup', {'side_effect': RuntimeError('injected cleanup failure')} if cleanup_failure else {})]:
                stack.enter_context(patch.object(owner, name, **kwargs))
            build_mock = stack.enter_context(patch.object(DISPATCH, 'build_stage', side_effect=build))
            result = DISPATCH.main([stage, 'debian-13', 'cloudstack-kvm'])
            return result, build_mock.call_count

    def build(self, project, state, evidence, name, guard, approval, sources, candidate):
        candidate.parent.mkdir()
        artifact = candidate.parent / 'disk.qcow2'; artifact.write_bytes(b'synthetic artifact')
        candidate.write_text(json.dumps({'schema_version': 1, **{k: approval[k] for k in ('profile', 'target', 'version', 'source_commit')},
            'artifact': {'path': str(artifact), 'sha256': DISPATCH.digest(artifact)}}))
        log = evidence / 'build.log'; log.write_text('synthetic build result')
        return [log]

    def test_cleanup_failure_never_publishes_pass_and_preflight_retry_succeeds(self):
        with self.assertRaisesRegex(RuntimeError, 'cleanup failure'):
            self.invoke('preflight', cleanup_failure=True)
        self.assertFalse((self.operation / 'preflight.json').exists())
        self.assertFalse(self.candidate.parent.exists())
        self.assertEqual(self.invoke('preflight')[0], self.binding)

    def test_successful_build_reuse_does_not_rebuild_and_expiry_is_rechecked(self):
        self.invoke('preflight')
        self.assertEqual(self.invoke('build', build=self.build), (self.binding, 1))
        self.assertEqual(self.invoke('build', build=self.build), (self.binding, 0))
        self.approval_path.write_text(json.dumps(self.approval | {'expires_at': 1}))
        with self.assertRaisesRegex(ValueError, 'expired'):
            self.invoke('build', build=self.build)

    def test_partial_failed_build_requires_new_version(self):
        self.invoke('preflight')
        self.candidate.parent.mkdir()
        with self.assertRaisesRegex(ValueError, 'Unfinalized version'):
            self.invoke('build', build=self.build)

    def test_changed_native_policy_invalidates_receipt_reuse(self):
        self.invoke('preflight')
        self.native_path.write_text('{"changed":true}')
        with self.assertRaisesRegex(ValueError, 'Operation policy changed'):
            self.invoke('preflight')



class SmokeStageAdapter(unittest.TestCase):
    def exercise(self, target, mutate=None):
        """Run the real adapter; replace only privileged execution and ownership checks."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / 'attempt'; evidence.mkdir()
            site = root / 'native.json'; site.write_text('{}')
            candidate = root / 'candidate.json'; candidate.write_text('{}')
            bound = {'candidate_sha256': DISPATCH.digest(candidate), 'artifact_sha256': 'b' * 64}
            approval = {'target': target, 'source_commit': 'a' * 40}
            settings = {'native_site': str(site), 'lxc_id_base': 2000000}
            native = SimpleNamespace(evidence=root / 'native-evidence')
            name = 'ci-' + 'c' * 24
            guard = 'zs-golden-guard-' + name + '.service'
            sys.path.insert(0, str(REPO / 'tests/native'))
            try:
                import common
            finally:
                sys.path.pop(0)
            reports = []

            def logged(argv, log, timeout, expected=0):
                # Consume the actual native helper CLI, including its output destination.
                args = list(map(str, argv))
                helper = str(REPO / 'tests/native' / ('vm_smoke.py' if target != 'proxmox-lxc' else 'lxc_smoke.py'))
                self.assertIn(helper, args)
                self.assertEqual(args[args.index('--site') + 1], str(site))
                context = json.loads(Path(args[args.index('--ci-context') + 1]).read_text())
                self.assertEqual(context['candidate_sha256'], bound['candidate_sha256'])
                self.assertEqual(context['guard_unit'], guard)
                self.assertEqual(context['operation_binding'], 'd' * 64)
                for option in ('--property=PrivateNetwork=yes', '--property=PrivateMounts=yes',
                               '--property=Slice=github-runner.slice', '--property=BindsTo=' + guard,
                               '--property=After=' + guard, '--setenv=GOLDEN_APPLY=smoke'):
                    self.assertIn(option, args)
                self.assertEqual(args[args.index('/usr/bin/unshare') + 1:args.index('/usr/bin/unshare') + 5],
                                 ['--mount', '--propagation', 'private', '--fork'])
                output = Path(args[args.index(str(candidate)) + 1])
                output.mkdir(parents=True)
                report = {'status': 'passed', 'original_artifact_unchanged': True,
                          **bound, 'test_source_commit': approval['source_commit']}
                if target != 'proxmox-lxc':
                    self.assertNotIn('--property=Delegate=yes', args)
                    report.update(scope='native-kvm-smoke-only', clone_uniqueness='passed',
                                  clones=[{'reboot_persistence': 'passed'}, {}])
                else:
                    self.assertIn('--property=Delegate=yes', args)
                    self.assertEqual(args[args.index('--id-base') + 1], str(settings['lxc_id_base']))
                    report.update(scope='native-lxc-one-clone-smoke-only', container_stopped=True,
                                  restart_persistence='passed', host_id_base=settings['lxc_id_base'],
                                  identity={key: key + str(len(reports)) for key in ('machine_id', 'host_key', 'hostname')})
                    if reports:
                        self.assertEqual(args[args.index('--compare-report') + 1], str(reports[0]))
                        report.update(previous_report_sha256=DISPATCH.digest(reports[0]), clone_uniqueness='passed')
                    else:
                        self.assertNotIn('--compare-report', args)
                if mutate:
                    mutate(report, len(reports))
                path = output / 'smoke-report.json'
                path.write_text(json.dumps(report))
                reports.append(path)
                log.write_text('Synthetic native command result')

            environment = dict.fromkeys(('PATH', 'HOME', 'LANG', 'PYTHONDONTWRITEBYTECODE',
                                         'ANSIBLE_CONFIG', 'ANSIBLE_ROLES_PATH', 'ANSIBLE_COLLECTIONS_PATH'), 'fixture')
            with patch.dict(os.environ, environment), patch.object(DISPATCH, 'protected', side_effect=lambda p: p), \
                 patch.object(DISPATCH, 'logged', side_effect=logged) as commands:
                result = DISPATCH.smoke_stage(REPO, evidence, name, guard, 'd' * 64, approval,
                                              candidate, bound, native, settings, common)
            self.assertEqual(result, reports)
            self.assertEqual(commands.call_count, 1 if target != 'proxmox-lxc' else 2)

    def test_kvm_consumes_two_clone_report_from_bound_private_command(self):
        self.exercise('cloudstack-kvm')
        self.exercise('proxmox-kvm')

    def test_kvm_rejects_wrong_artifact_and_incomplete_reboot_or_clone_evidence(self):
        for change in ({'artifact_sha256': 'f' * 64}, {'clones': [{}, {}]},
                       {'clones': [{'reboot_persistence': 'passed'}]}, {'clone_uniqueness': 'failed'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.exercise('cloudstack-kvm', lambda report, number: report.update(change))

    def test_native_reports_require_candidate_source_and_unchanged_artifact(self):
        for target in ('cloudstack-kvm', 'proxmox-kvm', 'proxmox-lxc'):
            for change in ({'candidate_sha256': 'f' * 64}, {'test_source_commit': 'f' * 40},
                           {'status': 'failed'}, {'original_artifact_unchanged': False}):
                with self.subTest(target=target, change=change), self.assertRaisesRegex(ValueError, 'binding or result mismatch'):
                    self.exercise(target, lambda report, number: report.update(change))

    def test_lxc_consumes_two_sequential_delegated_reports_with_exact_comparison(self):
        self.exercise('proxmox-lxc')

    def test_lxc_rejects_missing_restart_stop_or_id_mapping_proof(self):
        for change in ({'container_stopped': False}, {'restart_persistence': 'failed'}, {'host_id_base': 65536}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'Incomplete LXC smoke'):
                self.exercise('proxmox-lxc', lambda report, number: report.update(change))

    def test_lxc_rejects_wrong_previous_report_hash_and_failed_comparison(self):
        for change in ({'previous_report_sha256': 'f' * 64}, {'clone_uniqueness': 'failed'}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'not bound to the first'):
                self.exercise('proxmox-lxc', lambda report, number: report.update(change) if number == 1 else None)

    def test_lxc_rejects_reused_identity_even_when_second_report_claims_success(self):
        for field in ('machine_id', 'host_key', 'hostname'):
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'Clones reused identity: ' + field):
                self.exercise('proxmox-lxc', lambda report, number: report['identity'].update({field: field + '0'}) if number == 1 else None)


if __name__ == '__main__':
    unittest.main()
