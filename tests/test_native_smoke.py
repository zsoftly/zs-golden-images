"""Offline native-smoke safety tests. Never start guests or contact infrastructure."""
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

NATIVE = Path(__file__).parent / 'native'
sys.path.insert(0, str(NATIVE))
import common
import lxc_smoke
import vm_smoke
sys.path.pop(0)


class NativeSiteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.data = {}
        for name in ('workspace', 'evidence', 'tool_prefix'):
            directory = self.root / name
            directory.mkdir()
            self.data[name] = str(directory)
        self.marker = self.root / 'builder.json'
        self.marker.write_text(json.dumps({'purpose': 'isolated-image-builder', 'region': 'yow',
                                           'workspace': self.data['workspace']}))
        self.data.update(builder_marker=str(self.marker), runner_service='actions.runner.fixture.native-test.service')
        self.site = self.root / 'site.json'
        self.site.write_text(json.dumps(self.data))
        self.site.chmod(0o600)

    def load(self, dirty=False):
        self.site.write_text(json.dumps(self.data))
        # Fixtures belong to the test user. Live code independently checks root ownership.
        def git_result(argv, **kwargs):
            return SimpleNamespace(stdout=(' M fixture' if dirty else '') if 'status' in argv else 'a' * 40)
        with patch.object(common, 'protected'), patch.object(common, 'run', side_effect=git_result):
            return common.load_site(self.site)

    def test_requires_explicit_service_and_matching_marker(self):
        site = self.load()
        self.assertEqual(site.runner_service, self.data['runner_service'])
        self.assertEqual(site.workspace, Path(self.data['workspace']))
        self.marker.write_text(json.dumps({'purpose': 'isolated-image-builder', 'region': 'yow',
                                           'workspace': '/different/workspace'}))
        with self.assertRaisesRegex(RuntimeError, 'marker'):
            self.load()

    def test_rejects_missing_wildcard_or_nonservice_runner_inputs(self):
        for value in ('', '*.service', 'actions.runner.other.service --now', 'runner.timer'):
            with self.subTest(value=value):
                self.data['runner_service'] = value
                with self.assertRaises(RuntimeError):
                    self.load()
        del self.data['runner_service']
        with self.assertRaisesRegex(RuntimeError, 'keys'):
            self.load()

    def test_rejects_public_site_file_and_redirected_workspace(self):
        self.site.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'private regular'):
            self.load()
        self.site.chmod(0o600)
        link = self.root / 'redirect'
        link.symlink_to(self.root / 'workspace', target_is_directory=True)
        self.data['workspace'] = str(link)
        with self.assertRaisesRegex(RuntimeError, 'canonical'):
            self.load()

    def test_rejects_qemu_and_lxc_option_separators_in_configured_paths(self):
        for name in ('evidence,format=raw', 'evidence\nlxc.net.0.type=none'):
            with self.subTest(name=name):
                directory = self.root / name
                directory.mkdir()
                self.data['evidence'] = str(directory)
                with self.assertRaisesRegex(RuntimeError, 'option separators'):
                    self.load()

    def test_rejects_dirty_test_source(self):
        with self.assertRaisesRegex(RuntimeError, 'clean committed'):
            self.load(dirty=True)

    def test_rejects_noncanonical_site_before_reading_it(self):
        alias = self.root / 'unused' / '..' / 'site.json'
        with patch.object(common, 'protected') as protected:
            with self.assertRaisesRegex(RuntimeError, 'canonical'):
                common.load_site(alias)
        protected.assert_not_called()

    def test_runner_must_be_loaded_exactly_inactive_and_without_worker(self):
        service = 'actions.runner.fixture.native-test.service'
        cases = [(service, 'loaded', 'inactive', 1, True),
                 (service, 'not-found', 'inactive', 1, False),
                 ('other.service', 'loaded', 'inactive', 1, False),
                 (service, 'loaded', 'active', 1, False),
                 (service, 'loaded', 'inactive', 0, False)]
        for name, load, active, worker_code, allowed in cases:
            response = SimpleNamespace(returncode=0, stdout=f'Id={name}\nLoadState={load}\nActiveState={active}\n')
            with self.subTest(name=name, load=load, active=active, worker_code=worker_code), \
                    patch.object(common, 'run', side_effect=[response, SimpleNamespace(returncode=worker_code)]):
                if allowed:
                    common.require_drained(service)
                else:
                    with self.assertRaises(RuntimeError):
                        common.require_drained(service)

    def test_protected_path_rejects_symlink_even_when_parent_is_trusted(self):
        target = self.root / 'target'
        target.write_text('fixture')
        link = self.root / 'link'
        link.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'redirected'):
            common.protected(link)


class LxcRuntimePathTests(unittest.TestCase):
    def test_seed_hostname_replaces_only_the_disposable_clone_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            neutral = root / 'neutral'
            neutral.write_text('localhost\n')
            for clone, name in enumerate(('golden-smoke-1111', 'golden-smoke-2222')):
                etc = root / str(clone) / 'etc'
                etc.mkdir(parents=True)
                hostname = etc / 'hostname'
                hostname.symlink_to(neutral)
                with patch.object(lxc_smoke.os, 'fchown') as assign_owner:
                    lxc_smoke.seed_hostname(etc.parent, name, 1000000)
                assign_owner.assert_called_once()
                self.assertEqual(assign_owner.call_args.args[1:], (1000000, 1000000))
                self.assertFalse(hostname.is_symlink())
                self.assertEqual(hostname.read_text(), name + '\n')
                self.assertEqual(hostname.stat().st_mode & 0o777, 0o644)
                self.assertEqual(list(etc.iterdir()), [hostname])
            self.assertEqual(neutral.read_text(), 'localhost\n')

    def test_start_and_stop_use_private_mount_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            evidence = root / 'evidence' / 'attempt'
            evidence.parent.mkdir(mode=0o700)
            run_dir = root / 'run'
            run_dir.mkdir()
            artifact = root / 'rootfs.tar'
            artifact.write_bytes(b'fixture')
            candidate = root / 'candidate.json'
            candidate.write_text(json.dumps({'target': 'proxmox-lxc', 'profile': 'debian-13',
                                             'artifact': {'path': artifact.name, 'sha256': common.digest(artifact)}}))
            site = SimpleNamespace(workspace=root, evidence=evidence.parent, project=root, tool_prefix=root,
                                   runner_service='fixture', source_commit='a' * 40)
            commands = []

            def run(argv, **kwargs):
                commands.append(argv)
                if argv[0] == 'ssh-keygen':
                    argv[-1].write_text('fixture private key')
                    argv[-1].with_suffix('.pub').write_text('fixture public key')
                return SimpleNamespace(stdout='STOPPED')

            def path(value):
                return run_dir if value == '/run' else Path(value)

            argv = ['lxc_smoke.py', '--site', str(root / 'site.json'), str(candidate), str(evidence), '--id-base', '1000000']
            with (patch.object(lxc_smoke, 'Path', path), patch.object(lxc_smoke, 'load_site', return_value=site),
                  patch.object(lxc_smoke, 'protected'), patch.object(lxc_smoke, 'require_runner_context'),
                  patch.object(lxc_smoke, 'unused_id_range'), patch.object(lxc_smoke, 'extract'),
                  patch.object(lxc_smoke, 'seed_hostname'),
                  patch.object(lxc_smoke, 'run', side_effect=run), patch.object(lxc_smoke.shutil, 'which', return_value=None),
                  patch.object(lxc_smoke, 'os', wraps=os) as local_os, patch.object(common.fcntl, 'flock'),
                  patch.object(lxc_smoke.subprocess, 'Popen') as popen,
                  patch.object(common, 'wait_for', side_effect=RuntimeError('Guest failed at boot')),
                  patch.object(sys, 'argv', argv), patch.object(sys, 'platform', 'linux')):
                local_os.environ = {'GOLDEN_APPLY': 'smoke'}
                local_os.geteuid.return_value = 0
                local_os.readlink.side_effect = ['private', 'host']
                local_os.umask.return_value = 0
                local_os.fstat.return_value = SimpleNamespace(st_uid=0, st_mode=0o100600)
                local_os.open.return_value = 42
                popen.return_value.poll.return_value = 1
                with self.assertRaisesRegex(RuntimeError, 'Guest failed at boot'):
                    lxc_smoke.main()

            runtime = evidence / 'lxc'
            name = next(runtime.iterdir()).name
            alias = run_dir / name
            start = popen.call_args.args[0]
            self.assertEqual(start[1:5], ['-P', str(alias), '-n', name])
            self.assertEqual(start[start.index('-f') + 1], alias / name / 'config')
            self.assertIn(f'lxc.rootfs.path = dir:{alias / name / "rootfs"}\n', (runtime / name / 'config').read_text())
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
            self.assertEqual(runtime.stat().st_mode & 0o777, 0o711)
            self.assertLess(commands.index(['mount', '--make-rprivate', '/']), commands.index(['mount', '--bind', runtime, alias]))
            self.assertEqual(commands[-3:], [['lxc-stop', *start[1:5], '-t', '20'],
                                             ['lxc-info', *start[1:5], '-sH'], ['umount', alias]])
            self.assertFalse(alias.exists())
            self.assertFalse((evidence / 'admin-key').exists())
            self.assertTrue(json.loads((evidence / 'smoke-report.json').read_text())['container_stopped'])


class NativeArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.artifact = self.root / 'candidate.tar'

    def archive(self, entries):
        with tarfile.open(self.artifact, 'w') as archive:
            for name, kind, target in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = target
                member.mode = 0o755 if kind == tarfile.DIRTYPE else 0o640
                member.uid, member.gid = 12, 34
                archive.addfile(member)

    def test_rejects_traversal_links_and_special_members_before_extraction(self):
        bad_entries = [
            [('/etc/file', tarfile.REGTYPE, '')],
            [('../file', tarfile.REGTYPE, '')],
            [('dir/../../file', tarfile.REGTYPE, '')],
            [('dir', tarfile.SYMTYPE, '/tmp'), ('dir/file', tarfile.REGTYPE, '')],
            [('dir/file', tarfile.REGTYPE, ''), ('dir', tarfile.SYMTYPE, '/tmp')],
            [('hard', tarfile.LNKTYPE, '/etc/passwd')],
            [('hard', tarfile.LNKTYPE, '../file')],
            [('sym', tarfile.SYMTYPE, 'file'), ('hard', tarfile.LNKTYPE, 'sym')],
            [('node', tarfile.CHRTYPE, '')],
            [('fifo', tarfile.FIFOTYPE, '')],
            [('file', tarfile.REGTYPE, ''), ('./file', tarfile.REGTYPE, '')],
        ]
        for entries in bad_entries:
            with self.subTest(entries=entries):
                self.archive(entries)
                rootfs = self.root / 'never-created'
                with self.assertRaises(RuntimeError):
                    lxc_smoke.extract(self.artifact, rootfs, 300000)
                self.assertFalse(rootfs.exists(), 'Validation must finish before any extraction')

    def test_preserves_guest_symlinks_and_shifts_without_following_them(self):
        self.archive([('.', tarfile.DIRTYPE, ''), ('etc', tarfile.DIRTYPE, ''),
                      ('etc/config', tarfile.REGTYPE, ''), ('alias', tarfile.LNKTYPE, 'etc/config'),
                      ('var/run', tarfile.SYMTYPE, '/run')])
        rootfs = self.root / 'rootfs'
        with patch.object(lxc_smoke.os, 'chown') as chown:
            lxc_smoke.extract(self.artifact, rootfs, 300000)
        self.assertEqual(os.readlink(rootfs / 'var/run'), '/run')
        self.assertEqual((rootfs / 'alias').stat().st_ino, (rootfs / 'etc/config').stat().st_ino)
        for call in chown.call_args_list:
            self.assertFalse(call.kwargs['follow_symlinks'])
        self.assertIn(((rootfs / 'var/run', 300012, 300034), {'follow_symlinks': False}),
                      [(call.args, call.kwargs) for call in chown.call_args_list])

    def test_rejects_archive_ids_outside_mapping(self):
        self.archive([('file', tarfile.REGTYPE, '')])
        with tarfile.open(self.artifact) as archive:
            archive.getmembers()[0].uid = 65536
            with self.assertRaisesRegex(RuntimeError, 'mapped range'):
                lxc_smoke.archive_members(archive)

    def test_id_range_collisions(self):
        cases = [('free', 300000, 1000, '0 0 4294967295\n', True),
                 ('subordinate', 100000, 1000, '0 0 4294967295\n', False),
                 ('account', 300000, 300001, '0 0 4294967295\n', False),
                 ('live-map', 300000, 1000, '0 300000 65536\n', False)]
        for label, base, account, mapping, allowed in cases:
            def read(path, *args, **kwargs):
                return 'fixture:100000:65536\n' if str(path).startswith('/etc/') else mapping
            with self.subTest(case=label), patch.object(Path, 'read_text', read), \
                    patch.object(Path, 'glob', return_value=[Path('/proc/123')]), \
                    patch.object(lxc_smoke.pwd, 'getpwall', return_value=[SimpleNamespace(pw_uid=account)]), \
                    patch.object(lxc_smoke.grp, 'getgrall', return_value=[]):
                if allowed:
                    lxc_smoke.unused_id_range(base)
                else:
                    with self.assertRaises(RuntimeError):
                        lxc_smoke.unused_id_range(base)


class NativeCIContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.site_path = self.root / 'native-site.json'
        self.site_path.write_text('{"fixture":true}')
        self.candidate = self.root / 'candidate.json'
        self.candidate.write_text(json.dumps({'source_commit': 'a' * 40, 'target': 'cloudstack-kvm'}))
        self.site = SimpleNamespace(tool_prefix=self.root, source_commit='a' * 40, site_path=self.site_path)
        self.context_path = self.root / 'ci/evidence/attempt/context.json'
        self.context_path.parent.mkdir(parents=True)
        self.unit = 'zs-golden-smoke-ci-' + 'b' * 24 + '-1.service'
        self.guard = 'zs-golden-guard-ci-' + 'b' * 24 + '.service'
        self.group = '/github.slice/github-runner.slice/' + self.unit
        self.context = {'schema_version': 1, 'candidate': str(self.candidate), 'candidate_sha256': common.digest(self.candidate),
                        'source_commit': self.site.source_commit, 'site_path': str(self.site_path),
                        'site_sha256': common.digest(self.site_path), 'unit': self.unit, 'guard_unit': self.guard,
                        'operation_binding': 'c' * 64}
        self.active = {'Id': self.unit, 'LoadState': 'loaded', 'ActiveState': 'active', 'ControlGroup': self.group,
                       'Slice': 'github-runner.slice', 'BindsTo': self.guard, 'After': self.guard,
                       'PrivateNetwork': 'yes', 'KillMode': 'control-group', 'Delegate': 'no'}
        self.lifetime = {'Id': self.guard, 'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': '123',
                         'Slice': 'github-runner.slice', 'ControlGroup': '/github.slice/github-runner.slice/' + self.guard}

    def check(self, group=None, interfaces=None, shared_ns=False):
        self.context_path.write_text(json.dumps(self.context)); self.context_path.chmod(0o600)
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            return '0::' + (group or self.group) + '\n' if str(path) == '/proc/self/cgroup' else original_read(path, *args, **kwargs)
        def namespace(path):
            return 'namespace:1' if shared_ns or '/1/' in path else 'namespace:2'
        states = [SimpleNamespace(returncode=0, stdout='\n'.join(k + '=' + v for k, v in data.items()))
                  for data in (self.active, self.lifetime)]
        with patch.object(common, 'protected'), patch.object(Path, 'read_text', read), \
             patch.object(common, 'run', side_effect=states), patch.object(common.os, 'readlink', side_effect=namespace), \
             patch.object(common.socket, 'if_nameindex', return_value=interfaces or [(1, 'lo')]):
            common.require_runner_context('unused-manual-service', self.context_path, self.site, self.candidate)

    def test_manual_path_still_requires_drained_runner(self):
        with patch.object(common, 'require_drained') as drained:
            common.require_runner_context('runner.service', None, self.site, self.candidate)
        drained.assert_called_once_with('runner.service')

    def test_exact_owned_isolated_unit_accepts_context_without_github_environment(self):
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'untrusted/other', 'GITHUB_REF': 'refs/pull/1/head'}):
            self.check()

    def test_wrong_context_binding_cannot_authorize_helper(self):
        original = dict(self.context)
        for change in ({'candidate_sha256': 'd' * 64}, {'source_commit': 'd' * 40}, {'site_sha256': 'd' * 64},
                       {'candidate': '/other/candidate.json'}, {'unit': 'other.service'}, {'guard_unit': 'foreign.service'},
                       {'operation_binding': 'not-a-digest'}, {'extra': 'field'}):
            self.context = original | change
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.check()

    def test_foreign_cgroup_or_dead_guard_or_missing_isolation_is_refused(self):
        for kwargs in ({'group': '/system.slice/other.service'}, {'interfaces': [(1, 'lo'), (2, 'eth0')]}, {'shared_ns': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                self.check(**kwargs)
        original = dict(self.active)
        for change in ({'PrivateNetwork': 'no'}, {'BindsTo': ''}, {'After': ''}, {'Slice': 'system.slice'},
                       {'KillMode': 'process'}, {'ControlGroup': '/system.slice/other.service'}):
            self.active = original | change
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.check()
        self.active = original
        self.lifetime['ActiveState'] = 'inactive'
        with self.assertRaisesRegex(RuntimeError, 'guard is inactive'):
            self.check()

    def test_lxc_requires_actual_delegated_cgroup(self):
        self.candidate.write_text(json.dumps({'source_commit': 'a' * 40, 'target': 'proxmox-lxc'}))
        self.context['candidate_sha256'] = common.digest(self.candidate)
        with self.assertRaisesRegex(RuntimeError, 'delegation'):
            self.check()
        self.active['Delegate'] = 'yes'
        self.check()


class NativeGuestTests(unittest.TestCase):
    def test_qga_async_execution_retains_pid_until_exit(self):
        responses = [{'pid': 12}, {'exited': False},
                     {'exited': True, 'exitcode': 0, 'out-data': base64.b64encode(b'ok').decode()}]
        with patch.object(vm_smoke, 'qga', side_effect=responses) as qga, patch.object(vm_smoke.time, 'sleep'):
            self.assertEqual(vm_smoke.guest_exec('/unused', ['/bin/true']), 'ok')
        for call in qga.call_args_list[1:]:
            self.assertEqual(call.args[2], {'pid': 12})

    def test_configdrive_accepts_openstack_cloud_id_but_rejects_wrong_datasource(self):
        with tempfile.TemporaryDirectory() as directory:
            for datasource, status, accepted in [('configdrive', 'done', True),
                                                  ('nocloud', 'done', False),
                                                  ('configdrive', 'running', False)]:
                responses = [SimpleNamespace(stdout=json.dumps({'datasource': datasource, 'status': status})),
                             SimpleNamespace(stdout='openstack\n')]
                with self.subTest(datasource=datasource, status=status), patch.object(vm_smoke, 'run', side_effect=responses):
                    if accepted:
                        self.assertEqual(vm_smoke.cloud_identity([], Path(directory)), ('configdrive', 'openstack'))
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'ConfigDrive did not complete'):
                            vm_smoke.cloud_identity([], Path(directory))

    def test_qga_execution_timeout_is_bounded(self):
        with patch.object(vm_smoke, 'qga', side_effect=[{'pid': 12}, {'exited': False}]), \
                patch.object(vm_smoke.time, 'monotonic', side_effect=[0, 1, 31]), patch.object(vm_smoke.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'Guest command timed out'):
                vm_smoke.guest_exec('/unused', ['/bin/true'])

    def test_qga_rejects_failed_and_truncated_results(self):
        for result in ({'exited': True, 'exitcode': 1}, {'exited': True, 'exitcode': 0, 'out-truncated': True}):
            with self.subTest(result=result), patch.object(vm_smoke, 'qga', side_effect=[{'pid': 12}, result]):
                with self.assertRaisesRegex(RuntimeError, 'failed or output truncated'):
                    vm_smoke.guest_exec('/unused', ['/bin/false'])

    def test_qga_discards_stale_replies_before_accepting_sync(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.makefile.return_value = io.BytesIO(b'stale\n\xff{"return":12}\n\xff{"return":123}\n{"return":{"pid":9}}\n')
        with patch.object(vm_smoke.socket, 'socket', return_value=sock), patch.object(vm_smoke.secrets, 'randbits', return_value=123):
            self.assertEqual(vm_smoke.qga('/unused', 'guest-exec', {'path': '/bin/true'}), {'pid': 9})
        self.assertTrue(sock.sendall.call_args_list[0].args[0].startswith(b'\xff'))
        self.assertEqual(json.loads(sock.sendall.call_args_list[1].args[0])['execute'], 'guest-exec')

    def test_stuck_qemu_is_killed_and_reaped(self):
        process = MagicMock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('qemu', 15), 0]
        vm_smoke.stop_qemu(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)

    def test_clone_failure_stops_its_qemu(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = MagicMock()
            process.poll.return_value = None
            def fake_run(argv, **kwargs):
                if argv[0] == 'ssh-keygen':
                    Path(str(argv[-1]) + '.pub').write_text('ssh-ed25519 fixture')
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            site = SimpleNamespace(project=root, tool_prefix=root)
            with patch.object(vm_smoke, 'run', side_effect=fake_run), \
                    patch.object(vm_smoke.subprocess, 'Popen', return_value=process) as popen, \
                    patch.object(vm_smoke, 'wait_for', side_effect=RuntimeError('guest failed')):
                with self.assertRaisesRegex(RuntimeError, 'guest failed'):
                    vm_smoke.test_clone(root, root / 'candidate.qcow2', 'debian-13', 1, 22280, site)
            process.terminate.assert_called_once()
            process.wait.assert_called_once()
            argv = popen.call_args.args[0]
            self.assertIn('user,id=test,ipv6=off,restrict=on,hostfwd=tcp:127.0.0.1:22280-:22', argv)

    def test_identity_claim_requires_all_selected_fields_unique_or_stable(self):
        first = {'machine_id': '1' * 32, 'host_key': 'key-one', 'instance_id': 'instance-one'}
        second = {'machine_id': '2' * 32, 'host_key': 'key-two', 'instance_id': 'instance-two'}
        common.require_unique(first, second, tuple(first))
        common.require_stable(first, dict(first), tuple(first))
        for field in first:
            with self.subTest(field=field):
                reused = dict(second, **{field: first[field]})
                with self.assertRaisesRegex(RuntimeError, field):
                    common.require_unique(first, reused, tuple(first))
                changed = dict(first, **{field: second[field]})
                with self.assertRaisesRegex(RuntimeError, field):
                    common.require_stable(first, changed, tuple(first))


if __name__ == '__main__':
    unittest.main()
