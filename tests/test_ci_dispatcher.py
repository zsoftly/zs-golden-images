"""Exercise CI input and approval boundaries without privilege or image builds."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
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

    def test_only_four_exact_argument_pairs_are_accepted(self):
        for profile in ('debian-13', 'ubuntu-26.04'):
            for target in ('cloudstack-kvm', 'proxmox-lxc'):
                self.assertEqual(DISPATCH.arguments([profile, target]), (profile, target))
        for args in ([], [*self.request, 'extra'], ['debian-13;id', 'cloudstack-kvm'], ['../../etc', 'proxmox-lxc']):
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

    def test_workflow_has_no_checkout_upload_or_pull_request_execution(self):
        # BaseLoader retains YAML's 'on' key rather than interpreting it as bool.
        workflow = yaml.load((REPO / '.github/workflows/build-candidate.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow['on']), {'workflow_dispatch'})
        self.assertEqual(set(workflow['on']['workflow_dispatch']['inputs']), {'profile', 'target'})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        job = workflow['jobs']['build']
        self.assertIn("github.ref == 'refs/heads/main'", job['if'])
        self.assertIn("github.repository == 'zsoftly/zs-golden-images'", job['if'])
        self.assertEqual(job['runs-on'], ['self-hosted', 'Linux', 'zsoftly-image-build', 'zsoftly-yow-comp-14'])
        self.assertTrue(all('uses' not in step for step in job['steps']))
        script = job['steps'][0]['run']
        self.assertIn('>/dev/null 2>&1', script)
        self.assertNotIn('${{', script)
        self.assertNotIn('GITHUB_', script)
        result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
