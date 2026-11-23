"""Execute workflow shell with a fake privilege boundary; no infrastructure access."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.load((REPO / '.github/workflows/build-candidate.yml').read_text(), Loader=yaml.BaseLoader)
STAGES = ('preflight', 'build', 'inspect', 'smoke')
BINDING = 'a' * 64
DISPATCHER = '/opt/zs-golden-images/bin/dispatch-candidate'


class WorkflowBoundary(unittest.TestCase):
    def execute_stage(self, stage, *, binding=BINDING, expected=BINDING, code=0, profile='debian-13', target='cloudstack-kvm'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / 'sudo'
            fake.write_text('#!' + sys.executable + '\n' +
                            'import json,os,pathlib,sys\n' +
                            'pathlib.Path(os.environ["CALL_LOG"]).write_text(json.dumps(sys.argv[1:]))\n' +
                            'sys.stdout.write(os.environ["FAKE_BINDING"])\n' +
                            'sys.stderr.write("PRIVATE-DISPATCHER-DETAILS")\n' +
                            'sys.exit(int(os.environ["FAKE_EXIT"]))\n')
            fake.chmod(0o755)
            output = root / 'output'
            log = root / 'call'
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                               IMAGE_PROFILE=profile, IMAGE_TARGET=target, EXPECTED_BINDING=expected,
                               FAKE_BINDING=binding, FAKE_EXIT=str(code), CALL_LOG=str(log), GITHUB_OUTPUT=str(output))
            result = subprocess.run(['bash', '-c', WORKFLOW['jobs'][stage]['steps'][0]['run']], env=environment,
                                    capture_output=True, text=True, timeout=10, cwd=root)
            return result, output.read_text() if output.exists() else '', json.loads(log.read_text()) if log.exists() else None

    def test_manual_only_fixed_host_and_serial_run_contract(self):
        self.assertEqual(set(WORKFLOW['on']), {'workflow_dispatch'})
        inputs = WORKFLOW['on']['workflow_dispatch']['inputs']
        self.assertEqual(set(inputs), {'profile', 'target'})
        self.assertEqual(inputs['profile']['options'], ['debian-13', 'ubuntu-26.04'])
        self.assertEqual(inputs['target']['options'], ['cloudstack-kvm', 'proxmox-kvm', 'proxmox-lxc'])
        self.assertEqual(WORKFLOW['permissions'], {'contents': 'read'})
        self.assertEqual(WORKFLOW['concurrency'], {'group': 'golden-image-candidate-${{ inputs.profile }}-${{ inputs.target }}', 'cancel-in-progress': 'false'})
        self.assertEqual(set(WORKFLOW['jobs']), {*STAGES, 'summary'})
        for job in WORKFLOW['jobs'].values():
            self.assertIn("github.ref == 'refs/heads/main'", job['if'])
            self.assertIn("github.repository == 'zsoftly/zs-golden-images'", job['if'])
            self.assertEqual(job['runs-on'], ['self-hosted', 'Linux', 'zsoftly-image-build', 'zsoftly-yow-comp-14'])
            self.assertGreater(int(job['timeout-minutes']), 0)
            self.assertLessEqual(int(job['timeout-minutes']), 390)
            for step in job['steps']:
                self.assertNotIn('uses', step)
                self.assertNotIn('${{', step['run'])
                for forbidden in ('checkout', 'upload-artifact', 'git clone', './scripts/', 'GITHUB_WORKSPACE'):
                    self.assertNotIn(forbidden, step['run'])
                check = subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True)
                self.assertEqual(check.returncode, 0, check.stderr)

    def test_each_stage_requires_its_predecessors_and_exports_only_binding(self):
        self.assertNotIn('needs', WORKFLOW['jobs']['preflight'])
        for index, stage in enumerate(STAGES):
            job = WORKFLOW['jobs'][stage]
            self.assertEqual(job['outputs'], {'binding': '${{ steps.stage.outputs.binding }}'})
            self.assertNotIn('always()', job['if'])
            env = job['steps'][0]['env']
            self.assertEqual(env['IMAGE_PROFILE'], '${{ inputs.profile }}')
            self.assertEqual(env['IMAGE_TARGET'], '${{ inputs.target }}')
            if index:
                self.assertEqual(job['needs'], list(STAGES[:index]))
                self.assertEqual(env['EXPECTED_BINDING'], '${{ needs.preflight.outputs.binding }}')
        summary = WORKFLOW['jobs']['summary']
        self.assertEqual(summary['needs'], list(STAGES))
        self.assertIn('always()', summary['if'])

    def test_all_stage_pair_commands_use_literal_stage_and_quoted_inputs(self):
        for stage in STAGES:
            for profile in ('debian-13', 'ubuntu-26.04'):
                for target in ('cloudstack-kvm', 'proxmox-kvm', 'proxmox-lxc'):
                    with self.subTest(stage=stage, profile=profile, target=target):
                        result, output, call = self.execute_stage(stage, profile=profile, target=target)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(output, 'binding=' + BINDING + '\n')
                        self.assertEqual(call, ['-n', '--', DISPATCHER, stage, profile, target])
                        self.assertNotIn(BINDING, result.stdout + result.stderr)
                        self.assertNotIn('PRIVATE-', result.stdout + result.stderr)

    def test_failure_and_malformed_output_never_export_or_print_private_data(self):
        for stage in STAGES:
            for binding, code in ((BINDING, 1), ('PRIVATE-DETAILS', 1), ('PRIVATE-DETAILS', 0),
                                  (BINDING + '\nPRIVATE-DETAILS', 0), ('', 0), ('A' * 64, 0)):
                with self.subTest(stage=stage, binding=binding, code=code):
                    result, output, _ = self.execute_stage(stage, binding=binding, code=code)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(output, '')
                    self.assertNotIn('PRIVATE-', result.stdout + result.stderr)

    def test_missing_preflight_binding_rejects_before_privileged_invocation(self):
        for stage in STAGES[1:]:
            result, output, call = self.execute_stage(stage, expected='')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output, '')
            self.assertIsNone(call)

    def test_changed_approval_binding_fails_chain_after_authorized_stage(self):
        for stage in STAGES[1:]:
            result, output, call = self.execute_stage(stage, binding='b' * 64)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output, '')
            self.assertIsNotNone(call)
            self.assertIn('changed between stages', result.stdout)

    def test_shell_metacharacters_in_selected_inputs_are_passed_as_single_arguments(self):
        profile = '$(touch injected); echo PRIVATE-INPUT'
        target = 'target with spaces; false'
        result, _, call = self.execute_stage('preflight', profile=profile, target=target)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(call[-2:], [profile, target])
        self.assertNotIn('PRIVATE-INPUT', result.stdout + result.stderr)
        # The fake boundary accepts these values; actual dispatcher rejects them in its own tests.

    def test_summary_sanitizes_results_and_never_claims_release_acceptance(self):
        script = WORKFLOW['jobs']['summary']['steps'][0]['run']
        for statuses, passed in ((['success'] * 4, True), (['success', 'failure', 'skipped', 'skipped'], False),
                                 (['cancelled'] * 4, False), (['$(echo PRIVATE-DETAILS)'] * 4, False)):
            with self.subTest(statuses=statuses), tempfile.TemporaryDirectory() as directory:
                summary = Path(directory) / 'summary'
                env = dict(os.environ, GITHUB_STEP_SUMMARY=str(summary), **{stage.upper()+'_RESULT': result for stage, result in zip(STAGES, statuses)})
                result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                text = summary.read_text()
                self.assertNotIn('PRIVATE-', text)
                self.assertEqual('Native-tested candidate.' in text, passed)
                if passed:
                    self.assertIn('release acceptance remain outstanding', text)
                else:
                    self.assertIn('pipeline incomplete', text)


if __name__ == '__main__':
    unittest.main()
