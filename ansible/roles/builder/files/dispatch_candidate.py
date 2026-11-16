#!/usr/bin/python3 -I
"""Guarded root entry point for an approved experimental image build only."""
import fcntl
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time


PREFIX = Path('/opt/zs-golden-images')
CONFIG = Path('/etc/zs-golden-images/ci.json')
REQUESTS = Path('/etc/zs-golden-images/ci-requests')
SLICE = 'github-runner.slice'
STAGES = ('preflight', 'build', 'inspect', 'smoke')
PROFILES = {'debian-13': ('trixie', 'snapshot.debian.org'), 'ubuntu-26.04': ('resolute', 'snapshot.ubuntu.com')}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def protected(path):
    require(path.is_absolute(), 'Absolute protected path required')
    for part in (path, *path.parents):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Unprotected builder path')
    return path


def protected_tree(root):
    protected(root)
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            info = path.lstat()
            require(info.st_uid == 0, 'Toolchain contains a non-root-owned entry')
            if stat.S_ISLNK(info.st_mode):
                protected(path.resolve(strict=True))
            else:
                require(not info.st_mode & 0o022 and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                        'Toolchain contains an unsafe entry')


def arguments(argv):
    require(len(argv) == 3, 'Expected exactly stage, profile and target')
    stage, profile, target = argv
    require(stage in STAGES, 'Unknown candidate stage')
    require(profile in PROFILES and target in ('cloudstack-kvm', 'proxmox-lxc'), 'Unknown image profile or target')
    return stage, profile, target


def approved_request(record, request, now):
    profile, target = request
    require(set(record) == {'profile', 'target', 'version', 'source_commit', 'site_path', 'expires_at'}, 'Unexpected approval fields')
    require((record['profile'], record['target']) == (profile, target), 'Request differs from operator approval')
    require(isinstance(record['version'], str) and re.fullmatch(r'[0-9]{8}(-[a-z0-9][a-z0-9.-]{0,39})?', record['version']), 'Invalid approved version')
    require(isinstance(record['source_commit'], str) and re.fullmatch(r'[0-9a-f]{40}', record['source_commit']), 'Invalid approved source commit')
    require(type(record['expires_at']) is int and now < record['expires_at'], 'Operator approval expired')
    require(isinstance(record['site_path'], str) and record['site_path'].startswith('/'), 'Invalid approved site path')
    return Path(record['site_path'])


def source_records(profile, site):
    release, host = PROFILES[profile]
    records = []
    for suite in ('base', 'updates', 'security'):
        mirror = site['security_mirror_url'] if suite == 'security' else site['mirror_url']
        require(re.fullmatch(r'https://' + re.escape(host) + r'/[A-Za-z0-9_./+-]+', mirror), 'Only reviewed official snapshots are supported')
        suffix = '' if suite == 'base' else '-' + suite
        records.append({'profile': profile, 'url': f'{mirror}/dists/{release}{suffix}/InRelease',
                        'sha256': site['inrelease_sha256'][suite]})
    return records


def unit_state(unit):
    result = subprocess.run(['systemctl', 'show', unit, '-p', 'Id', '-p', 'LoadState', '-p', 'ActiveState', '-p', 'ControlGroup',
                             '-p', 'MainPID', '-p', 'MemoryHigh', '-p', 'MemoryMax', '-p', 'MemorySwapMax'],
                            capture_output=True, text=True, timeout=15)
    require(result.returncode in (0, 1, 4), 'Cannot read owned unit state')
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def fleet_slice():
    data = unit_state(SLICE)
    require(data.get('LoadState') == 'loaded' and data.get('ActiveState') == 'active', 'Approved fleet slice unavailable')
    for key, gib in (('MemoryHigh', 24), ('MemoryMax', 26), ('MemorySwapMax', 2)):
        require(data.get(key) == str(gib * 1024 ** 3), 'Fleet budget changed; operator review required')
    group = data.get('ControlGroup', '')
    require(group == '/github.slice/github-runner.slice', 'Unexpected fleet control group')
    return group


def parent_death_guard():
    parent = os.getppid()
    require(parent > 1, 'Dispatcher is already orphaned')
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(1, signal.SIGTERM, 0, 0, 0) == 0, 'Cannot bind dispatcher lifetime to its parent')
    require(os.getppid() == parent, 'Dispatcher parent changed during setup')


def start_guard(unit, pidfile):
    pidfile.write_text(str(os.getpid()) + '\n')
    subprocess.run(['systemd-run', '--quiet', '--collect', '--unit=' + unit, '--property=Type=exec',
                    '--property=Slice=' + SLICE, '--property=Restart=no', '--property=RuntimeMaxSec=23000',
                    '--property=StartLimitIntervalSec=infinity', '--property=StartLimitBurst=1',
                    '--property=TimeoutStopSec=15', '--property=KillMode=control-group',
                    '/usr/bin/pidwait', '-F', pidfile], check=True, timeout=30)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        state = unit_state(unit)
        require(state.get('ActiveState') == 'active', 'Lifetime guard exited before work started')
        pid = int(state.get('MainPID', '0'))
        require(pid > 1, 'Lifetime guard PID unavailable')
        for path in Path(f'/proc/{pid}/fdinfo').glob('*'):
            try:
                data = path.read_text()
            except FileNotFoundError:
                continue
            if re.search(r'^Pid:\s+' + str(os.getpid()) + r'$', data, re.MULTILINE):
                return
        time.sleep(0.05)
    raise ValueError('Lifetime guard did not acquire the dispatcher pidfd')


def lifetime_properties(guard):
    return ['--property=Slice=' + SLICE, '--property=BindsTo=' + guard, '--property=After=' + guard,
            '--property=KillMode=control-group', '--property=TimeoutStopSec=15']


def cleanup(units, parent_group):
    for unit in units:
        before = unit_state(unit)
        if before.get('LoadState') != 'not-found':
            subprocess.run(['systemctl', 'stop', unit], check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        after = unit_state(unit)
        require(after.get('LoadState') == 'not-found' or after.get('ActiveState') in ('inactive', 'failed'), 'Owned unit did not stop')
        for group in {before.get('ControlGroup'), after.get('ControlGroup'), parent_group + '/' + unit} - {None, ''}:
            events = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
            if events.exists():
                require('populated 0' in events.read_text().splitlines(), 'Owned cgroup remains populated')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def operation_identity(approval, site_bytes):
    identity = {key: approval[key] for key in ('profile', 'target', 'version', 'source_commit', 'site_path')}
    identity['site_sha256'] = hashlib.sha256(site_bytes).hexdigest()
    return identity, hashlib.sha256(canonical(identity)).hexdigest()


def write_new(path, data):
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8) + '.tmp')
    try:
        with temporary.open('x') as stream:
            stream.write(json.dumps(data, indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # Atomic publication; never replace an existing receipt.
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def candidate_binding(candidate, identity, workspace):
    protected(candidate)
    data = json.loads(candidate.read_text())
    require(data.get('schema_version') == 1 and all(data.get(key) == identity[key]
            for key in ('profile', 'target', 'version', 'source_commit')), 'Candidate provenance mismatch')
    artifact = candidate.parent / data['artifact']['path']
    require(artifact.is_absolute() and artifact.resolve() == artifact and artifact.is_relative_to(candidate.parent) and
            candidate.parent.is_relative_to(workspace), 'Candidate artifact escaped its workspace')
    protected(artifact)
    require(artifact.is_file() and artifact.stat().st_size > 0 and digest(artifact) == data['artifact']['sha256'], 'Candidate artifact changed')
    return {'candidate': str(candidate), 'candidate_sha256': digest(candidate),
            'artifact': str(artifact), 'artifact_sha256': digest(artifact)}


def check_receipts(operation, stage, binding, current_candidate):
    """Only finalized receipts count; partial attempts never become prerequisites."""
    prior = None
    current = None
    for name in STAGES[:STAGES.index(stage) + 1]:
        path = operation / (name + '.json')
        if not path.exists():
            require(name == stage, 'Previous stage has no finalized successful receipt')
            return None
        protected(path)
        receipt = json.loads(path.read_text())
        require(receipt.get('status') == 'passed' and receipt.get('stage') == name and receipt.get('binding') == binding and
                receipt.get('operation_sha256') == digest(operation / 'identity.json') and
                receipt.get('previous_receipt_sha256') == prior, 'Stage receipt identity/order mismatch')
        require(isinstance(receipt.get('evidence'), list) and receipt['evidence'], 'Stage receipt has no evidence')
        require(receipt.get('candidate') == (None if name == 'preflight' else current_candidate), 'Stage candidate binding changed')
        for item in receipt['evidence']:
            file = protected(Path(item['path']))
            require(file.is_file() and digest(file) == item['sha256'], 'Stage evidence changed')
        prior = digest(path)
        current = receipt
    return current


def finalize_receipt(operation, stage, binding, candidate, evidence):
    previous = STAGES.index(stage) - 1
    receipt = {'schema_version': 1, 'status': 'passed', 'stage': stage, 'binding': binding,
               'operation_sha256': digest(operation / 'identity.json'),
               'previous_receipt_sha256': digest(operation / (STAGES[previous] + '.json')) if previous >= 0 else None,
               'candidate': candidate, 'completed_at': int(time.time()),
               'evidence': [{'path': str(path), 'sha256': digest(path)} for path in evidence]}
    write_new(operation / (stage + '.json'), receipt)


def unit_command(unit, guard, project, argv, timeout, *, private=False, delegate=False, environment=None):
    options = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=' + unit,
               '--property=Type=exec', '--property=RuntimeMaxSec=' + str(timeout),
               '--property=MemoryHigh=6G', '--property=MemoryMax=8G', '--property=MemorySwapMax=0',
               '--property=CPUQuota=300%', *lifetime_properties(guard), '--working-directory=' + str(project)]
    if private:
        options += ['--property=PrivateNetwork=yes', '--property=PrivateMounts=yes']
    if delegate:
        options += ['--property=Delegate=yes']
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'LANG', 'PYTHONDONTWRITEBYTECODE',
                                          'ANSIBLE_CONFIG', 'ANSIBLE_ROLES_PATH', 'ANSIBLE_COLLECTIONS_PATH')}
    env.update(environment or {})
    options += ['--setenv=' + key + '=' + value for key, value in env.items()]
    return [*options, *argv]


def logged(argv, log, timeout, expected=0):
    with log.open('x') as stream:
        result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    require(result.returncode == expected, 'Stage command failed; inspect private log')


def build_stage(project, state, evidence, name, guard, approval, sources, candidate):
    require(not candidate.parent.exists(), 'Version workspace already exists; approve a new version')
    variables = {'golden_ci_state': str(state), 'golden_ci_project': str(project), 'golden_egress_run_id': name,
                 'golden_build_profile': approval['profile'], 'golden_build_target': approval['target'],
                 'golden_build_version': approval['version'], 'golden_build_site': approval['site_path'],
                 'golden_expected_commit': approval['source_commit'], 'golden_probe_sources': sources,
                 'golden_ci_guard_unit': guard, 'golden_ci_lifetime_properties': lifetime_properties(guard)}
    variables_path = evidence / 'probe-inputs.json'
    write_new(variables_path, variables)
    logged(unit_command('zs-golden-probe-' + name + '.service', guard, project,
           [PREFIX / 'venv/bin/ansible-playbook', '-i', 'localhost,', '-e', '@' + str(variables_path),
            project / 'ansible/playbooks/21-verify-ci-egress.yml'], 900), evidence / 'probe.log', 930)
    result_path = protected(state / 'evidence' / ('egress-' + name) / 'result.json')
    probe = json.loads(result_path.read_text())
    require(probe['restricted_loopback'] == 'denied' and probe['unrestricted_loopback'] == 'passed', 'Egress proof incomplete')
    require(0 <= time.time() - probe['provenance']['verified_at'] <= 900, 'Egress proof stale')
    require(probe['provenance']['site_sha256'] == digest(Path(approval['site_path'])) and
            probe['provenance']['source_commit'] == approval['source_commit'], 'Egress input identity changed')
    argv = probe['build_argv']
    require('--unit=zs-golden-build-' + name in argv and all(prop in argv for prop in lifetime_properties(guard)),
            'Build command lacks this attempt lifetime binding')
    logged(argv, evidence / 'build.log', 21690, expected=2)
    require(candidate.is_file(), 'Build did not produce an experimental candidate')
    return [evidence / 'build.log', result_path]


def smoke_stage(project, evidence, name, guard, binding, approval, candidate, bound, native, settings, native_module):
    reports = []
    target = approval['target']
    for number in ((1,) if target == 'cloudstack-kvm' else (1, 2)):
        unit = 'zs-golden-smoke-' + name + '-' + str(number) + '.service'
        output = native.evidence / (name + '-smoke-' + str(number))
        context = evidence / ('native-context-' + str(number) + '.json')
        write_new(context, {'schema_version': 1, 'candidate': str(candidate), 'candidate_sha256': bound['candidate_sha256'],
                           'source_commit': approval['source_commit'], 'site_path': settings['native_site'],
                           'site_sha256': digest(Path(settings['native_site'])), 'unit': unit,
                           'guard_unit': guard, 'operation_binding': binding})
        helper = project / 'tests/native' / ('vm_smoke.py' if target == 'cloudstack-kvm' else 'lxc_smoke.py')
        argv = ['/usr/bin/unshare', '--mount', '--propagation', 'private', '--fork',
                PREFIX / 'venv/bin/python', helper, '--site', settings['native_site'], '--ci-context', context, candidate, output]
        if target == 'proxmox-lxc':
            argv += ['--id-base', str(settings['lxc_id_base'])]
            if reports:
                argv += ['--compare-report', reports[0]]
        logged(unit_command(unit, guard, project, argv, 3600, private=True, delegate=target == 'proxmox-lxc', environment={'GOLDEN_APPLY': 'smoke'}),
               evidence / ('smoke-' + str(number) + '.log'), 3630)
        path = protected(output / 'smoke-report.json')
        report = json.loads(path.read_text())
        require(report.get('status') == 'passed' and report.get('original_artifact_unchanged') is True and
                report.get('candidate_sha256') == bound['candidate_sha256'] and report.get('artifact_sha256') == bound['artifact_sha256'] and
                report.get('test_source_commit') == approval['source_commit'], 'Native report binding or result mismatch')
        if target == 'cloudstack-kvm':
            require(report.get('scope') == 'native-kvm-smoke-only' and report.get('clone_uniqueness') == 'passed' and
                    len(report.get('clones', [])) == 2 and report['clones'][0].get('reboot_persistence') == 'passed', 'Incomplete two-clone KVM smoke')
        else:
            require(report.get('scope') == 'native-lxc-one-clone-smoke-only' and report.get('container_stopped') is True and
                    report.get('restart_persistence') == 'passed' and report.get('host_id_base') == settings['lxc_id_base'], 'Incomplete LXC smoke')
            if reports:
                require(report.get('clone_uniqueness') == 'passed' and report.get('previous_report_sha256') == digest(reports[0]), 'Second LXC clone is not bound to the first')
                native_module.require_unique(json.loads(reports[0].read_text())['identity'], report['identity'], ('machine_id', 'host_key', 'hostname'))
        reports.append(path)
    return reports


def main(argv):
    stage, profile, target = arguments(argv)
    request = (profile, target)
    require(sys.platform == 'linux' and os.geteuid() == 0, 'An approved root invocation mechanism is required')
    parent_death_guard()
    os.umask(0o077)
    with open(os.devnull, 'rb') as empty:
        os.dup2(empty.fileno(), 0)
    os.environ.clear()
    os.environ.update(PATH=str(PREFIX / 'venv/bin') + ':' + str(PREFIX / 'bin') + ':/usr/sbin:/usr/bin:/sbin:/bin',
                      HOME='/root', LANG='C.UTF-8', PYTHONDONTWRITEBYTECODE='1',
                      ANSIBLE_COLLECTIONS_PATH=str(PREFIX / 'collections'))
    settings = json.loads(protected(CONFIG).read_text())
    require(set(settings) == {'project', 'state', 'workspace', 'native_site', 'lxc_id_base', 'min_free_bytes'}, 'Unexpected dispatcher configuration')
    require(type(settings['min_free_bytes']) is int and settings['min_free_bytes'] > 0 and
            type(settings['lxc_id_base']) is int and 65536 <= settings['lxc_id_base'] <= 4294967295 - 65536, 'Missing capacity/ID policy')
    project, state, workspace = (protected(Path(settings[key])) for key in ('project', 'state', 'workspace'))
    require(project == PREFIX / 'project' and state == PREFIX / 'ci', 'Unexpected protected installation')
    os.environ['ANSIBLE_CONFIG'] = str(protected(state / 'ansible.cfg'))
    for path in (project, PREFIX / 'venv', PREFIX / 'collections', PREFIX / 'bin'):
        protected_tree(path)
    for path in ('/usr/sbin', '/usr/bin', '/sbin', '/bin', '/root'):
        protected(Path(path).resolve(strict=True))
    os.chdir(project)
    os.environ['ANSIBLE_ROLES_PATH'] = str(project / 'ansible/roles')
    parent_group = fleet_slice()
    approval_path = protected(REQUESTS / (profile + '-' + target + '.json'))
    approval = json.loads(approval_path.read_text())
    site_path = protected(approved_request(approval, request, int(time.time())))
    require(not site_path.is_relative_to(project), 'Site inputs must remain outside public source')
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=15).strip() == approval['source_commit'], 'Installed source differs from approval')
    require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], text=True, timeout=15).strip(), 'Installed source is dirty')
    site_bytes = site_path.read_bytes()
    site = json.loads(site_bytes)
    require(site['version'] == approval['version'] and site['workspace'] == str(workspace), 'Site differs from approved version or workspace')
    sources = source_records(profile, site)
    # Reuse the protected native site and ID validators, never job-workspace imports.
    sys.path.insert(0, str(project / 'tests/native'))
    import common as native_module
    import lxc_smoke
    sys.path.pop(0)
    native = native_module.load_site(Path(settings['native_site']))
    require(native.workspace == workspace and native.project == project and native.tool_prefix == PREFIX and
            native.source_commit == approval['source_commit'], 'Native site differs from approved installation')
    runner = unit_state(native.runner_service)
    require(runner.get('Id') == native.runner_service and runner.get('LoadState') == 'loaded' and
            runner.get('ActiveState') == 'active', 'Exact CI runner listener is not active')
    require(not Path('/etc/pve').exists(), 'CI builds must not run on a Proxmox host')
    require(shutil.disk_usage(workspace).free >= settings['min_free_bytes'], 'Configured free disk floor not met')
    tools = ['systemd-run', 'pidwait', 'unshare', 'ssh', 'ssh-keygen', 'qemu-img']
    tools += ['lxc-start', 'lxc-stop', 'lxc-info', 'lxc-attach', 'nsenter', 'ip', 'mount', 'umount'] if target == 'proxmox-lxc' else ['qemu-system-x86_64', 'xorriso']
    for tool in tools:
        found = shutil.which(tool)
        require(found is not None, 'Required native tool missing')
        protected(Path(found).resolve(strict=True))
    build_lock = os.open(workspace / '.build.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        lock_info = os.fstat(build_lock)
        require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == 0 and not lock_info.st_mode & 0o022, 'Unsafe build lock')
        fcntl.flock(build_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(build_lock)  # Helpers and pipeline acquire this lock themselves.
    if target == 'proxmox-lxc':
        lxc_smoke.unused_id_range(settings['lxc_id_base'])
        require(shutil.which('newuidmap') is None and shutil.which('newgidmap') is None, 'Review LXC mapping helpers before CI smoke')
    else:
        require(Path('/dev/kvm').is_char_device(), 'KVM device missing')
    identity, binding = operation_identity(approval, site_bytes)
    operation_record = {'identity': identity, 'binding': binding, 'configuration_sha256': digest(CONFIG),
                        'native_site_sha256': digest(native.site_path),
                        'toolchain_sha256': digest(protected(Path('/etc/zs-golden-images/toolchain.json')))}
    lock = os.open(state / '.dispatch.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, 'rb'):
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe dispatcher lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        operation = protected(state / 'operations') / binding
        if not operation.exists():
            require(stage == 'preflight', 'Preflight must establish the operation first')
            operation.mkdir(mode=0o700)
            write_new(operation / 'identity.json', operation_record)
        require(json.loads(protected(operation / 'identity.json').read_text()) == operation_record, 'Operation policy changed; approve a new version')
        candidate = workspace / f'{profile}-{target}-{approval["version"]}' / 'candidate.json'
        bound = None
        if (operation / 'build.json').exists():
            bound = candidate_binding(candidate, identity, workspace)
            check_receipts(operation, 'build', binding, bound)
        elif candidate.parent.exists():
            raise ValueError('Unfinalized version workspace exists; approve a new version')
        reused = check_receipts(operation, stage, binding, bound)
        name = 'ci-' + secrets.token_hex(12)
        evidence = protected(state / 'evidence') / ('attempt-' + name)
        evidence.mkdir(mode=0o700)
        guard = 'zs-golden-guard-' + name + '.service'
        units = [guard] + ['zs-golden-' + kind + '-' + name + '.service' for kind in ('probe', 'resolve', 'fixture', 'dns', 'denied', 'build', 'check', 'validate', 'inspect')]
        units += ['zs-golden-source-' + name + '-' + str(index) + '.service' for index in range(len(sources))]
        units += ['zs-golden-smoke-' + name + '-' + str(number) + '.service' for number in (1, 2)]
        require(all(unit_state(unit).get('LoadState') == 'not-found' for unit in units), 'Request unit already exists')
        write_new(evidence / 'approved-request.json', approval)
        results = []
        try:
            start_guard(guard, evidence / 'dispatcher.pid')
            logged(unit_command('zs-golden-check-' + name + '.service', guard, project,
                   [PREFIX / 'venv/bin/python', project / 'scripts/verify-toolchain.py', project / 'builders/pins.json',
                    project / 'ansible/requirements-builder.lock', project / 'ansible/roles/builder/files'], 300, private=True),
                   evidence / 'toolchain.log', 330)
            logged(unit_command('zs-golden-validate-' + name + '.service', guard, project,
                   [project / 'scripts/pipeline.sh', 'validate', profile, target, site_path], 60, private=True),
                   evidence / 'validate.log', 90)
            results = [evidence / 'toolchain.log', evidence / 'validate.log']
            if reused is None:
                if stage == 'build':
                    results += build_stage(project, state, evidence, name, guard, approval, sources, candidate)
                    bound = candidate_binding(candidate, identity, workspace)
                elif stage == 'inspect':
                    logged(unit_command('zs-golden-inspect-' + name + '.service', guard, project,
                           [PREFIX / 'venv/bin/python', project / 'scripts/release.py', 'inspect', candidate], 300, private=True),
                           evidence / 'inspect.log', 330)
                    results += [evidence / 'inspect.log']
                elif stage == 'smoke':
                    results += smoke_stage(project, evidence, name, guard, binding, approval, candidate, bound, native, settings, native_module)
            write_new(evidence / 'result.json', {'stage': stage, 'binding': binding, 'status': 'pending-cleanup', 'reused': reused is not None})
        except BaseException as error:
            (evidence / 'failure.txt').write_text(type(error).__name__ + ': ' + str(error) + '\n')
            raise
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                cleanup(units, parent_group)
            except BaseException as error:
                (evidence / 'cleanup-failure.txt').write_text(type(error).__name__ + ': ' + str(error) + '\n')
                raise
        # Recheck the current authority after cleanup, including renewals of the same identity.
        renewed = json.loads(protected(approval_path).read_text())
        approved_request(renewed, request, int(time.time()))
        require(operation_identity(renewed, protected(Path(renewed['site_path'])).read_bytes())[1] == binding,
                'Approval changed during stage')
        require(digest(CONFIG) == operation_record['configuration_sha256'] and
                digest(native.site_path) == operation_record['native_site_sha256'] and
                digest(Path('/etc/zs-golden-images/toolchain.json')) == operation_record['toolchain_sha256'], 'Operator policy changed during stage')
        if bound is not None:
            require(candidate_binding(candidate, identity, workspace) == bound, 'Candidate changed during stage')
        if reused is None:
            finalize_receipt(operation, stage, binding, None if stage == 'preflight' else bound, results)
        write_new(evidence / 'finalized.json', {'stage': stage, 'binding': binding, 'status': 'passed', 'reused': reused is not None})
        return binding


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise RuntimeError('Dispatcher interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        print(main(sys.argv[1:]))
    except BaseException:
        print('Candidate request failed; inspect private operator evidence.', file=sys.stderr)
        sys.exit(1)
