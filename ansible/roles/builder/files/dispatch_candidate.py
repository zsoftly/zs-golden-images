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
import signal
import stat
import subprocess
import sys
import time


PREFIX = Path('/opt/zs-golden-images')
CONFIG = Path('/etc/zs-golden-images/ci.json')
REQUESTS = Path('/etc/zs-golden-images/ci-requests')
SLICE = 'github-runner.slice'
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
    require(len(argv) == 2, 'Expected exactly profile and target')
    profile, target = argv
    require(profile in PROFILES and target in ('cloudstack-kvm', 'proxmox-lxc'), 'Unknown image profile or target')
    return profile, target


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
    result = subprocess.run(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'ControlGroup',
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


def main(argv):
    request = arguments(argv)
    require(sys.platform == 'linux' and os.geteuid() == 0, 'An approved root invocation mechanism is required')
    parent_death_guard()
    os.umask(0o077)
    with open(os.devnull, 'rb') as empty:
        os.dup2(empty.fileno(), 0)
    os.environ.clear()
    os.environ.update(PATH=str(PREFIX / 'venv/bin') + ':' + str(PREFIX / 'bin') + ':/usr/sbin:/usr/bin:/sbin:/bin',
                      HOME='/root', LANG='C.UTF-8', PYTHONDONTWRITEBYTECODE='1',
                      ANSIBLE_COLLECTIONS_PATH=str(PREFIX / 'collections'))
    profile, target = request
    settings = json.loads(protected(CONFIG).read_text())
    require(set(settings) == {'project', 'state', 'workspace'}, 'Unexpected dispatcher configuration')
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
    approval = json.loads(protected(REQUESTS / (profile + '-' + target + '.json')).read_text())
    site_path = protected(approved_request(approval, request, int(time.time())))
    version, commit = approval['version'], approval['source_commit']
    require(not site_path.is_relative_to(project), 'Site inputs must remain outside public source')
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=15).strip() == commit, 'Installed source differs from approval')
    require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], text=True, timeout=15).strip(), 'Installed source is dirty')
    site = json.loads(site_path.read_text())
    require(site['version'] == version and site['workspace'] == str(workspace), 'Site differs from approved version or workspace')
    sources = source_records(profile, site)
    name = 'ci-' + secrets.token_hex(12)
    candidate = workspace / f'{profile}-{target}-{version}' / 'candidate.json'
    require(not candidate.parent.exists(), 'Image version already exists')
    lock = os.open(state / '.dispatch.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(lock)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe dispatcher lock')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    evidence = protected(state / 'evidence') / ('attempt-' + name)
    evidence.mkdir(mode=0o700)
    guard = 'zs-golden-guard-' + name + '.service'
    probe_unit = 'zs-golden-probe-' + name + '.service'
    units = [guard, probe_unit] + ['zs-golden-' + kind + '-' + name + '.service' for kind in ('resolve', 'fixture', 'dns', 'denied', 'build')]
    units += ['zs-golden-source-' + name + '-' + str(index) + '.service' for index in range(len(sources))]
    require(all(unit_state(unit).get('LoadState') == 'not-found' for unit in units), 'Request unit already exists')
    variables = {'golden_ci_state': str(state), 'golden_ci_project': str(project), 'golden_egress_run_id': name,
                 'golden_build_profile': profile, 'golden_build_target': target, 'golden_build_version': version,
                 'golden_build_site': str(site_path), 'golden_expected_commit': commit, 'golden_probe_sources': sources,
                 'golden_ci_guard_unit': guard, 'golden_ci_lifetime_properties': lifetime_properties(guard)}
    variables_path = evidence / 'probe-inputs.json'
    variables_path.write_text(json.dumps(variables))
    (evidence / 'approved-request.json').write_text(json.dumps(approval))
    try:
        start_guard(guard, evidence / 'dispatcher.pid')
        with (evidence / 'probe.log').open('x') as log:
            subprocess.run(['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=' + probe_unit,
                            '--property=Type=exec', '--property=RuntimeMaxSec=900', *lifetime_properties(guard),
                            '--setenv=ANSIBLE_CONFIG=' + os.environ['ANSIBLE_CONFIG'],
                            '--setenv=ANSIBLE_ROLES_PATH=' + os.environ['ANSIBLE_ROLES_PATH'],
                            '--setenv=ANSIBLE_COLLECTIONS_PATH=' + os.environ['ANSIBLE_COLLECTIONS_PATH'],
                            '--setenv=PYTHONDONTWRITEBYTECODE=1', '--working-directory=' + str(project),
                            '--setenv=PATH=' + os.environ['PATH'], '--setenv=HOME=/root', '--setenv=LANG=C.UTF-8',
                            PREFIX / 'venv/bin/ansible-playbook', '-i', 'localhost,', '-e', '@' + str(variables_path),
                            project / 'ansible/playbooks/21-verify-ci-egress.yml'], stdout=log, stderr=subprocess.STDOUT, timeout=900, check=True)
        probe = json.loads((state / 'evidence' / ('egress-' + name) / 'result.json').read_text())
        require(probe['restricted_loopback'] == 'denied' and probe['unrestricted_loopback'] == 'passed', 'Egress proof incomplete')
        require(0 <= time.time() - probe['provenance']['verified_at'] <= 900, 'Egress proof stale')
        require(probe['provenance']['site_sha256'] == hashlib.sha256(site_path.read_bytes()).hexdigest(), 'Site changed during probe')
        require(probe['provenance']['source_commit'] == commit, 'Source changed during probe')
        with (evidence / 'build.log').open('x') as log:
            result = subprocess.run(probe['build_argv'], stdout=log, stderr=subprocess.STDOUT, timeout=21690)
        require(result.returncode == 2 and candidate.is_file(), 'Build did not produce an experimental candidate')
        manifest = json.loads(protected(candidate).read_text())
        require((manifest['profile'], manifest['target'], manifest['version'], manifest['source_commit']) ==
                (profile, target, version, commit), 'Candidate provenance mismatch')
        with (evidence / 'inspect.log').open('x') as log:
            subprocess.run([PREFIX / 'venv/bin/python', project / 'scripts/release.py', 'inspect', candidate],
                           stdout=log, stderr=subprocess.STDOUT, timeout=180, check=True)
        (evidence / 'result.json').write_text(json.dumps({'status': 'experimental-unaccepted', 'completed': ['build', 'inspect'],
                                                       'candidate': str(candidate), 'source_commit': commit}, indent=2) + '\n')
    except BaseException as error:
        (evidence / 'failure.txt').write_text(type(error).__name__ + ': ' + str(error) + '\n')
        raise
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup(units, parent_group)
        os.close(lock)


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise RuntimeError('Dispatcher interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        main(sys.argv[1:])
    except BaseException:
        print('Candidate request failed; inspect private operator evidence.', file=sys.stderr)
        sys.exit(1)
