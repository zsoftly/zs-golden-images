"""Shared guards for explicitly authorized native candidate smoke tests."""
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import time
from types import SimpleNamespace

USER = 'goldencheck'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def protected(path):
    for entry in (path, *path.parents):
        info = entry.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Unprotected or redirected path: ' + str(entry))


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def run(argv, *, timeout=60, check=True, env=None, log=None):
    result = subprocess.run([str(arg) for arg in argv], capture_output=True, text=True,
                            timeout=timeout, env=env)
    if log:
        log.write_text(result.stdout + result.stderr)
    if check:
        require(result.returncode == 0, 'Command failed: ' + str(argv[0]) +
                '; see ' + str(log or 'captured process output') + ': ' + result.stderr[-1500:])
    return result


def wait_for(proc, callback, timeout=300):
    deadline = time.monotonic() + timeout
    last = ''
    while time.monotonic() < deadline:
        require(proc.poll() is None, 'Guest process exited; inspect the private runtime and console logs')
        try:
            return callback()
        except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            last = str(error)
            time.sleep(2)
    raise RuntimeError('Guest readiness timed out: ' + last)


def child_guard(parent_pid):
    def guard():
        if ctypes.CDLL(None).prctl(1, signal.SIGTERM) != 0 or os.getppid() != parent_pid:
            os._exit(1)
    return guard


def load_site(path):
    """Read private deployment inputs and bind workspace use to its builder marker."""
    project = Path(__file__).resolve().parents[2]
    require(path.is_absolute() and path.resolve() == path and not path.is_relative_to(project),
            'Keep canonical private site inputs outside the checkout')
    protected(path)
    require(path.is_file() and not path.stat().st_mode & 0o077, 'Site inputs must be a private regular file')
    data = json.loads(path.read_text())
    path_keys = {'workspace', 'evidence', 'tool_prefix', 'builder_marker'}
    require(isinstance(data, dict) and set(data) == path_keys | {'runner_service'}, 'Unexpected native smoke site keys')
    require(isinstance(data['runner_service'], str) and
            re.fullmatch(r'actions\.runner\.[A-Za-z0-9_.@-]+\.service', data['runner_service']),
            'Name the exact existing runner service in private site inputs')
    paths = {}
    for key in path_keys:
        require(isinstance(data[key], str), 'Site paths must be strings')
        value = Path(data[key])
        require(value.is_absolute() and value.resolve() == value and not value.is_relative_to(project) and
                re.fullmatch(r'[A-Za-z0-9/_.-]+', str(value)),
                'Site paths must be canonical absolute paths without option separators outside the checkout')
        protected(value)
        require(value.is_file() if key == 'builder_marker' else value.is_dir(), 'Missing site path: ' + key)
        paths[key] = value
    marker = json.loads(paths['builder_marker'].read_text())
    require(marker.get('purpose') == 'isolated-image-builder' and marker.get('region') == 'yow' and
            marker.get('workspace') == str(paths['workspace']), 'Dedicated builder marker does not match the workspace')
    protected(project)
    require(not run(['git', '-C', project, 'status', '--porcelain', '--untracked-files=all']).stdout.strip(),
            'Native smoke requires a clean committed checkout')
    source_commit = run(['git', '-C', project, 'rev-parse', 'HEAD']).stdout.strip()
    require(re.fullmatch('[0-9a-f]{40}', source_commit), 'Missing native test source commit')
    return SimpleNamespace(**paths, site_path=path, project=project, runner_service=data['runner_service'], source_commit=source_commit)


def require_unique(first, second, fields):
    for field in fields:
        require(first[field] != second[field], 'Clones reused identity: ' + field)


def require_stable(first, second, fields):
    for field in fields:
        require(first[field] == second[field], 'Identity changed on restart: ' + field)


def require_drained(service):
    result = run(['systemctl', 'show', service, '-p', 'Id', '-p', 'LoadState', '-p', 'ActiveState'],
                 timeout=15, check=False)
    properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    require(result.returncode == 0 and properties.get('Id') == service and
            properties.get('LoadState') == 'loaded' and properties.get('ActiveState') == 'inactive',
            'The exact loaded runner service must be drained and stopped')
    require(run(['pgrep', '-f', '[R]unner.Worker'], check=False).returncode == 1, 'Runner job still active')


def require_runner_context(service, context_path, site, candidate):
    """Manual callers drain the runner; CI must prove an owned isolated unit."""
    if context_path is None:
        require_drained(service)
        return
    require(context_path.is_absolute() and context_path.resolve() == context_path and
            context_path.is_relative_to(site.tool_prefix / 'ci/evidence'), 'CI context must be protected dispatcher evidence')
    protected(context_path)
    require(context_path.is_file() and not context_path.stat().st_mode & 0o077, 'CI context must be private')
    context = json.loads(context_path.read_text())
    require(set(context) == {'schema_version', 'candidate', 'candidate_sha256', 'source_commit',
                            'site_path', 'site_sha256', 'unit', 'guard_unit', 'operation_binding'}, 'Unexpected CI context fields')
    require(context['schema_version'] == 1 and context['candidate'] == str(candidate) and
            context['candidate_sha256'] == digest(candidate) and context['source_commit'] == site.source_commit and
            json.loads(candidate.read_text())['source_commit'] == site.source_commit, 'CI candidate/source binding mismatch')
    site_path = Path(context['site_path'])
    protected(site_path)
    require(site_path == site.site_path and context['site_sha256'] == digest(site_path), 'CI native site binding mismatch')
    require(re.fullmatch('[0-9a-f]{64}', context['operation_binding']), 'Invalid CI operation binding')
    unit, guard = context['unit'], context['guard_unit']
    match = re.fullmatch(r'zs-golden-smoke-(ci-[0-9a-f]{24})-[12]\.service', unit)
    require(match and guard == 'zs-golden-guard-' + match[1] + '.service', 'Unexpected CI unit ownership')
    group = '/github.slice/github-runner.slice/' + unit
    membership = Path('/proc/self/cgroup').read_text().splitlines()
    require(len(membership) == 1 and membership[0].startswith('0::') and
            (membership[0][3:] == group or membership[0][3:].startswith(group + '/')), 'Helper is outside its owned CI cgroup')
    properties = ['Id', 'LoadState', 'ActiveState', 'ControlGroup', 'Slice', 'BindsTo', 'After', 'PrivateNetwork', 'KillMode', 'MainPID', 'Delegate']
    def state(name):
        result = run(['systemctl', 'show', name, *sum((['-p', prop] for prop in properties), [])], timeout=15)
        return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    active, lifetime = state(unit), state(guard)
    require(active.get('Id') == unit and active.get('LoadState') == 'loaded' and active.get('ActiveState') == 'active' and
            active.get('ControlGroup') == group and active.get('Slice') == 'github-runner.slice' and
            active.get('PrivateNetwork') == 'yes' and active.get('KillMode') == 'control-group' and
            guard in active.get('BindsTo', '').split() and guard in active.get('After', '').split(), 'CI unit isolation/lifetime mismatch')
    if json.loads(candidate.read_text())['target'] == 'proxmox-lxc':
        require(active.get('Delegate') == 'yes', 'CI LXC unit lacks cgroup delegation')
    require(lifetime.get('Id') == guard and lifetime.get('LoadState') == 'loaded' and lifetime.get('ActiveState') == 'active' and
            lifetime.get('ControlGroup') == '/github.slice/github-runner.slice/' + guard and
            lifetime.get('Slice') == 'github-runner.slice' and int(lifetime.get('MainPID', '0')) > 1, 'CI lifetime guard is inactive')
    require(os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net') and
            {name for _, name in socket.if_nameindex()} == {'lo'}, 'CI network namespace is not isolated')
    require(os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'), 'CI mount namespace is not isolated')
