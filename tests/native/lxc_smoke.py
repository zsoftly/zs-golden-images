#!/usr/bin/env python3
"""Private one-clone native LXC smoke; requires a private mount namespace."""
import argparse
import grp
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

import common as vm
from common import digest, load_site, protected, require, require_runner_context, require_stable, require_unique, run, write_json


def unused_id_range(base):
    require(65536 <= base and base + 65536 <= 4294967295, 'Invalid subordinate ID range')
    overlaps = lambda start, count: base < start + count and start < base + 65536
    for filename in ('/etc/subuid', '/etc/subgid'):
        for line in Path(filename).read_text().splitlines():
            if line.strip() and not line.lstrip().startswith('#'):
                _, start, count = line.rsplit(':', 2)
                require(not overlaps(int(start), int(count)), 'Range overlaps ' + filename)
    for ident in [entry.pw_uid for entry in pwd.getpwall()] + [entry.gr_gid for entry in grp.getgrall()]:
        require(not overlaps(ident, 1), 'Range overlaps a host account or group')
    for process in Path('/proc').glob('[0-9]*'):
        for kind in ('uid_map', 'gid_map'):
            try:
                lines = (process / kind).read_text().splitlines()
            except (FileNotFoundError, ProcessLookupError):
                continue
            for line in lines:
                inside, outside, count = map(int, line.split())
                if inside != outside:
                    require(not overlaps(outside, count), 'Range overlaps live ' + str(process / kind))


def archive_members(archive):
    """Validate the whole archive before extracting even a directory."""
    members = {}
    for item in archive.getmembers():
        path = PurePosixPath(item.name)
        require(not path.is_absolute() and '..' not in path.parts, 'Unsafe archive member: ' + item.name)
        name = str(path)
        require(name != '.' or item.isdir(), 'Invalid archive root')
        require(name not in members, 'Duplicate archive member: ' + name)
        require(item.isdir() or item.isreg() or item.issym() or item.islnk(), 'Unsupported special archive member: ' + name)
        require(0 <= item.uid < 65536 and 0 <= item.gid < 65536, 'Archive ID outside mapped range')
        require(not item.sparse, 'Sparse archive member unsupported')
        members[name] = item
    require(bool(members), 'Empty rootfs archive')
    for name, item in members.items():
        for parent in PurePosixPath(name).parents:
            require(str(parent) not in members or members[str(parent)].isdir(), 'Archive member beneath non-directory: ' + name)
        if item.islnk():
            target = PurePosixPath(item.linkname)
            require(not target.is_absolute() and '..' not in target.parts, 'Unsafe hardlink target: ' + item.linkname)
            require(str(target) in members and members[str(target)].isreg(), 'Hardlink must target one regular archive member')
    return members


def extract(artifact, rootfs, base):
    # Input must be our reviewed, hash-verified builder output, not an untrusted upload.
    # Symlink contents retain guest semantics; no extraction traverses a symlink.
    with tarfile.open(artifact, 'r:*') as archive:
        members = archive_members(archive)
        rootfs.mkdir(mode=0o700)
        for name, item in members.items():
            destination = rootfs / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if item.isdir():
                destination.mkdir(exist_ok=True)
            elif item.isreg():
                with archive.extractfile(item) as source, destination.open('xb') as output:
                    shutil.copyfileobj(source, output)
        for name, item in members.items():
            if item.islnk():
                os.link(rootfs / str(PurePosixPath(item.linkname)), rootfs / name, follow_symlinks=False)
        for name, item in members.items():
            if item.issym():
                os.symlink(item.linkname, rootfs / name)
        # Include implicit directories; never follow an archived link while shifting.
        for directory, dirs, files in os.walk(rootfs, followlinks=False):
            for entry in [Path(directory), *(Path(directory) / name for name in dirs + files)]:
                item = members.get(str(entry.relative_to(rootfs)))
                if item and item.islnk():
                    item = members[str(PurePosixPath(item.linkname))]
                os.chown(entry, base + (item.uid if item else 0), base + (item.gid if item else 0), follow_symlinks=False)
                if not entry.is_symlink():
                    os.chmod(entry, (item.mode & 0o7777) if item else 0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', type=Path, required=True, help='Private native smoke site JSON')
    parser.add_argument('--ci-context', type=Path, help='Protected dispatcher context; manual calls still require a drained runner')
    parser.add_argument('candidate', type=Path)
    parser.add_argument('evidence_run', type=Path)
    parser.add_argument('--id-base', type=int, required=True, help='Explicit unused host UID/GID start; validated before use')
    parser.add_argument('--compare-report', type=Path, help='Prior successful native LXC report for this artifact')
    args = parser.parse_args()
    previous = None
    require(sys.platform == 'linux' and os.geteuid() == 0 and os.environ.get('GOLDEN_APPLY') == 'smoke', 'Requires authorized root Linux execution')
    require(os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'), 'Run under unshare --mount --propagation private')
    require(not Path('/etc/pve').exists(), 'Do not smoke-test on a production Proxmox host')
    site = load_site(args.site)
    os.umask(0o077)
    protected(site.workspace)
    protected(site.evidence)
    protected(site.project)
    protected(args.candidate)
    require(args.candidate.is_absolute() and args.candidate.is_file(), 'Invalid candidate path')
    require(args.evidence_run.parent == site.evidence and re.fullmatch('[A-Za-z0-9_-]+', args.evidence_run.name) and not args.evidence_run.exists(), 'Use a new direct evidence child with a simple name')
    require_runner_context(site.runner_service, args.ci_context, site, args.candidate)
    lockfd = os.open(site.workspace / '.build.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(lockfd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe build lock')
    vm.fcntl.flock(lockfd, vm.fcntl.LOCK_EX | vm.fcntl.LOCK_NB)
    require(shutil.which('newuidmap') is None and shutil.which('newgidmap') is None,
            'Mapping helpers are present; LXC may require a reserved root range. Do not rewrite host subuid/subgid.')
    unused_id_range(args.id_base)
    candidate = json.loads(args.candidate.read_text())
    require(candidate['target'] == 'proxmox-lxc' and candidate['profile'] in ('debian-13', 'ubuntu-26.04'), 'Unsupported candidate')
    artifact = (args.candidate.parent / candidate['artifact']['path']).absolute()
    require(artifact.is_relative_to(site.workspace) and artifact.resolve() == artifact, 'Artifact must remain in protected workspace')
    protected(artifact)
    original = digest(artifact)
    require(original == candidate['artifact']['sha256'], 'Candidate hash mismatch')
    if args.compare_report is not None:
        require(args.compare_report.is_absolute() and args.compare_report.is_relative_to(site.evidence), 'Prior report must be protected evidence')
        protected(args.compare_report)
        previous = json.loads(args.compare_report.read_text())
        require(previous.get('scope') == 'native-lxc-one-clone-smoke-only' and previous.get('status') == 'passed' and
                previous.get('container_stopped') is True and previous.get('original_artifact_unchanged') is True and
                previous.get('artifact_sha256') == original and previous.get('candidate_sha256') == digest(args.candidate) and
                previous.get('test_source_commit') == site.source_commit, 'Prior report must be successful for the same unchanged candidate and source')
    evidence = args.evidence_run
    evidence.mkdir(mode=0o700)
    report = {'schema_version': 1, 'scope': 'native-lxc-one-clone-smoke-only', 'status': 'failed',
              'artifact_sha256': original, 'candidate_sha256': digest(args.candidate),
              'test_source_commit': site.source_commit,
              'not_tested': ['second-clone-uniqueness', 'proxmox-platform-compatibility', 'cloudstack-platform-compatibility',
                             'external-dns', 'network-provisioning', 'ntp-synchronization', 'full-cis', 'vulnerability-clearance', 'release-approval']}
    name = 'golden-smoke-' + os.urandom(4).hex()
    runtime = evidence / 'lxc'
    instance = runtime / name
    rootfs = instance / 'rootfs'
    visible = Path('/run') / name
    visible_instance = visible / name
    key = evidence / 'admin-key'
    process = None
    visible_created = False
    mounted = False
    base = ['-P', str(visible), '-n', name]
    attach = ['lxc-attach', *base, '--clear-env', '--']

    def attach_run(argv, **kwargs):
        return run([*attach, *argv], **kwargs)

    def container_pid():
        pid = int(run(['lxc-info', *base, '-pH']).stdout.strip())
        require(pid > 1, 'Invalid container init PID')
        return pid

    def identity():
        code = "import json,pathlib,socket; p=pathlib.Path; print(json.dumps({'machine_id':p('/etc/machine-id').read_text().strip(),'host_key':p('/etc/ssh/ssh_host_ed25519_key.pub').read_text().strip(),'hostname':socket.gethostname()}))"
        current = json.loads(attach_run(['/usr/bin/python3', '-c', code], timeout=15).stdout)
        require(re.fullmatch('[0-9a-f]{32}', current['machine_id']), 'Machine identity not initialized')
        require(current['host_key'].startswith('ssh-ed25519 '), 'Host key not initialized')
        return current

    def stop():
        nonlocal process
        if process is None:
            return
        try:
            run(['lxc-stop', *base, '-t', '20'], timeout=35, check=False, log=evidence / 'stop.log')
        except subprocess.TimeoutExpired:
            pass
        if process.poll() is None:
            run(['lxc-stop', *base, '-k'], timeout=20, check=False, log=evidence / 'kill.log')
        process.wait(timeout=20)
        require(run(['lxc-info', *base, '-sH'], check=False).stdout.strip() == 'STOPPED', 'Container is not confirmed stopped')
        process = None

    def start(logname):
        nonlocal process
        with (evidence / logname).open('w') as output:
            process = subprocess.Popen(['lxc-start', *base, '-F', '-f', visible_instance / 'config', '-L', evidence / (logname + '.console'),
                                        '-o', evidence / (logname + '.lxc'), '-l', 'INFO'], stdout=output, stderr=subprocess.STDOUT,
                                       preexec_fn=vm.child_guard(os.getpid()))
        current = vm.wait_for(process, identity)
        pid = container_pid()
        for kind in ('uid_map', 'gid_map'):
            mapping = [list(map(int, line.split())) for line in Path(f'/proc/{pid}/{kind}').read_text().splitlines()]
            require(mapping == [[0, args.id_base, 65536]], 'Container is not mapped as requested: ' + kind)
            write_json(evidence / (logname + '.' + kind + '.json'), mapping)
        require(os.readlink(f'/proc/{pid}/ns/net') != os.readlink('/proc/self/ns/net'), 'Container shares host network namespace')
        network = json.loads(run(['nsenter', '-t', str(pid), '-n', '--', 'ip', '-j', 'link', 'show']).stdout)
        require([link['ifname'] for link in network] == ['lo'], 'Container has an unexpected network interface')
        write_json(evidence / (logname + '.network.json'), network)
        return current, pid

    try:
        run([site.tool_prefix / 'venv/bin/python', site.project / 'scripts/release.py', 'inspect', args.candidate], log=evidence / 'inspect.log')
        # LXC checks traversal of -P after switching to mapped root. Keep the
        # evidence private and give only the runtime tree a traversable alias.
        instance.mkdir(parents=True)
        runtime.chmod(0o711)
        instance.chmod(0o711)
        extract(artifact, rootfs, args.id_base)
        config = '\n'.join([
            'lxc.include = /usr/share/lxc/config/common.conf', 'lxc.include = /usr/share/lxc/config/userns.conf',
            'lxc.arch = x86_64', 'lxc.rootfs.path = dir:' + str(visible_instance / 'rootfs'), 'lxc.uts.name = ' + name,
            f'lxc.idmap = u 0 {args.id_base} 65536', f'lxc.idmap = g 0 {args.id_base} 65536',
            'lxc.net =', 'lxc.net.0.type = empty', 'lxc.apparmor.profile = generated',
            'lxc.apparmor.allow_nesting = 0', 'lxc.cgroup2.memory.max = 1073741824',
            'lxc.cgroup2.memory.swap.max = 0', 'lxc.cgroup2.pids.max = 512', 'lxc.cgroup2.cpu.max = 200000 100000',
            'lxc.tty.max = 0', 'lxc.pty.max = 64', ''])
        (instance / 'config').write_text(config)
        run(['mount', '--make-rprivate', '/'])
        visible.mkdir(mode=0o700)
        visible_created = True
        run(['mount', '--bind', runtime, visible])
        mounted = True
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
        public_key = key.with_suffix('.pub').read_text().strip()
        first, pid = start('first-boot.log')
        write_json(evidence / 'identity-first.json', first)
        attach_run(['/bin/sh', '-ec', 'umask 077; mkdir -p /root/.ssh; printf "%s\\n" "$1" > /root/.ssh/authorized_keys', '--', public_key])
        known = evidence / 'known_hosts'
        known.write_text('127.0.0.1 ' + ' '.join(first['host_key'].split()[:2]) + '\n')
        common = ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                  '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=5',
                  '-o', 'ControlMaster=no', '-o', 'ControlPath=none']
        vm.wait_for(process, lambda: run(['nsenter', '-t', str(pid), '-n', '--', 'ssh', *common,
                                         '-i', key, 'root@127.0.0.1', 'true'], timeout=15))
        inventory = {'all': {'children': {'golden_candidates': {'hosts': {'smoke': {
            'ansible_host': '127.0.0.1', 'ansible_user': 'root', 'ansible_ssh_private_key_file': str(key),
            'ansible_python_interpreter': '/usr/bin/python3', 'ansible_ssh_common_args': shlex.join(common)}}}}}}
        write_json(evidence / 'inventory.json', inventory)
        settings = {'golden_runtime_approved': True, 'golden_profile': candidate['profile'], 'golden_target': 'proxmox-lxc',
                    'golden_enrollment_policy': 'public', 'golden_admin_user': vm.USER,
                    'golden_admin_public_key': public_key, 'golden_admin_private_key_file': str(key),
                    'golden_admin_ssh_host': '127.0.0.1', 'golden_admin_known_hosts_file': str(known), 'golden_admin_sudo_commands': 'ALL'}
        write_json(evidence / 'vars.json', settings)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', ANSIBLE_ROLES_PATH=str(site.project / 'ansible/roles'),
                   ANSIBLE_COLLECTIONS_PATH=str(site.tool_prefix / 'collections'), ANSIBLE_HOST_KEY_CHECKING='True')

        def play(filename, phase, logname, active_pid):
            run(['nsenter', '-t', str(active_pid), '-n', '--', site.tool_prefix / 'venv/bin/ansible-playbook',
                 '-i', evidence / 'inventory.json', '-e', '@' + str(evidence / 'vars.json'), site.project / 'ansible/playbooks' / filename],
                env=dict(env, GOLDEN_APPLY=phase), timeout=300, log=evidence / logname)

        play('45-provision-lxc-admin.yml', 'provision-admin', 'admin-provision.log', pid)
        inventory['all']['children']['golden_candidates']['hosts']['smoke']['ansible_user'] = vm.USER
        write_json(evidence / 'inventory.json', inventory)
        play('40-verify-runtime.yml', 'verify', 'runtime-first.log', pid)
        denied = run(['nsenter', '-t', str(pid), '-n', '--', 'ssh', *common, '-i', key, 'root@127.0.0.1', 'id -u'],
                     timeout=20, check=False, log=evidence / 'root-login-denied.log')
        require(denied.returncode != 0, 'Root SSH unexpectedly succeeded')
        stop()
        after, pid = start('restart.log')
        require_stable(first, after, ('machine_id', 'host_key', 'hostname'))
        write_json(evidence / 'identity-restart.json', after)
        play('40-verify-runtime.yml', 'verify', 'runtime-restart.log', pid)
        if previous is not None:
            require_unique(previous['identity'], after, ('machine_id', 'host_key', 'hostname'))
            report['clone_uniqueness'] = 'passed'
            report['previous_report_sha256'] = digest(args.compare_report)
            report['not_tested'].remove('second-clone-uniqueness')
        report.update(status='passed', native_runtime_checks='passed', restart_persistence='passed', identity=after,
                      container_name=name, host_id_base=args.id_base, root_ssh='denied')
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        try:
            stop()
            report['container_stopped'] = True
        except BaseException as error:
            report.update(status='failed', cleanup_error=str(error))
            raise
        finally:
            key.unlink(missing_ok=True)
            report['original_artifact_unchanged'] = digest(artifact) == original
            if not report['original_artifact_unchanged']:
                report['status'] = 'failed'
            if process is None and visible_created:
                try:
                    if mounted:
                        run(['umount', visible], timeout=20)
                    visible.rmdir()
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                    report.update(status='failed', cleanup_error=str(error))
            write_json(evidence / 'smoke-report.json', report)
            require(report['original_artifact_unchanged'], 'Original archive was modified')
    require(report['status'] == 'passed', 'Native smoke cleanup failed')
    print('Native LXC smoke passed; consult not_tested for remaining checks. Platform and full release acceptance remain unverified. Report: ' + str(evidence / 'smoke-report.json'))


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    main()
