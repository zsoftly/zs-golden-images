#!/usr/bin/env python3
"""Private native KVM smoke test. Never promotes or modifies a candidate image."""
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid

from common import (USER, child_guard, digest, load_site, protected, require, require_runner_context,
                    require_stable, require_unique, run, wait_for, write_json)


def qga(sockpath, command, arguments=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(sockpath))
        stream = sock.makefile('rb')
        nonce = secrets.randbits(63)
        request = {'execute': 'guest-sync-delimited', 'arguments': {'id': nonce}}
        sock.sendall(b'\xff' + json.dumps(request).encode() + b'\n')
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            line = stream.readline(1_000_000)
            require(line, 'QGA closed during stream synchronization')
            if b'\xff' not in line:
                continue
            message = json.loads(line.rsplit(b'\xff', 1)[1])
            if message.get('return') == nonce:
                break
        else:
            raise RuntimeError('QGA synchronization timed out')
        request = {'execute': command}
        if arguments is not None:
            request['arguments'] = arguments
        sock.sendall(json.dumps(request).encode() + b'\n')
        message = json.loads(stream.readline(1_000_000))
        require('error' not in message, 'QGA: ' + json.dumps(message.get('error')))
        return message['return']


def guest_exec(sockpath, argv):
    pid = qga(sockpath, 'guest-exec', {'path': argv[0], 'arg': argv[1:], 'capture-output': True})['pid']
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = qga(sockpath, 'guest-exec-status', {'pid': pid})
        if result.get('exited'):
            require(result.get('exitcode') == 0 and not result.get('out-truncated'),
                    'Guest command failed or output truncated')
            return base64.b64decode(result.get('out-data', '')).decode()
        time.sleep(1)
    raise RuntimeError('Guest command timed out')


def identity(sockpath):
    code = "import json,pathlib,socket; p=pathlib.Path; print(json.dumps({'machine_id':p('/etc/machine-id').read_text().strip(),'boot_id':p('/proc/sys/kernel/random/boot_id').read_text().strip(),'instance_id':p('/var/lib/cloud/data/instance-id').read_text().strip(),'host_key':p('/etc/ssh/ssh_host_ed25519_key.pub').read_text().strip(),'hostname':socket.gethostname()}))"
    return json.loads(guest_exec(sockpath, ['/usr/bin/python3', '-c', code]))


def stop_qemu(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def cloud_identity(ssh, directory, expected_datasource):
    cloud_status = json.loads(run([*ssh, 'cloud-init status --format json'], timeout=20).stdout)
    write_json(directory / 'cloud-init-status.json', cloud_status)
    datasource = cloud_status.get('datasource')
    require(datasource == expected_datasource and cloud_status.get('status') == 'done',
            f'{expected_datasource} did not complete: {datasource}')
    platform = run([*ssh, 'cloud-id'], timeout=20).stdout.strip()
    return datasource, platform


def write_seed(directory, target, instance, hostname, mac, config):
    seed = directory / 'seed'
    if target == 'proxmox-kvm':
        seed.mkdir()
        write_json(seed / 'meta-data', {'instance-id': instance, 'local-hostname': hostname})
        write_json(seed / 'network-config', {'version': 2, 'ethernets': {
            'nic0': {'match': {'macaddress': mac}, 'dhcp4': True}}})
        (seed / 'user-data').write_text('#cloud-config\n' + json.dumps(config) + '\n')
        return 'CIDATA', 'nocloud'
    configdrive = seed / 'openstack' / 'latest'
    configdrive.mkdir(parents=True)
    write_json(configdrive / 'meta_data.json', {'uuid': instance, 'name': hostname, 'hostname': hostname,
                                               'meta': {'dsmode': 'local'}})
    write_json(configdrive / 'network_data.json', {
        'links': [{'id': 'nic0', 'type': 'phy', 'ethernet_mac_address': mac}],
        'networks': [{'id': 'net0', 'type': 'ipv4_dhcp', 'link': 'nic0'}], 'services': []})
    (configdrive / 'user_data').write_text('#cloud-config\n' + json.dumps(config) + '\n')
    return 'config-2', 'configdrive'


def test_clone(root, artifact, profile, target, number, port, site):
    directory = root / ('clone-' + str(number))
    directory.mkdir(mode=0o700)
    key = directory / 'admin-key'
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
    public_key = key.with_suffix('.pub').read_text().strip()
    instance = str(uuid.uuid4())
    hostname = 'golden-smoke-' + str(number)
    mac = '52:54:00:' + ':'.join(f'{value:02x}' for value in secrets.token_bytes(3))
    config = {'users': [{'name': USER, 'shell': '/bin/bash', 'lock_passwd': True,
                         'sudo': ['ALL=(ALL) NOPASSWD:ALL'], 'ssh_authorized_keys': [public_key]}],
              'disable_root': True, 'ssh_pwauth': False, 'package_update': False,
              'package_upgrade': False, 'manage_etc_hosts': True}
    label, expected_datasource = write_seed(directory, target, instance, hostname, mac, config)
    iso = directory / 'configdrive.iso'
    run(['xorriso', '-as', 'mkisofs', '-quiet', '-r', '-J', '-V', label, '-o', iso, directory / 'seed'], log=directory / 'iso.log')
    overlay = directory / 'disk.qcow2'
    run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', artifact, overlay], log=directory / 'overlay.log')
    ga = directory / 'qga.sock'
    require(len(str(ga).encode()) < 104, 'Evidence path is too long for a Unix QGA socket')
    args = ['qemu-system-x86_64', '-machine', 'pc', '-accel', 'kvm', '-cpu', 'host', '-smp', '2', '-m', '2048',
            '-name', hostname, '-uuid', instance, '-display', 'none', '-monitor', 'none',
            '-serial', 'file:' + str(directory / 'serial.log'),
            '-drive', 'file=' + str(overlay) + ',format=qcow2,if=virtio', '-cdrom', str(iso), '-boot', 'c',
            '-netdev', f'user,id=test,ipv6=off,restrict=on,hostfwd=tcp:127.0.0.1:{port}-:22',
            '-device', 'virtio-net-pci,netdev=test,mac=' + mac,
            '-device', 'virtio-serial-pci', '-chardev', 'socket,path=' + str(ga) + ',server=on,wait=off,id=qga',
            '-device', 'virtserialport,chardev=qga,name=org.qemu.guest_agent.0']
    write_json(directory / 'qemu-argv.json', args)
    with (directory / 'qemu.log').open('w') as log:
        proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT,
                                preexec_fn=child_guard(os.getpid()))
        try:
            first = wait_for(proc, lambda: identity(ga))
            require(re.fullmatch('[0-9a-f]{32}', first['machine_id']), 'Invalid guest machine identity')
            require(first['instance_id'] == instance, 'Cloud-init instance identity not applied')
            require(first['host_key'].startswith('ssh-ed25519 '), 'Unexpected guest host key')
            known = directory / 'known_hosts'
            known.write_text(f'[127.0.0.1]:{port} ' + ' '.join(first['host_key'].split()[:2]) + '\n')
            common = ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                      '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
                      '-o', 'ConnectTimeout=5', '-o', 'ConnectionAttempts=1', '-o', 'ControlMaster=no',
                      '-o', 'ControlPath=none', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2']
            ssh = ['ssh', *common, '-i', key, '-p', str(port), USER + '@127.0.0.1']
            wait_for(proc, lambda: run([*ssh, 'test "$(id -un)" = goldencheck && test "$(sudo -n id -u)" = 0'], timeout=20))
            env = dict(os.environ, GOLDEN_APPLY='verify', PYTHONDONTWRITEBYTECODE='1',
                       ANSIBLE_ROLES_PATH=str(site.project / 'ansible/roles'),
                       ANSIBLE_COLLECTIONS_PATH=str(site.tool_prefix / 'collections'), ANSIBLE_HOST_KEY_CHECKING='True')
            inventory = {'all': {'children': {'golden_candidates': {'hosts': {'smoke': {
                'ansible_host': '127.0.0.1', 'ansible_port': port, 'ansible_user': USER,
                'ansible_ssh_private_key_file': str(key), 'ansible_python_interpreter': '/usr/bin/python3',
                'ansible_ssh_common_args': shlex.join(common)}}}}}}
            write_json(directory / 'inventory.json', inventory)
            settings = {'golden_runtime_approved': True, 'golden_profile': profile,
                        'golden_target': target, 'golden_enrollment_policy': 'public'}
            write_json(directory / 'vars.json', settings)
            play = [site.tool_prefix / 'venv/bin/ansible-playbook', '-i', directory / 'inventory.json',
                    '-e', '@' + str(directory / 'vars.json'), site.project / 'ansible/playbooks/40-verify-runtime.yml']
            run(play, timeout=300, env=env, log=directory / 'runtime-first.log')
            datasource, platform = cloud_identity(ssh, directory, expected_datasource)
            first = identity(ga)
            require(first['hostname'] == hostname and first['instance_id'] == instance, 'Instance metadata mismatch')
            write_json(directory / 'identity-first.json', first)
            root_login = run(['ssh', *common, '-i', key, '-p', str(port), 'root@127.0.0.1', 'id -u'], timeout=20, check=False, log=directory / 'root-login-denied.log')
            require(root_login.returncode != 0, 'Root SSH unexpectedly succeeded')
            result = {'uuid': instance, 'mac': mac, 'hostname': hostname, 'identity': first,
                      'native_runtime_checks': 'passed', 'root_ssh': 'denied', 'datasource': datasource,
                      'cloud_id_platform': platform}
            if number == 1:
                run([*ssh, 'sudo -n systemctl reboot --no-block'], timeout=20, check=False, log=directory / 'reboot-request.log')
                def rebooted():
                    current = identity(ga)
                    require(current['boot_id'] != first['boot_id'], 'Waiting for new boot identity')
                    return current
                after = wait_for(proc, rebooted)
                wait_for(proc, lambda: run([*ssh, 'true'], timeout=20))
                run(play, timeout=300, env=env, log=directory / 'runtime-reboot.log')
                after = identity(ga)
                require_stable(first, after, ('machine_id', 'host_key', 'instance_id', 'hostname'))
                write_json(directory / 'identity-reboot.json', after)
                result['reboot_persistence'] = 'passed'
            write_json(directory / 'result.json', result)
            return result
        finally:
            stop_qemu(proc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', type=Path, required=True, help='Private native smoke site JSON')
    parser.add_argument('--ci-context', type=Path, help='Protected dispatcher context; manual calls still require a drained runner')
    parser.add_argument('candidate', type=Path)
    parser.add_argument('evidence_run', type=Path)
    parser.add_argument('--ssh-port', type=int, default=22280)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0 and os.environ.get('GOLDEN_APPLY') == 'smoke',
            'Requires authorized root Linux execution with GOLDEN_APPLY=smoke')
    require(not Path('/etc/pve').exists(), 'Do not smoke-test on a production Proxmox host')
    site = load_site(args.site)
    os.umask(0o077)
    require(1024 <= args.ssh_port <= 65535, 'Use an unprivileged TCP port')
    require(args.candidate.is_absolute() and args.candidate.is_file() and not args.candidate.is_symlink(), 'Invalid candidate path')
    protected(args.candidate)
    require(args.evidence_run.is_absolute() and args.evidence_run.parent == site.evidence and not args.evidence_run.exists(),
            'Use a new direct child of the protected evidence directory')
    protected(site.evidence)
    protected(site.project)
    protected(site.workspace)
    lockfd = os.open(site.workspace / '.build.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(lockfd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe build lock')
    fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # Keep this process-owned descriptor open until exit, matching pipeline.sh's flock.
    require(re.fullmatch('[A-Za-z0-9_-]+', args.evidence_run.name), 'Use a simple evidence directory name')
    require_runner_context(site.runner_service, args.ci_context, site, args.candidate)
    require(Path('/dev/kvm').is_char_device(), 'KVM device missing')
    candidate = json.loads(args.candidate.read_text())
    require(candidate['target'] in ('cloudstack-kvm', 'proxmox-kvm') and candidate['profile'] in ('debian-13', 'ubuntu-26.04'),
            'Unsupported candidate')
    artifact = (args.candidate.parent / candidate['artifact']['path']).absolute()
    require(artifact.is_relative_to(site.workspace) and artifact.resolve() == artifact and re.fullmatch(r'[A-Za-z0-9/_.-]+', str(artifact)),
            'Artifact must be a canonical protected workspace path without QEMU option separators')
    protected(artifact)
    require(artifact.is_file(), 'Candidate artifact missing')
    original = digest(artifact)
    require(original == candidate['artifact']['sha256'], 'Candidate artifact hash mismatch')
    args.evidence_run.mkdir(mode=0o700)
    report = {'schema_version': 1, 'scope': 'native-kvm-smoke-only',
              'candidate_sha256': digest(args.candidate), 'artifact_sha256': original,
              'test_source_commit': site.source_commit,
              'not_tested': ['external-dns', 'ntp-synchronization', 'patching', 'cloudstack-platform-compatibility',
                             'proxmox-platform-compatibility', 'full-cis', 'vulnerability-clearance', 'release-approval'],
              'status': 'failed'}
    try:
        run([site.tool_prefix / 'venv/bin/python', site.project / 'scripts/release.py', 'inspect', args.candidate], log=args.evidence_run / 'inspect.log')
        clones = [test_clone(args.evidence_run, artifact, candidate['profile'], candidate['target'], n, args.ssh_port, site)
                  for n in (1, 2)]
        require_unique(clones[0]['identity'], clones[1]['identity'], ('machine_id', 'host_key', 'instance_id'))
        report.update(status='passed', clones=clones, clone_uniqueness='passed')
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        for number in (1, 2):
            (args.evidence_run / ('clone-' + str(number)) / 'admin-key').unlink(missing_ok=True)
        report['original_artifact_unchanged'] = digest(artifact) == original
        if not report['original_artifact_unchanged']:
            report['status'] = 'failed'
        write_json(args.evidence_run / 'smoke-report.json', report)
        require(report['original_artifact_unchanged'], 'Original candidate was modified')
    print('Native KVM smoke passed; release and platform acceptance remain blocked. Report: ' + str(args.evidence_run / 'smoke-report.json'))


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    main()
