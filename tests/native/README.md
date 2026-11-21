# Native candidate smoke tests

These helpers test existing candidates with upstream QEMU/KVM and LXC. They do not assemble images or import templates. Run them only on the approved dedicated builder. Direct manual use requires draining its existing runner and confirming no job remains. They refuse a Proxmox host, require root Linux execution with `GOLDEN_APPLY=smoke`, and hold the same workspace lock as the image pipeline. The surrounding manual operational playbook owns runner restoration and verifies that its guest processes have stopped first. The staged CI dispatcher instead supplies a protected `--ci-context` bound to the candidate, source, native site and owned lifetime guard; the helper verifies its isolated cgroup and namespaces before allowing the active-runner CI path. The context option is not a general drain bypass.

Keep the source checkout root-owned, protected, clean and committed. The report records its commit. Invoke these files from that checkout so they reuse its runtime playbooks. The helpers do not install tools or change fleet configuration, host networking, subordinate-ID allocations or global AppArmor settings.

## Private inputs

Supply `--site` with an absolute path to a root-owned mode-0600 JSON file outside the checkout. It must contain exactly these fields:

| Field | Required value |
| --- | --- |
| `workspace` | Existing protected workspace matching the bootstrap builder marker. |
| `evidence` | Existing protected directory for private test results. |
| `tool_prefix` | Existing protected prefix installed by the builder Ansible role, containing `venv/` and `collections/`. |
| `builder_marker` | Existing protected JSON marker written by bootstrap, with purpose `isolated-image-builder`, region `yow` and the same workspace. |
| `runner_service` | Exact existing `actions.runner.…service` from private fleet inventory. Manual use requires that exact loaded, inactive service; guarded CI uses the dispatcher context described above. There is no default. |

Site paths use only letters, numbers, `/`, `_`, `.` and `-`, excluding CLI option separators. Paths and their parents must be root-owned, without symlinks or group/other write permission. The candidate artifact must remain inside the configured workspace. Each evidence run must be a new direct child of the configured evidence directory, with a name containing only letters, numbers, `_` and `-`. Keep VM run names short because Unix socket paths are limited.

The artifact must be reviewed builder output whose candidate checksum matches. Archive validation is an additional safety check, not a sandbox for arbitrary uploaded files. Logs, temporary clone disks/root filesystems and host identities remain private. Temporary administrator private keys are generated on the builder and removed on completion or failure. Never copy private keys or raw evidence into this repository.

## VM smoke

Set `SITE`, `CANDIDATE` and `EVIDENCE_RUN` to approved absolute private paths. After the live-test approval and runner drain:

```bash
sudo env GOLDEN_APPLY=smoke python3 tests/native/vm_smoke.py \
  --site "$SITE" "$CANDIDATE" "$EVIDENCE_RUN"
```

Required tools are QEMU with usable `/dev/kvm`, `qemu-img`, `xorriso`, OpenSSH and the Ansible toolchain installed by bootstrap. The candidate needs cloud-init, QEMU guest agent and the baseline packages supplied by the VM pipeline. `--ssh-port` optionally selects an unused unprivileged loopback port.

Two sequential clones use disposable QCOW2 overlays, distinct ConfigDrive metadata and distinct SSH keys. QEMU user networking has restricted mode enabled and IPv6 disabled, with SSH forwarding bound only to `127.0.0.1`. The guest agent supplies each guest's public SSH host key through its private Unix socket before SSH connects. The test requires the ConfigDrive datasource to finish, records `cloud-id` separately, and runs `40-verify-runtime.yml` through a non-root key-only administrator. It checks first-clone reboot persistence, cross-clone machine and instance identities, distinct host keys and the unchanged source disk checksum. QEMU is stopped on failure.

## LXC smoke

Choose an explicit unused 65,536-ID host range through the private host inventory. Before extracting, the helper rejects overlap with `/etc/subuid`, `/etc/subgid`, host account/group IDs or live nonidentity UID/GID maps. It also refuses installed `newuidmap`/`newgidmap` helpers because LXC then requires a reserved root range. Resolve that operational prerequisite separately without changing allocations to force the smoke test through.

After approval and drain, set `ID_BASE` and run one clone in a private mount namespace:

```bash
sudo env GOLDEN_APPLY=smoke unshare --mount --propagation private -- \
  python3 tests/native/lxc_smoke.py --site "$SITE" \
  "$CANDIDATE" "$EVIDENCE_RUN" --id-base "$ID_BASE"
```

Required tools are native LXC with its packaged common/user-namespace configuration, `unshare`, `mount`, `nsenter`, `ip`, OpenSSH and the installed Ansible toolchain. The kernel must permit root-launched user namespaces and the generated LXC AppArmor profile. Stop if host policy blocks the test; the helper does not weaken global policy.

The archive is fully checked before extraction. Absolute or traversing member names, duplicate names, children beneath archived symlinks, unsafe hardlink targets and special-device entries are rejected. Ownership is shifted without following symlinks. LXC uses a temporary path under `/run` to reach its runtime directory and mapped root filesystem inside the private mount namespace. Evidence and SSH keys remain outside that mount.

Explicit `lxc.net.0.type=empty` creates a loopback-only network namespace. The helper verifies that namespace and the actual `/proc` UID/GID maps. It bootstraps a temporary root key, uses `45-provision-lxc-admin.yml` to verify a non-root administrator before disabling root SSH, and runs `40-verify-runtime.yml` before and after stop/start. The controller enters only the container's network namespace for loopback SSH, retaining its private host-side inventory and keys. Cleanup stops the container and removes its private bind mount; extracted evidence remains available for inspection.

Run a second invocation with a fresh evidence directory and `--compare-report "$PREVIOUS_REPORT"`, pointing to the first successful `smoke-report.json`. The prior report must cover the same unchanged artifact and a stopped container. The second invocation additionally requires distinct machine IDs, host keys and hostnames. A single-clone report explicitly leaves uniqueness untested.

## Evidence limits and offline tests

Reports carry a native-only scope, actual status and a `not_tested` list. They contain no promotion flag. Passing native smoke does not establish CloudStack or Proxmox provisioning compatibility, external DNS, NTP synchronization, patching, complete CIS coverage, vulnerability clearance or release approval. Use real platform and security evidence for those gates. Runtime checks exercise the existing baseline, not a complete CIS benchmark.

The normal repository validator discovers the offline harness tests:

```bash
python3 -m unittest discover -s tests -p test_native_smoke.py -v
```

Fixtures cover archive traversal/link rejection, ownership handling, UID-range conflicts, private-site guards, asynchronous QGA replies and failure/timeout handling, QEMU cleanup, datasource identity and clone/restart identity claims. They use no live guests or infrastructure.

Upstream references: [QEMU restricted user networking](https://www.qemu.org/docs/master/system/invocation.html), [QEMU guest-agent protocol](https://www.qemu.org/docs/master/interop/qemu-ga-ref.html), [cloud-init ConfigDrive](https://docs.cloud-init.io/en/latest/reference/datasources/configdrive.html), [LXC configuration](https://linuxcontainers.org/lxc/manpages/man5/lxc.container.conf.5.html) and [LXC 6.0.6 ID mapping](https://github.com/lxc/lxc/blob/v6.0.6/src/lxc/idmap_utils.c).
