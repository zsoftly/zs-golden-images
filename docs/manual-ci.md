# Manual candidate pipeline

The workflow runs one selected image through `preflight → build → inspect → smoke`, followed by an outcome summary. A successful chain produces a native-tested experimental candidate. Platform compatibility, full CIS coverage, security acceptance, signing and publication remain separate gates.

Each job runs from `main` in this repository on the same fixed image-builder labels. There is no checkout, third-party action, job-workspace source execution or artifact upload. GitHub receives stage outcomes and an opaque binding digest. Site inputs, images, logs and detailed evidence stay in protected builder storage. Profile/target choices and normal Actions metadata remain visible on GitHub.

## Stage contract

- **Preflight:** validate the operator approval, private inputs, protected source/toolchain, fleet configuration and capacity.
- **Build:** invoke the existing upstream builder and Ansible hooks. Configuration, hardening and cleanup run within the build job, with phase receipts bound to the same root filesystem. Failed builds retain partial work for inspection.
- **Inspect:** verify the candidate manifest and artifact structure/checksum.
- **Smoke:** run native VM or unprivileged LXC checks on disposable instances, with private evidence and owned-resource cleanup.
- **Summary:** report success, failure, cancellation or skipped stages. It runs after failed dependencies too, but still needs the shared runner to become available.

Successful dispatcher calls return only a 64-character lowercase hexadecimal binding. Each later job compares its binding with the preflight output before declaring success. Keep the approval identity stable throughout a run. If it changes, a later dispatcher call may execute the newly approved stage before the workflow detects the binding mismatch and fails the chain. Each operation still requires its own valid approval and prerequisite receipts. GitHub outputs are correlation data, not authorization: every dispatcher call independently validates the root-owned approval and protected receipts.

Workflow concurrency is scoped to profile and target and does not cancel an active run. GitHub keeps one pending run per pair by default; a newer pending run replaces the older pending run. There is no global FIFO guarantee. Different image chains and other repositories may interleave on the single host slot, while the dispatcher lock serializes actual stages. Protected receipts persist on that host across job boundaries; there is no GitHub artifact handoff. The workflow does not stop or restart its own runner.

## Invocation grant and activation

The Proxmox VM target requires a reviewed dispatcher redeployment and a fleet-owned sudo grant update. Verify the installed dispatcher hash and exact source revision before activation. The previous two-target grant does not allow the Proxmox VM commands.

The fleet grant lists these 24 exact commands without wildcards.

```text
/opt/zs-golden-images/bin/dispatch-candidate preflight debian-13 cloudstack-kvm
/opt/zs-golden-images/bin/dispatch-candidate preflight debian-13 proxmox-kvm
/opt/zs-golden-images/bin/dispatch-candidate preflight debian-13 proxmox-lxc
/opt/zs-golden-images/bin/dispatch-candidate preflight ubuntu-26.04 cloudstack-kvm
/opt/zs-golden-images/bin/dispatch-candidate preflight ubuntu-26.04 proxmox-kvm
/opt/zs-golden-images/bin/dispatch-candidate preflight ubuntu-26.04 proxmox-lxc
/opt/zs-golden-images/bin/dispatch-candidate build debian-13 cloudstack-kvm
/opt/zs-golden-images/bin/dispatch-candidate build debian-13 proxmox-kvm
/opt/zs-golden-images/bin/dispatch-candidate build debian-13 proxmox-lxc
/opt/zs-golden-images/bin/dispatch-candidate build ubuntu-26.04 cloudstack-kvm
/opt/zs-golden-images/bin/dispatch-candidate build ubuntu-26.04 proxmox-kvm
/opt/zs-golden-images/bin/dispatch-candidate build ubuntu-26.04 proxmox-lxc
/opt/zs-golden-images/bin/dispatch-candidate inspect debian-13 cloudstack-kvm
/opt/zs-golden-images/bin/dispatch-candidate inspect debian-13 proxmox-kvm
/opt/zs-golden-images/bin/dispatch-candidate inspect debian-13 proxmox-lxc
/opt/zs-golden-images/bin/dispatch-candidate inspect ubuntu-26.04 cloudstack-kvm
/opt/zs-golden-images/bin/dispatch-candidate inspect ubuntu-26.04 proxmox-kvm
/opt/zs-golden-images/bin/dispatch-candidate inspect ubuntu-26.04 proxmox-lxc
/opt/zs-golden-images/bin/dispatch-candidate smoke debian-13 cloudstack-kvm
/opt/zs-golden-images/bin/dispatch-candidate smoke debian-13 proxmox-kvm
/opt/zs-golden-images/bin/dispatch-candidate smoke debian-13 proxmox-lxc
/opt/zs-golden-images/bin/dispatch-candidate smoke ubuntu-26.04 cloudstack-kvm
/opt/zs-golden-images/bin/dispatch-candidate smoke ubuntu-26.04 proxmox-kvm
/opt/zs-golden-images/bin/dispatch-candidate smoke ubuntu-26.04 proxmox-lxc
```

The dispatcher rejects other argument counts or values. It uses isolated Python, ignores stdin and the caller's environment, and verifies protected source and toolchain ownership. The runner account may serve other repositories, whose processes could invoke the same granted commands. Only the root-owned approval selects a source commit, version and private site configuration. This does not isolate work from a caller that already has host-root access through Docker or another fleet permission.

Before activation, preserve these repository/fleet prerequisites:

- A selected-repository runner group must explicitly allow this public repository, including `allows_public_repositories: true`. Group membership alone is insufficient. The fleet owner approves and manages that permission.
- Keep repository `pull_request_creation_policy: collaborators_only` and fork-workflow approval at `all_external_contributors`. These are supplementary controls; this workflow remains manual-only and does not run pull-request code.
- Verify missing, expired and mismatched approvals, unsupported stages and extra arguments fail for the expected reason without creating build resources. Verify cancellation/timeout cleanup and actual Actions job-slot release on the deployed version.
- Grant activation separately from installation. This repository does not change runner groups, labels, sudoers or repository security settings.

## Private operator setup

1. Deploy the reviewed merged commit to the protected checkout at `/opt/zs-golden-images/project`; never copy a runner workspace into it.
2. Use the existing authorized bootstrap with `golden_builder_install_ci_dispatcher: true`. Supply `golden_builder_ci_native_site` as an existing absolute private native-site JSON path, `golden_builder_ci_lxc_id_base` as the explicitly selected unused UID/GID range start, and `golden_builder_ci_min_free_bytes` as the positive disk-space floor. The native site supplies `workspace`, `evidence`, `tool_prefix`, `builder_marker` and `runner_service`. Keep these paths and files root-owned and protected.
3. Verify the installed dispatcher hash, source revision and configuration. Confirm that the installed paths and their ancestors are root-owned and not writable by the runner. The private `ci.json` includes `native_site`, `lxc_id_base` and `min_free_bytes`; the dispatcher rechecks them for each stage.
4. Place a root-owned mode `0600` approval at `/etc/zs-golden-images/ci-requests/PROFILE-TARGET.json`, inside the root-owned mode `0700` directory, through private operational configuration.
5. Complete the fleet invocation review, live negative/cancellation checks and repository/group prerequisites above. Dispatch from `main` only after approval.

An approval still contains exactly `profile`, `target`, `version`, `source_commit`, `site_path` and `expires_at`. `source_commit` is the full reviewed installed commit. `site_path` names the protected private input JSON outside the checkout, matching the approved version and builder workspace. `expires_at` is a future integer UTC Unix timestamp. The workflow supplies neither that file nor its contents.

Example structure, deliberately expired and unusable:

```json
{
  "profile": "debian-13",
  "target": "cloudstack-kvm",
  "version": "20261116-r1",
  "source_commit": "0000000000000000000000000000000000000000",
  "site_path": "/private/approved-site.json",
  "expires_at": 0
}
```

The dispatcher verifies stage prerequisites and existing receipts before reuse. Rerunning a completed build verifies its candidate instead of rebuilding it; failed inspection or smoke can be retried against that same verified candidate. Renewing only the approval expiry preserves the binding, so a paused chain can resume after operator renewal. The protected operation record also binds CI configuration, native-site and toolchain hashes. Changing source, site inputs, native-test settings, ID allocation or disk policy rejects reuse. Approve a new image version and matching site inputs before rebuilding. A partial build without a valid completion receipt is retained for inspection and is not overwritten; use a separately approved new version after resolving the failure. Remove or expire approvals when they should no longer be callable.

Every actual build performs a fresh egress probe under its current lifetime guard; preflight does not prove egress. Reusing a completed build verifies its stored candidate and evidence hashes instead. Source acquisition retains the existing signed-metadata and scoped-egress checks. DNS rotation or private addresses fail closed. Native smoke uses the guarded CI ownership path; direct manual smoke retains its drained-runner requirement. All stage work remains in the existing fleet resource slice with bounded lifetime and cleanup. No stage requires a production Proxmox or CloudStack resource.

A native `pidwait` guard holds a verified pidfd for the dispatcher. Transient units bind to that guard, and Ansible descendants remain inside owned cgroups. Cleanup stops only owned units and verifies empty cgroups. Keep actual GitHub cancellation and slot-release acceptance separate from offline tests or inert process fixtures.

There are no placeholder signing or publishing jobs. After native smoke, collect the remaining platform and security evidence, obtain the independent signed release approval, and use the separate release tooling. A green workflow is not production or CIS certification.

References: [workflow dependencies, outputs and concurrency](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax), [runner-group public-repository permission](https://docs.github.com/en/rest/actions/self-hosted-runner-groups), [repository pull-request creation policy](https://docs.github.com/en/rest/repos/repos), [fork-workflow approvals](https://docs.github.com/en/rest/actions/permissions), [systemd IP filtering](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#IPAddressAllow=), and [Python isolated mode](https://docs.python.org/3/using/cmdline.html#cmdoption-I).
