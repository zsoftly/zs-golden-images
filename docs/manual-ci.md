# Manual candidate builds

The manual workflow builds and inspects an experimental candidate. It does not run native smoke tests, sign or publish images, or import templates. Native smoke helpers retain their idle-runner requirement and run in a separately drained window.

The workflow accepts only an OS profile and target. It runs from `main` in this repository on the approved image-builder labels. It executes no checkout, third-party action, repository script from the job workspace, or upload step. Only generic success or failure text goes to GitHub. Artifact files, approved site inputs, source metadata and detailed logs remain in protected storage on the YOW builder. Profile and target selections and normal Actions job metadata are visible on GitHub.

## Root invocation boundary

The runner currently needs a separately approved invocation grant from the fleet owner. Installing this repository's dispatcher does not grant that permission and does not change sudoers, runner configuration, Docker, labels, or groups. Keep Actions disabled until the implementation, installed source and invocation boundary are reviewed and verified.

The fleet owner should allow only these four complete commands, without wildcards:

```text
/opt/zs-golden-images/bin/dispatch-candidate debian-13 cloudstack-kvm
/opt/zs-golden-images/bin/dispatch-candidate debian-13 proxmox-lxc
/opt/zs-golden-images/bin/dispatch-candidate ubuntu-26.04 cloudstack-kvm
/opt/zs-golden-images/bin/dispatch-candidate ubuntu-26.04 proxmox-lxc
```

The dispatcher rejects any other argument count or value. It uses isolated Python, discards stdin and the caller's environment, selects a fixed protected working directory and executable path, and verifies protected source and toolchain ownership. It never trusts GitHub environment variables as authorization.

The same operating-system runner account can serve another repository. Its processes could invoke any command granted to that account. The root-owned approval registry therefore binds every permitted build to an exact reviewed source commit, profile, target, version, private site file and expiry. Another process with this invocation permission can trigger the currently approved build and consume its version before the intended job. It cannot provide a command, change source, select a private URL, or read the resulting evidence through the dispatcher. The host's existing Docker access is a separate fleet security boundary; this dispatcher does not provide isolation from a caller that already controls host root.

## Operator setup

1. Review and merge the implementation. Deploy that exact commit to the existing protected checkout at `/opt/zs-golden-images/project`; never copy a runner workspace into it.
2. Use the existing bootstrap playbook with the private authorized inventory and `golden_builder_install_ci_dispatcher: true`. Its existing approval gates still apply. This installs a root-owned mode `0755` dispatcher, protected state directories and `/etc/zs-golden-images/ci.json`. It installs no privilege grant.
3. Verify the dispatcher hash against the reviewed file and verify that the checkout, dispatcher, Python environment, collections, native tools and their parent directories are root-owned and not writable by the runner. On invocation, the dispatcher rechecks its protected source and toolchain trees and system executable directories.
4. Through the private Ansible operational configuration, place one root-owned mode `0600` request in `/etc/zs-golden-images/ci-requests/PROFILE-TARGET.json`. The containing directory must remain root-owned mode `0700`. Do not commit the requests or site files.
5. Have the fleet owner review and install the separately approved exact-command invocation grant. Test rejection of extra arguments and unapproved, expired or mismatched requests before enabling the workflow.
6. After the operator approves activation, enable Actions and dispatch from `main`. A passing job means build and offline inspection passed, not image acceptance.

Each request contains exactly `profile`, `target`, `version`, `source_commit`, `site_path`, and `expires_at`. `source_commit` is the full reviewed commit installed in the protected checkout. `site_path` points to an existing root-owned private site JSON outside the checkout. `expires_at` is an integer UTC Unix timestamp, and must be in the future. The site file must contain the same version and the workspace from the installed builder identity. Use a new version for every attempt; the pipeline retains and rejects previous workspaces, including failed builds.

Example structure, deliberately expired until an operator replaces the approval fields:

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

The dispatcher reuses the Ansible egress probe before calling the existing `pipeline.sh`. The probe resolves official snapshot hosts through its private public resolver, rejects non-global addresses, verifies denied loopback access and successful signed metadata downloads, and records the exact restricted build command. DNS/CDN rotation fails closed; the code does not widen the allow-list. All transient units run under the existing fleet slice, whose 24 GiB high, 26 GiB maximum and 2 GiB swap limits are checked without modification. Per-build limits remain below that aggregate budget.

A native `pidwait` guard holds a verified pidfd for the dispatcher. Every probe and build unit binds its lifetime to that guard. Ansible itself runs inside an owned transient cgroup so its descendants cannot outlive that boundary. The dispatcher requests a parent-death signal, refuses an already-orphaned caller, and ignores repeated termination signals during cleanup. The guard cannot restart within its lifetime. Cleanup stops only owned units and verifies empty cgroups; the workflow does not stop or restart its own runner. Before activation, verify parent cancellation and forced dispatcher termination with inert workloads, including a delayed child. Record actual GitHub cancellation and job-slot release as unverified until an approved job confirms every owned unit has stopped.

Private evidence is under `/opt/zs-golden-images/ci/evidence/attempt-ci-*`, with probe evidence alongside it. Failures before an attempt directory exists require operator inspection of the approval, source or invocation boundary. Once a request succeeds, another invocation with the same approved version fails rather than replacing the artifact. Remove or expire approvals when they should no longer be callable.

References: [GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax), [systemd IP filtering](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#IPAddressAllow=), and [Python isolated mode](https://docs.python.org/3/using/cmdline.html#cmdoption-I).
