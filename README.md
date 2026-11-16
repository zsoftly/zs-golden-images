# zs-golden-images

One image project for Debian 13 and Ubuntu 26.04 LTS, using OpenStack diskimage-builder for CloudStack/KVM disks and LXC distrobuilder for Proxmox LXC archives. Ansible provides shared operating-system configuration and target-specific hardening.

The active pipeline targets a dedicated, isolated bare-metal builder and does not allocate production Proxmox capacity. The manual CI workflow separates preflight, build, inspection and native smoke testing. Each installation requires its own approved host, invocation permissions and live verification; a passing candidate pipeline does not approve publication or production templates.

## Common pipeline

`Source → Build → Configure → Harden → Test → Sign/Checksum → Publish`

Upstream builders assemble the disk or root filesystem. Project scripts select inputs, call those tools and Ansible, record evidence, and enforce release gates. The repository does not implement another image-building engine.

- `cloudstack-kvm`: a BIOS/MBR QCOW2 VM disk with cloud-init and VM-specific packages and controls.
- `proxmox-lxc`: a root filesystem archive with container-specific packages and exclusions. Use `rootfs.tar.xz` for Proxmox; the upstream companion metadata archive is not the Proxmox template.
- `debian-13` and `ubuntu-26.04`: explicit profiles used throughout the pipeline, provenance, and acceptance evidence.

Version artifacts by OS profile, target, and release identifier. Keep approved versions immutable and retain the prior approved version for rollback. Test rollback by provisioning from that retained artifact, including signature and checksum verification.

A fixed tool version and source checksum do not freeze package repositories. Record approved mirror or snapshot inputs and package versions. Treat byte-for-byte reproducibility as unverified until repeated builds establish it.

## Offline validation

Use Python 3.12 or newer with Bash, jq, ripgrep, ShellCheck, and GnuPG available through your workstation tooling. Install the pinned Python validation dependencies once, then run the offline checks:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
./scripts/validate.sh
```

The default checks shell syntax, ShellCheck, Ansible syntax, YAML/JSON/Jinja parsing, Python syntax and unit tests, audit-report cases, and whitespace. It does not install builder dependencies, contact infrastructure, or build an image. Packer is optional:

```bash
./scripts/validate.sh --legacy
```

The optional legacy check validates Packer formatting and syntax without downloading plugins. Run the same required offline checks before a pull request and include DCO sign-offs on commits. Before activating GitHub Actions, review the dedicated builder, staged dispatcher, fleet invocation grant and repository security settings.

## Builder inputs and commands

The active entry point is [scripts/pipeline.sh](scripts/pipeline.sh). Select one OS profile and one target. Keep a private JSON input file outside the checkout with exactly these fields:

- `version`: a release identifier in `YYYYMMDD` or `YYYYMMDD-revision` form.
- `workspace`: the root-owned dedicated workspace recorded by the Ansible bootstrap. It must be an existing absolute path, at least three components deep, without symlinks or group/other write permission.
- `mirror_url` and `security_mirror_url`: approved HTTPS repository roots ending with the selected snapshot identifier. Ubuntu uses the same root for both fields. Debian permits a separate security mirror.
- `snapshot_id`: the immutable repository snapshot identifier, formatted as `YYYYMMDDTHHMMSSZ`.
- `source_date_epoch`: the positive integer Unix timestamp matching `snapshot_id`, recorded for the build.
- `inrelease_sha256`: an object containing lowercase SHA256 values for `base`, `updates`, and `security` repository metadata. Establish these through the approved source-verification process before use.

The profile selects `trixie`, `trixie-updates`, and `trixie-security` for Debian, or `resolute`, `resolute-updates`, and `resolute-security` for Ubuntu. Bootstrap installs both distribution archive keyrings. Builds require the selected keyring, verify pinned InRelease signatures with `gpgv`, and supply explicit trusted keys to both upstream builders. DIB also forces debootstrap signature verification. A timestamp in a URL does not prove the server preserves immutable content. Builds permit expired `Valid-Until` dates for the explicitly pinned historical snapshot. Package signature verification and pre/post-build InRelease signature and hash checks remain enabled. Cleanup removes this build-only expiry exception and restores normal signed update repositories for guest runtime.

Set `SITE` to the absolute private input path. Validation checks inputs without downloading sources or contacting infrastructure:

```bash
./scripts/pipeline.sh validate debian-13 cloudstack-kvm "$SITE"
./scripts/pipeline.sh validate debian-13 proxmox-lxc "$SITE"
```

Use `ubuntu-26.04` with its own matching input file. After the dedicated builder handoff and explicit live-build approval, set `CHECKOUT` to the approved absolute path of a root-owned, clean committed checkout on that host. Keep the checkout and its parent directories protected from writes by other users. Run as root:

```bash
cd -- "$CHECKOUT"
GOLDEN_APPLY=build ./scripts/pipeline.sh build debian-13 cloudstack-kvm "$SITE"
```

The active builder requires an amd64 Linux host, root, the Ansible-installed dedicated-builder marker, and native debootstrap support for the selected release. It refuses Proxmox hosts, serializes builds with a lock, and creates a new workspace for each profile, target, and version. Existing version workspaces are retained and rejected, including failed attempts; inspect them before separately authorized cleanup.

The pipeline rechecks repository metadata, records source and builder inputs, and produces a candidate manifest beside the artifact. Bootstrap installs hash-locked Python dependencies and SHA256-pinned Ansible collection archives. Each build checks the reviewed locks, installed Python inventory, installed collection contents, and builder executable hashes against the recorded toolchain. VM builds select classic sudo through a private build path and verify that `sudo -E` preserves the required build variables; the host's sudo alternative and policy stay unchanged. That toolchain record is included in candidate provenance. A completed candidate exits with status `2` because live compatibility and security acceptance remain outstanding. Status `0` from input validation is not an image-build result. No pipeline build command signs, publishes, or imports a production template.

## Development and operational boundary

The optional [manual CI workflow](docs/manual-ci.md) runs preflight, build, inspect and native smoke jobs through a root-owned approval registry. Protected stage receipts permit retries without rebuilding a verified candidate. Installing its dispatcher does not grant runner privileges or enable Actions; the staged interface requires fleet review of all 16 exact commands before activation.

Continue code, unit tests, static checks, Ansible roles, and setup documentation while infrastructure preparation is pending. The infrastructure owner supplies the dedicated server, private inventory, workspace filesystem, isolated network, and verified access. Obtain approval after that handoff before installing the builder or starting live image builds.

Keep site configuration, credentials, raw audits, build logs, and acceptance evidence outside this public checkout. Generic images contain no organization staff keys, enrollment credentials, or enrolled Wazuh identity. Managed enrollment and access policy belong to authorized provisioning; customer images require customer-supplied settings or an explicit managed-service agreement.

The retained Packer implementation appears below as a legacy path. It is not a dependency of the new pipeline.

## Ansible builder setup

The infrastructure owner must provide a dedicated amd64 bare-metal Debian 13 or Ubuntu 26.04 host, an existing protected workspace, isolated networking, and verified SSH access. The bootstrap requires the workspace and its parent directories to be root-owned and protected before installation. It installs pinned tools and writes a dedicated-builder marker. It does not create the workspace, format disks, configure the network, or enable GitHub Actions.

Set `INVENTORY` and `BUILDER_VARS` to absolute private paths. The inventory group is `golden_builders`; the variables must identify the approved dedicated workspace and set `golden_builder_approved: true` and `golden_builder_region: yow`. The marker reflects the current deployment boundary. An approval variable is not a substitute for operator authorization.

```bash
export ANSIBLE_ROLES_PATH="$PWD/ansible/roles"
ansible-playbook -i "$INVENTORY" -e "@$BUILDER_VARS" --list-hosts ansible/playbooks/20-bootstrap-builder.yml
ansible-playbook -i "$INVENTORY" -e "@$BUILDER_VARS" --syntax-check ansible/playbooks/20-bootstrap-builder.yml
```

Inspect the host list before installation. The bootstrap rejects check mode because its tool installation cannot provide a reliable simulation. After the server handoff and installation approval:

```bash
GOLDEN_APPLY=bootstrap ansible-playbook -i "$INVENTORY" -e "@$BUILDER_VARS" ansible/playbooks/20-bootstrap-builder.yml
```

Do not repurpose production Proxmox hosts. Keep temporary root filesystems, disks, caches, artifacts, test guests, and evidence on the dedicated allocation. Begin with one active build or acceptance test. Verify network isolation and capacity before live execution.

## Configuration, hardening, and runtime checks

Both upstream builders call the same guarded Ansible rootfs adapter for `configure`, `harden`, and `cleanup`. The adapter is a build hook, not a general command for modifying arbitrary host directories. It requires the dedicated workspace and matching source metadata.

The LXC path runs all three phases in a private mount namespace with selected device nodes, proc, read-only sysfs, and a temporary `/run`. The wrapper unmounts them on exit before distrobuilder packs the root filesystem. Mount behavior still requires validation during the first authorized Linux build.

Ansible owns the VM datasource list: `CloudStack`, `ConfigDrive`, and `None`. The DIB configuration does not add a competing datasource list. Verify both CloudStack metadata delivery paths during live acceptance.

The offline hardening role writes an explicit `offline-l1-subset` record. It configures key-based SSH, local password policy, root password locking, default permissions, account-file permissions, core-dump limits, and VM-only kernel settings. Filesystem layout, firewall policy, audit rules, bootloader policy, account lockout, and full benchmark mapping still require separate coverage. Password-history enforcement is configured but requires runtime verification. Container host-owned controls are recorded as such. This baseline does not claim a complete CIS Level 1 implementation.

In-image provenance and hardening records use `acceptance_source: signed-release-metadata`; release acceptance is recorded outside the immutable image. The hardening record's `cis_complete: false` describes the offline subset's coverage. It does not override a later signed release assessment. Candidate manifests and experimental audit reports still block promotion until their separate acceptance gates pass.

Cleanup captures package versions, removes build identities and temporary state, resets machine identity, and prepares unique SSH host keys on first boot. It removes inherited resolver contents and DIB's resolver backup. VM cleanup also removes `/etc/.resolv.conf.systemd-resolved.bak` and `/run/systemd/resolve/stub-resolv.conf`, which package installation can populate with builder DNS settings. VM artifacts retain a resolver symlink to the stub generated at runtime; LXC archives contain an empty regular `/etc/resolv.conf` for Proxmox provisioning. Resolver generation and DNS after provisioning still require live acceptance. The adapter removes `/root/.ansible` after Ansible finishes its cleanup phase.

Cleanup replaces private build snapshot sources with signed public distribution update repositories in the final image. The pinned build package selection therefore differs from the intentionally current repositories used for later guest patching.

Runtime playbooks operate only on explicitly authorized `golden_candidates` inventory entries. They are held until the dedicated environment is ready and live work is approved. Set `RUNTIME_INVENTORY` and `RUNTIME_VARS` to private files naming the exact disposable guests and target policy:

```bash
GOLDEN_APPLY=verify ansible-playbook -i "$RUNTIME_INVENTORY" -e "@$RUNTIME_VARS" ansible/playbooks/40-verify-runtime.yml
```

The runtime variables include `golden_runtime_approved`, `golden_profile`, `golden_target`, and `golden_enrollment_policy` (`public` or `managed`). Public-policy checks require no captured Wazuh identity. Managed-policy checks require separately provisioned enrollment, local agent health, and TLS-verified manager confirmation for the selected agent. Supply the private manager URL, agent ID, and token through the approved secret mechanism; the playbook does not enroll the agent.

For LXC, per-instance administrator provisioning must verify a fresh non-root SSH connection and selected sudo permissions before disabling temporary root-key access. The [LXC administrator playbook](ansible/playbooks/45-provision-lxc-admin.yml) accepts private per-instance key, host-trust, username, and sudo-policy inputs. No employee key is built into the generic archive.

The [runtime VM remediation playbook](ansible/playbooks/50-remediate-vm.yml) provides a separate guarded path for a pinned upstream CIS role on an authorized disposable KVM candidate. It requires reviewed control selections, explicit exceptions, tested recovery access, firewall review, matching benchmark identity, and an unmodified pinned role checkout. Level 2 and embedded audits are disabled. It does not run during offline assembly and does not support LXC. Any runtime mutation requires reboot, a fresh audit, sanitization, recapture, and acceptance of the resulting artifact before release; an approval for the earlier disk cannot cover it.

Prepare the pinned role into a new absolute `ROLE_DIR` outside the checkout without executing it:

```bash
./scripts/prepare-remediation.sh debian-13 "$ROLE_DIR"
```

After live remediation approval, the private runtime variables must supply the role directory, benchmark version, reviewed rule settings and exceptions, recovery-test reference, and firewall-review confirmation. The playbook requires an explicit decision for rule `5_2_4` and a reason for each disabled selected rule. Review the pinned role's other defaults before execution. Run the guarded adapter on the configured builder/controller; it supplies the required `level1-server` tag and the Ansible collection search path. Both private paths must be absolute:

```bash
GOLDEN_APPLY=remediate ./scripts/run-remediation.sh "$RUNTIME_INVENTORY" "$RUNTIME_VARS"
```

## Native candidate smoke tests

The [native smoke helpers](tests/native/README.md) boot disposable candidates on the approved dedicated builder using QEMU/KVM or native LXC. They reuse the runtime Ansible playbooks, preserve the original artifact, and write private evidence for boot, administrative access, restart and identity checks. Their private site file supplies the protected workspace, evidence directory, builder marker, tool prefix and exact runner service. Direct manual runs require that runner to be drained; the staged dispatcher provides a separately guarded CI ownership path.

These tests do not import templates, enable Actions, or establish CloudStack or Proxmox integration acceptance. Platform, networking, security and release gates remain separate. The ordinary offline validation suite exercises harness safety with mocks and archive fixtures; it never starts a guest.

## Acceptance, signing, and publication

[scripts/release.py](scripts/release.py) keeps offline structure checks, acceptance approval, signing, publication, and platform import distinct. Set `CANDIDATE` to the pipeline's candidate manifest:

```bash
python3 scripts/release.py inspect "$CANDIDATE"
```

This validates artifact checksums and format-specific structure, not successful boot or compatibility. VM inspection requires `qemu-img`. LXC inspection checks the rootfs archive and captured identities, requires an empty regular `etc/resolv.conf`, and rejects a nonempty or nonregular `etc/resolv.conf.ORIG` if present.

An authorized reviewer must sign a private approval JSON after reviewing real acceptance evidence. The approval uses `schema_version: 1`, the exact `candidate_sha256` and `artifact_sha256`, an unexpired `expires` date, and an `evidence` array of `{path, sha256}` entries. Each named check must have `status: passed` and an `evidence` array referring to those hashes. Evidence paths resolve relative to the approval file.

- Common checks: `boot`, `clone_identity`, `network`, `dns`, `time`, `ansible_idempotency`, `patching`, `reboot`, `workload`, `rollback`, `secret_scan`, `vulnerability_scan`, `cis_coverage`, `cis_remediation`, and `wazuh_readiness`.
- CloudStack checks: `cloud_init`, `guest_agent`, and `cloudstack_compatibility`.
- Proxmox LXC checks: `unprivileged_lxc`, `container_provisioning`, and `proxmox_compatibility`.
- `vulnerability_scan` metadata: scanner `tool` and `version`, `database_sha256`, `database_updated` date, and `report_sha256` bound to the check's evidence. The current gate requires a database no older than seven days and integer `critical: 0` and `high: 0` counts.
- Each item bound to `cis_coverage` must be a JSON object with `coverage: complete`, `raw_provenance: verified`, and `promotion_allowed: true`, regardless of its filename. List supporting manual artifacts separately and include their assessment in the complete coverage record.
- `secret_scan` must inspect `/etc/resolv.conf`, `/etc/resolv.conf.ORIG`, `/etc/.resolv.conf.systemd-resolved.bak`, and `/run/systemd/resolve/stub-resolv.conf` for inherited nameservers and search domains, including inside VM disks that format inspection does not mount.

Do not manufacture passing entries to exercise the release path. JSON evidence reporting incomplete coverage, unverified provenance, or blocked promotion prevents approval regardless of its filename or acceptance check. Text evidence carrying the audit adapter's matching blocked markers also prevents approval. Reviewers assess the evidence; the script verifies signatures, identities, hashes, required fields, and release policy. The existing experimental audit report alone cannot satisfy this gate.

Obtain the expected reviewer and signer fingerprints through the approved organizational process, independently of the candidate and its supplied signatures. They are trusted operator inputs: the CLI proves cryptographic binding to those keys, not organizational authorization or separation of duties. Protect the invoking account, keyring, and any automation supplying those arguments. Perform approval and signing in an approved release environment outside the builder; keep private review and signing keys off the builder.

Set `APPROVAL` and `APPROVAL_SIGNATURE` to the private reviewed document and detached signature, `REVIEWER` and `SIGNER` to full trusted OpenPGP fingerprints, and `GPG_HOME` to the private keyring. `RELEASE_DIR` must be a new absolute directory outside the checkout. After acceptance approval:

```bash
python3 scripts/release.py check "$CANDIDATE" "$APPROVAL" "$APPROVAL_SIGNATURE" --reviewer "$REVIEWER" --gpg-home "$GPG_HOME"
python3 scripts/release.py prepare "$CANDIDATE" "$APPROVAL" "$APPROVAL_SIGNATURE" "$RELEASE_DIR" --reviewer "$REVIEWER" --signer "$SIGNER" --gpg-home "$GPG_HOME"
python3 scripts/release.py verify "$RELEASE_DIR" --signer "$SIGNER" --gpg-home "$GPG_HOME"
```

Preparation copies the artifact and writes sanitized release metadata, `SHA256SUMS`, and a detached signature. Private raw audit and acceptance evidence are not included. Keep signing keys outside the source tree and images. Verify the independently trusted signer and checksums before every import, including rollback to an earlier approved version.

Publication remains held. The optional publisher requires a private destination JSON with exactly `endpoint_url`, `bucket`, `prefix`, `region`, `canada_storage_approved: true`, and `conditional_writes_verified: true`. Infra must verify the endpoint's Canadian storage policy, conditional writes, object versioning, and checksum upload/readback support. These flags record verified prerequisites; they do not establish them. Credentials use the AWS CLI's approved external credential configuration, never JSON fields or URLs.

After separate release/publication approval, set `DESTINATION` to that private file:

```bash
GOLDEN_APPLY=publish python3 scripts/release.py publish "$RELEASE_DIR" "$DESTINATION" --signer "$SIGNER" --gpg-home "$GPG_HOME"
```

The publisher creates a versioned path and refuses collisions. It uploads the signature last, reads back object versions and checksums, and never deletes partial uploads or updates a moving `latest` pointer. Consumers must verify the complete signed release before use. The current uploader accepts objects up to 5,000,000,000 bytes; larger artifacts require reviewed multipart support. Publication does not register CloudStack or Proxmox templates. Retention and any later cleanup remain explicit infrastructure decisions.

## Experimental audit adapter

The audit adapter runs separately from image assembly. It does not remediate the guest, reboot it, change SSH or sudo policy, or enroll an agent. It requests Level 1 server checks from pinned Ansible Lockdown audit content using Syver 0.15.1. Both upstream defaults enable Level 2, so the adapter explicitly forces Level 2 off. Heavy tests are disabled for the bounded pilot.

The Debian audit targets benchmark 1.1.0. The pinned Debian remediation candidate targets 1.0.0; running it does not establish coverage of benchmark 1.1.0. Ubuntu audit and remediation candidate declare 1.0.0. The offline build invokes neither remediation candidate. The separate runtime remediation playbook requires scoped authorization and review of its preliminary tasks and control selections before use. See [audit/pins.json](audit/pins.json) for exact commits, executable checksum, enforced variables, and omitted checks.

Prepare dependencies on a workstation into a new directory outside this checkout. `BUNDLE` must be an absolute path whose parent already exists. Preparation downloads upstream content and the Linux amd64 executable but runs neither. Failed preparation leaves its directory for inspection; retry with a new path.

```bash
./scripts/prepare-audit.sh debian-13 "$BUNDLE"
```

Copy the repository and bundle through your approved transfer process to a separately authorized disposable clone. The guest needs Bash, jq, Git, coreutils (`sha256sum`), and systemd (`systemd-detect-virt`), provisioned separately before auditing. The runner installs nothing. Keep the bundle owned by the auditing account. Run as root only inside the clone, using a new absolute `EVIDENCE` directory outside both trees:

```bash
GOLDEN_APPLY=audit ./scripts/audit-guest.sh debian-13 "$BUNDLE" "$EVIDENCE"
```

Repeat with `ubuntu-26.04` and a matching bundle. The runner checks the OS, KVM guest type, image provenance, audit commit, clean dependency tree, and executable checksum before executing checks with concurrency two. For the active pipeline, image provenance points to external acceptance metadata; it does not authorize the audit. The operator must identify an approved disposable clone. Never run this on an existing workload or a customer VM.

Some upstream checks have side effects. The adapter disables Debian 1.2.2.1 (`apt update`), Ubuntu 7.2.3 (fixed temporary-file writes), Ubuntu 1.1.1.11 (an external helper), and 5.4.2.5 on both profiles (login shell startup). These omissions remain visible in the report and require replacement evidence. Auditing also reads sensitive host configuration. Treat the whole evidence directory, including raw JSON and stderr, as private; directories use mode 0700 and files 0600. Keep it in approved storage and never upload it to the public repository.

The report provides JSON and text with returned-check counts, not benchmark-control coverage. Its profile, benchmark, and commit fields are labeled `requested_*`: standalone raw JSON has unverified provenance, so current pins cannot establish which software produced an older or externally supplied file. It distinguishes passed, failed, skipped, error, unknown, and excepted checks. `not_applicable` stays zero because this adapter has no evidence-based applicability classifier. Skipped checks never mean not applicable. Empty, malformed, duplicate, or inconsistent results are rejected. The parser uses Syver's result enum and error field, not its `successful` boolean.

Every current audit/report exits nonzero: 2 means evidence was produced with promotion blocked, and 1 means invalid input or an execution error. Even an all-pass result remains blocked until independent benchmark coverage, manual evidence, remediation, and guest acceptance are reviewed. An audit checks implementation outcomes; it is not certification.

To record an approved temporary build exception, rerun the report with a private JSON array. Each entry must name the exact `resource-type`, `resource-id`, and `property` from raw output, plus a nonempty `reason` and an unexpired `expires` date (`YYYY-MM-DD`). Only failed checks receive an `excepted` disposition; the original failed outcome remains recorded. Errors, unknowns, and skipped checks retain their outcomes. An exception never enables promotion. Do not grant blanket sudo/cloud-init exceptions: preserve build access during future remediation and review its final provisioned policy separately.

```bash
./scripts/report-audit.sh debian-13 "$EVIDENCE/raw.json" "$REPORT" "$EXCEPTIONS"
```

Upstream sources: [Debian audit](https://github.com/ansible-lockdown/DEBIAN13-CIS-Audit/tree/1a02e81f141c9b86a8620daee62dd07ec3634d0a), [Ubuntu audit](https://github.com/ansible-lockdown/UBUNTU26-CIS-Audit/tree/30675914e43b3d3821094c5f675d1baa993dc061), and [Syver 0.15.1](https://github.com/krameff/syver/releases/tag/v0.15.1). Downloaded projects retain their licenses and notices in the bundle.

## Acceptance still required

Before promotion, verify cloud-init identity uniqueness, SSH recovery, DNS, networking, time synchronization, guest-agent response, second-run Ansible idempotency, patching, reboot recovery, and workload compatibility on an isolated clone. Record provisioning duration and compare it with the current process. Test rollback by provisioning from a retained approved template. Add the selected CIS control implementation, complete independent audit coverage, documented exceptions, and managed enrollment gate before claiming the original security objective is complete.

The base contains no enrollment credentials or enrolled Wazuh identity. Public images must not automatically grant organization staff access or enroll into an organization's security manager.

## Legacy Packer path

The earlier Proxmox VM foundation is retained for reference and transition. It is outside the active upstream-builder pipeline and does not authorize production capacity or live operations. Its Ansible and audit work remain reusable.

1. Choose a dated vendor cloud image and verify its SHA256 against the vendor's authenticated checksum publication.
2. Reserve separate seed and final template VMIDs, storage, a build node, and an isolated network in your private infrastructure inventory.
3. Import the verified image with Ansible. The seed has no network interface or credentials and is never booted.
4. Packer makes a full clone, configures a temporary cloud-init identity, and runs the base Ansible playbook.
5. Guest cleanup removes machine identity, build keys, logs, generated network configuration, and cloud-init state. Packer stops the guest, removes build-time cloud-init settings, and converts it to a template.
6. Test a separate disposable clone before promotion. Reserve its ID independently of the seed and template IDs.

The seed remains available for later builds. Each build requires a new final template ID and version. The scripts never overwrite an existing ID or automatically delete a failed build. Inspect partial resources before any separately authorized cleanup.

### Legacy validation

Install Packer, Ansible, Bash, jq, curl, Git, and ShellCheck through your normal workstation tooling. Packer downloads the exact Proxmox and Ansible plugins declared in the build configuration.

```bash
packer fmt -check -recursive packer profiles
packer init packer/proxmox
packer validate -syntax-only packer/proxmox
```

These optional legacy checks validate Packer formatting and syntax. They do not connect to Proxmox, run playbooks on guests, or prove that an image boots.

### Legacy private inputs

Keep site configuration outside this public checkout. Supply a JSON object with exactly these keys:

- `proxmox_url`: trusted HTTPS API URL ending in `/api2/json`.
- `proxmox_username`: API token identity in `user@realm!token-id` form.
- `node`: one authorized Proxmox node, also resolvable in the seed-import Ansible inventory.
- `storage_pool`: storage for both seed and final template disks.
- `seed_cache_dir`: an existing root-owned cache parent on the node, at least three path components deep, with no group/other write permission or symlink components. The importer creates a private `zs-golden-images` child and never changes parent permissions. An existing child must carry this project's ownership marker and mode `0700`.
- `seed_vm_id`, `template_vm_id`: distinct reserved integer IDs. The build VM becomes the final template with the same ID.
- `bridge`, `vlan_tag`: an explicitly approved isolated bridge and VLAN, with required package-mirror egress and build-runner SSH access.
- `cpu_type`: a portable `x86-64-v2`, `x86-64-v2-AES`, `x86-64-v3`, or `x86-64-v4` model supported by the node and selected vendor image. Validate CPU compatibility before building or migrating.
- `ip_address`: reserved build address with CIDR prefix.
- `gateway`, `nameserver`: addresses reachable from that network.
- `ssh_host`: the same reserved build guest address, reachable from the runner.
- `source_image_url`: a dated Debian trixie or Ubuntu resolute vendor image URL. Moving `latest`, `current`, and `release` paths are rejected.
- `source_image_sha256`: verified lowercase 64-character SHA256 digest.
- `image_version`: `YYYYMMDD` or `YYYYMMDD-revision`.

Select `debian-13` or `ubuntu-26.04` as the command's profile. The profile sets the expected OS and cloud username. The build rejects an OS/profile mismatch after boot. Use amd64 cloud disk images, not LXC archives, ARM images, or installer ISOs.

The runner must trust the Proxmox API certificate. TLS verification is never disabled. Supply `PROXMOX_TOKEN` through your credential provider only when building, not inside JSON or a command argument. Seed import uses the explicit Ansible inventory and its existing secure authentication. Do not enable Packer debug logging: it can write the temporary private SSH key.

Packer creates an ephemeral SSH key and injects its public key through cloud-init. Its initial guest SSH connection does not establish a pretrusted host-key identity. Keep this phase inside the approved isolated build network; do not expose the build guest on an untrusted network. Establish managed host trust when provisioning accepted clones.

The pilot is capped at 2 vCPUs, 2 GiB RAM, and a 16 GiB root disk. Guests do not start automatically with the host. Clones retain the seed's disk storage; the build preflight checks that it matches `storage_pool`.

### Legacy commands

Set `SITE` to your absolute private JSON path. Set `INVENTORY` to your authorized Ansible inventory path. These paths must be supplied by the operator.

```bash
./scripts/build.sh validate debian-13 "$SITE"
GOLDEN_APPLY=seed ./scripts/build.sh seed debian-13 "$SITE" "$INVENTORY"
GOLDEN_APPLY=build ./scripts/build.sh build debian-13 "$SITE"
```

Repeat with `ubuntu-26.04` and its separately reserved IDs and vendor disk. Live operations require a clean committed checkout. Validation allows an uncommitted checkout and uses its current HEAD only to validate the commit format. `validate` downloads missing Packer plugins but performs no infrastructure writes. Seed import cannot provide a reliable Ansible check-mode simulation and rejects check mode.

The source commit, vendor URL, checksum, and package versions are recorded inside the image. Packer writes a local manifest under ignored `artifacts/`. Package updates use the vendor repositories at build time, so this is a repeatable process with captured package versions, not a byte-for-byte reproducible package snapshot.

## References and license

- [diskimage-builder documentation](https://docs.openstack.org/diskimage-builder/latest/) and [Apache-2.0 license](https://github.com/openstack/diskimage-builder/blob/master/LICENSE)
- [distrobuilder build commands](https://linuxcontainers.org/distrobuilder/docs/latest/howto/build/) and [Apache-2.0 license](https://github.com/lxc/distrobuilder/blob/main/COPYING)
- [S3 conditional uploads and checksums](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-object.html)
- [S3 object verification](https://docs.aws.amazon.com/cli/latest/reference/s3api/head-object.html)
- [GnuPG signing and verification](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html)
- [QEMU image inspection](https://www.qemu.org/docs/master/tools/qemu-img.html)
- [Packer Proxmox clone builder](https://developer.hashicorp.com/packer/integrations/hashicorp/proxmox/latest/components/builder/clone)
- [Proxmox VM command reference](https://pve.proxmox.com/pve-docs/qm.1.html)
- [Debian trixie cloud images](https://cloud.debian.org/images/cloud/trixie/)
- [Ubuntu resolute cloud images](https://cloud-images.ubuntu.com/releases/resolute/)
- [Cloud-init cleanup command](https://cloudinit.readthedocs.io/en/latest/reference/cli.html#clean)
- [Systemd journal cleanup](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html#--relinquish-var)

Project-owned code is licensed under Apache-2.0. See [LICENSE](LICENSE). OS packages and external plugins retain their own licenses. This repository does not redistribute CIS benchmarks, CIS-CAT, or CIS Build Kits.
