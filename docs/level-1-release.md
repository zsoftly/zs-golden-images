# CIS Level 1 images and public releases

## CIS Level 1 evidence

Use the CIS Level 1 Server benchmark for the candidate OS. The audit pins identify [Debian 13 benchmark 1.1.0](https://www.cisecurity.org/benchmark/debian_linux) and [Ubuntu 26.04 LTS benchmark 1.0.0](https://www.cisecurity.org/benchmark/ubuntu_linux). Keep the benchmark material, assessment inventory, and supporting evidence in the private approval directory.

1. Build and boot the candidate on its intended platform in an isolated test environment. Record the artifact SHA-256 before testing.
2. Review the full Level 1 Server control inventory for the selected benchmark. Use the pinned audit for available VM checks and assess any omitted controls separately. Resolve failed applicable controls and repeat acceptance against the final image after any remediation or recapture.
3. Bind the inventory, results, and supporting files by SHA-256 in the signed approval. Submit one report under `checks.cis_coverage.evidence`. The release tool checks the report against the reviewed inventory. The reviewer must confirm that the inventory covers the benchmark and that the supporting evidence establishes each outcome.

The coverage report has `coverage: complete`, `raw_provenance: verified`, `promotion_allowed: true`, `target`, `artifact_sha256`, `control_inventory_sha256`, `benchmark`, and `controls`. The `benchmark` object has `family` (`CIS`), `profile` (the candidate OS slug), `version` (the pinned version), `level` (integer `1`), and `system_type` (`Server`). The hashed inventory has the same `benchmark` object and a `control_ids` list.

The `controls` object has one entry for each reviewed ID. Each result has `status` and `evidence_sha256`, which references supporting evidence in the signed approval. `passed` is the required result for applicable guest controls. Use `not_applicable` with a rationale and supporting evidence where a control does not apply. For LXC, `host_inherited` requires a rationale and evidence from the Proxmox host configuration tested with the image. An LXC assessment applies to that host configuration. The archive alone cannot establish host security on another cluster.

## Proxmox VM acceptance

The `proxmox-kvm` target uses diskimage-builder to create a QCOW2 disk. On a designated test Proxmox node, import that disk into a SeaBIOS VM and attach a NoCloud cloud-init drive. Set `ciupgrade=0` before the first boot of the acceptance clone so the assessment measures the packaged image. Test patching on a separate clone. Start the acceptance clone with a non-root user and an instance SSH public key. Verify boot, metadata, network configuration, guest-agent health, root SSH denial, and distinct clone identities. Record `proxmox_compatibility` evidence from that platform test. [Proxmox cloud-init guide](https://github.com/proxmox/pve-docs/blob/master/qm-cloud-init.adoc) · [Proxmox cloud-init implementation](https://github.com/proxmox/qemu-server/blob/master/src/PVE/QemuServer/Cloudinit.pm)

## GitHub Releases

Run publishing from the approved release environment with the authenticated GitHub CLI. Use the signed bundle created by [`release.py prepare`](../README.md#acceptance-signing-and-publication). Each asset must be smaller than 2 GiB. Public promotion checks that the repository has immutable releases enabled, which requires admin read access. [GitHub release asset limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas) · [GitHub immutable release setting](https://docs.github.com/en/rest/repos/repos#check-if-immutable-releases-are-enabled-for-a-repository)

1. Stage the versioned draft. The command sets the GitHub target to the signed source commit and uploads the image, `release.json`, `SHA256SUMS`, and `SHA256SUMS.asc`. It checks each asset's size and digest against GitHub's readback. Rerun with the same signed bundle to resume a partial draft. If GitHub reports an empty upload placeholder after a failed upload, remove that zero-byte asset from the draft before retrying. A conflicting tag or asset stops the command.

   ```bash
   GOLDEN_APPLY=publish python3 scripts/release.py publish-github "$RELEASE_DIR" \
     --signer "$SIGNER" --gpg-home "$GPG_HOME"
   ```

2. After approval to release publicly, designate one operator to publish the draft. Keep other editors and automation off that draft and its tag until verification finishes. GitHub exposes separate verification and publication requests and keeps drafts editable until publication. The command checks the bundle before publication and confirms the published tag, immutability, and assets afterwards. [GitHub release API](https://docs.github.com/en/rest/releases/releases) · [GitHub release asset API](https://docs.github.com/en/rest/releases/assets)

   ```bash
   GOLDEN_APPLY=publish python3 scripts/release.py publish-github "$RELEASE_DIR" \
     --signer "$SIGNER" --gpg-home "$GPG_HOME" --publish-draft
   ```

Each release tag includes the OS, target, and version. Download the four assets together and verify the bundle with the trusted signer before importing it. Use the same procedure for a retained version when rolling back.
