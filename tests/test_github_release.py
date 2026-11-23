"""Exercise GitHub publishing against an offline release API fixture."""

import argparse
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_release import release


class GitHubReleaseTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.directory = Path(scratch.name)
        self.commit = "a" * 40
        self.tag = "zs-debian-13-proxmox-kvm-20261123"
        self.artifact = self.tag + ".qcow2"
        self.files = (self.artifact, "release.json", "SHA256SUMS", "SHA256SUMS.asc")
        for name in self.files:
            (self.directory / name).write_text(name)
        self.release_data = {"profile": "debian-13", "target": "proxmox-kvm", "version": "20261123",
                             "source_commit": self.commit, "artifact": {"path": self.artifact},
                             "cis_level_1": release.cis_benchmark("debian-13")}
        self.args = argparse.Namespace(directory=self.directory, signer="B" * 40,
                                       gpg_home=self.directory, publish_draft=False)
        self.remote = None
        self.tag_sha = None
        self.immutable_enabled = True
        self.assets = []
        self.writes = []
        for target, method in (("verify_release", lambda *_: self.release_data),
                               ("github_api", self.api), ("github_list", self.list_remote), ("run", self.run_command)):
            mock = patch.object(release, target, side_effect=method)
            mock.start()
            self.addCleanup(mock.stop)
        environment = patch.dict(os.environ, {"GOLDEN_APPLY": "publish"})
        environment.start()
        self.addCleanup(environment.stop)

    def api(self, endpoint, *flags):
        if endpoint == "immutable-releases":
            return {"enabled": self.immutable_enabled}
        if endpoint == f"commits/{self.commit}":
            return {"sha": self.commit}
        if endpoint == f"git/matching-refs/tags/{self.tag}":
            return [{"ref": f"refs/tags/{self.tag}", "object": {"type": "commit", "sha": self.tag_sha}}] \
                if self.tag_sha else []
        if endpoint == "releases" and flags[:2] == ("-X", "POST"):
            self.assertIn(f"target_commitish={self.commit}", flags)
            self.assertIn(f"tag_name={self.tag}", flags)
            self.assertIn("draft=true", flags)
            self.writes.append("create draft")
            self.remote = {"id": 1, "draft": True, "tag_name": self.tag, "target_commitish": self.commit}
            return self.remote
        if endpoint == "releases/1" and flags[:2] == ("-X", "PATCH"):
            self.assertIn("draft=false", flags)
            self.writes.append("publish draft")
            self.remote["draft"] = False
            self.remote["immutable"] = self.immutable_enabled
            self.tag_sha = self.commit
            return self.remote
        self.fail(f"Unexpected API request: {endpoint} {flags}")

    def list_remote(self, endpoint):
        if endpoint == "releases":
            return [self.remote] if self.remote else []
        self.assertEqual(endpoint, "releases/1/assets")
        return self.assets

    def run_command(self, argv):
        if argv[:2] == ["git", "check-ref-format"]:
            self.assertEqual(argv[2], f"refs/tags/{self.tag}")
            return
        self.assertEqual(argv[:4], ["gh", "release", "upload", self.tag])
        self.assertEqual(argv[-2:], ["--repo", "github.com/zsoftly/zs-golden-images"])
        asset = argv[4]
        self.writes.append(asset.name)
        self.assets.append({"name": asset.name, "state": "uploaded", "size": asset.stat().st_size,
                            "digest": f"sha256:{release.digest(asset)}"})

    def publish(self):
        with redirect_stdout(io.StringIO()):
            release.publish_github(self.args)

    def test_staging_and_retry_keep_a_verified_draft(self):
        self.publish()
        self.assertTrue(self.remote["draft"])
        self.assertEqual(self.writes, ["create draft", *self.files])
        self.writes.clear()
        self.publish()
        self.assertEqual(self.writes, [])

    def test_explicit_publication_reads_back_the_asset_set_and_commit(self):
        self.publish()
        self.args.publish_draft = True
        self.writes.clear()
        self.publish()
        self.assertFalse(self.remote["draft"])
        self.assertEqual(self.writes, ["publish draft"])
        self.writes.clear()
        self.publish()
        self.args.publish_draft = False
        with self.assertRaisesRegex(ValueError, "already public"):
            self.publish()
        self.assertEqual(self.writes, [])

    def test_missing_conflicting_and_tampered_assets_block_publication(self):
        self.publish()
        self.args.publish_draft = True
        self.writes.clear()
        expected = self.assets.copy()
        for assets, reason in ((expected[:-1], "missing verified assets"),
                               ([*expected, {"name": "private-audit.json"}], "Unexpected"),
                               ([{**expected[0], "digest": "sha256:" + "f" * 64}, *expected[1:]], "digest mismatch")):
            with self.subTest(reason=reason):
                self.assets = assets
                with self.assertRaisesRegex(ValueError, reason):
                    self.publish()
        self.assertEqual(self.writes, [])

    def test_guardrails_reject_unapproved_oversize_and_conflicting_tag_without_writes(self):
        with patch.dict(os.environ, {"GOLDEN_APPLY": ""}):
            with self.assertRaisesRegex(ValueError, "GOLDEN_APPLY"):
                self.publish()
        with patch.object(release, "GITHUB_MAX_ASSET", len(self.artifact)):
            with self.assertRaisesRegex(ValueError, "smaller than 2 GiB"):
                self.publish()
        self.tag_sha = "b" * 40
        with self.assertRaisesRegex(ValueError, "different source commit"):
            self.publish()
        self.release_data.pop("cis_level_1")
        with self.assertRaisesRegex(ValueError, "CIS Level 1"):
            self.publish()
        self.assertEqual(self.writes, [])

    def test_publication_requires_repository_immutability(self):
        self.publish()
        self.args.publish_draft = True
        self.immutable_enabled = False
        self.writes.clear()
        with self.assertRaisesRegex(ValueError, "Enable GitHub immutable releases"):
            self.publish()
        self.assertEqual(self.writes, [])

    def test_empty_upload_placeholder_requires_review_before_retry(self):
        self.publish()
        self.assets[0] = {"name": self.artifact, "size": 0, "state": "starter"}
        self.writes.clear()
        with self.assertRaisesRegex(ValueError, "empty upload placeholder"):
            self.publish()
        self.assets.pop(0)
        self.publish()
        self.assertEqual(self.writes, [self.artifact])
