#!/usr/bin/env python3
"""Exercise the opt-in build boundary without loading a private dependency.

The private checkout is replaced by a local stand-in repository; nothing here contacts a remote.
"""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
FAKE_URL = "git@example.invalid:stand-in/rustfs-ucx.git"
# A developer's global hooks or signing configuration must not decide whether a fixture commits.
GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def git(cwd, *args):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
         "-c", "init.defaultBranch=main", *args],
        cwd=cwd, env=GIT_ENV, capture_output=True, text=True, check=True).stdout.strip()


class RdmaBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        (self.root / "rdma").mkdir()
        self.script = self.root / "scripts/build-rdma.sh"
        shutil.copyfile(REPO_ROOT / "scripts/build-rdma.sh", self.script)
        self.pin = self.root / "rdma/rustfs-ucx.rev"
        self.private = self.root / "vendor/rustfs-ucx"
        self.env = dict(os.environ)
        self.env.pop("RUSTFS_RDMA_TOOLCHAIN", None)
        self.env.pop("CARGO_BUILD_JOBS", None)
        self.env["GIT_CONFIG_GLOBAL"] = os.devnull
        self.env["GIT_CONFIG_NOSYSTEM"] = "1"
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        cargo = fake_bin / "cargo"
        cargo.write_text("#!/bin/sh\n[ \"${RUSTFS_PRIVATE_BUILD_PROBE:-}\" = enabled ] || exit 7\nprintf '%s\\n' \"$@\"\n")
        cargo.chmod(0o755)
        self.env["PATH"] = str(fake_bin) + os.pathsep + self.env["PATH"]

    def run_build(self, *args):
        return subprocess.run(["bash", str(self.script), *args], env=self.env,
                              capture_output=True, text=True, check=False)

    def write_pin(self, rev, url=FAKE_URL):
        self.pin.write_text(f"# fixture\nurl = {url}\nbranch = s3-rdma\nrev = {rev}\n")

    def prepare_private(self, *, pin=True):
        """Create a stand-in checkout with one commit; pin it unless told not to."""
        self.private.mkdir(parents=True)
        (self.private / "Cargo.toml").write_text('[package]\nname = "rustfs-ucx"\n')
        entry = self.private / "integrations/gateway/src/lib.rs"
        entry.parent.mkdir(parents=True)
        entry.write_text("// Fixture: only the build preflight reads this path.\n")
        (self.private / "scripts").mkdir()
        (self.private / "scripts/build-env.sh").write_text("export RUSTFS_PRIVATE_BUILD_PROBE=enabled\n")
        git(self.private, "init", "-q")
        git(self.private, "add", "-A")
        git(self.private, "commit", "-qm", "stand-in")
        head = git(self.private, "rev-parse", "HEAD")
        if pin:
            self.write_pin(head)
        return head

    def assert_refused(self, result, *fragments):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        for fragment in fragments:
            self.assertIn(fragment, result.stderr)

    # --- checkout state -------------------------------------------------------------------------

    def test_missing_checkout_prints_the_pinned_fetch_command(self):
        rev = "a" * 40
        self.write_pin(rev)
        result = self.run_build()
        self.assert_refused(result, "private checkout",
                            f"Run: git clone {FAKE_URL} {self.private} && "
                            f"git -C {self.private} checkout --detach {rev}")

    def test_empty_checkout_directory_is_treated_as_missing(self):
        self.write_pin("a" * 40)
        self.private.mkdir(parents=True)
        result = self.run_build()
        self.assert_refused(result, "Run: git clone")

    def test_checkout_at_the_pinned_commit_proceeds(self):
        self.prepare_private()
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[:2], ["+1.98.1", "build"])

    def test_checkout_at_another_commit_names_both_commits(self):
        pinned = self.prepare_private()
        (self.private / "later.txt").write_text("moved on\n")
        git(self.private, "add", "-A")
        git(self.private, "commit", "-qm", "later")
        actual = git(self.private, "rev-parse", "HEAD")
        self.assertNotEqual(actual, pinned)
        result = self.run_build()
        self.assert_refused(result, actual, pinned, "rdma/rustfs-ucx.rev pins")

    def test_pin_of_another_commit_is_refused_even_when_files_are_complete(self):
        actual = self.prepare_private(pin=False)
        other = "0123456789abcdef0123456789abcdef01234567"
        self.write_pin(other)
        result = self.run_build()
        self.assert_refused(result, actual, other)

    def test_plain_directory_inside_an_enclosing_repository_is_refused(self):
        # The enclosing repository's HEAD must never stand in for the private checkout's.
        git(self.root, "init", "-q")
        (self.root / "outer.txt").write_text("gateway stand-in\n")
        git(self.root, "add", "outer.txt")
        git(self.root, "commit", "-qm", "outer")
        self.write_pin(git(self.root, "rev-parse", "HEAD"))
        self.private.mkdir(parents=True)
        (self.private / "Cargo.toml").write_text('[package]\nname = "rustfs-ucx"\n')
        result = self.run_build()
        self.assert_refused(result, "not a git checkout of its own")

    def test_checkout_without_a_commit_is_refused(self):
        self.write_pin("a" * 40)
        self.private.mkdir(parents=True)
        (self.private / "Cargo.toml").write_text('[package]\nname = "rustfs-ucx"\n')
        git(self.private, "init", "-q")
        result = self.run_build()
        self.assert_refused(result, "no commit", "a" * 40)

    def test_partial_checkout_is_rejected(self):
        self.prepare_private()
        shutil.rmtree(self.private / "integrations")
        self.assert_refused(self.run_build(), "private checkout")

    def test_entry_without_manifest_is_rejected(self):
        self.prepare_private()
        (self.private / "Cargo.toml").unlink()
        self.assert_refused(self.run_build())

    def test_missing_private_build_environment_is_rejected(self):
        self.prepare_private()
        (self.private / "scripts/build-env.sh").unlink()
        self.assert_refused(self.run_build())

    # --- pin file -------------------------------------------------------------------------------

    def test_missing_pin_file_is_refused(self):
        self.prepare_private(pin=False)
        self.assert_refused(self.run_build(), "rdma/rustfs-ucx.rev is missing")

    def test_abbreviated_rev_is_refused(self):
        head = self.prepare_private(pin=False)
        self.write_pin(head[:12])
        self.assert_refused(self.run_build(), "40-character")

    def test_uppercase_rev_is_refused(self):
        head = self.prepare_private(pin=False)
        self.write_pin(head.upper())
        self.assert_refused(self.run_build(), "40-character")

    def test_pin_without_rev_is_refused(self):
        self.prepare_private(pin=False)
        self.pin.write_text(f"url = {FAKE_URL}\n")
        self.assert_refused(self.run_build(), "40-character")

    def test_pin_without_url_is_refused(self):
        head = self.prepare_private(pin=False)
        self.pin.write_text(f"rev = {head}\n")
        self.assert_refused(self.run_build(), "no 'url = '")

    def test_duplicate_rev_is_refused(self):
        head = self.prepare_private(pin=False)
        self.pin.write_text(f"url = {FAKE_URL}\nrev = {head}\nrev = {head}\n")
        self.assert_refused(self.run_build(), "more than once")

    def test_unknown_pin_line_is_refused(self):
        head = self.prepare_private(pin=False)
        self.pin.write_text(f"url = {FAKE_URL}\nrev = {head}\ncommit = {head}\n")
        self.assert_refused(self.run_build(), "rdma/rustfs-ucx.rev:3")

    def test_committed_pin_file_is_well_formed(self):
        # The real pin must parse: with no checkout present, the script must reach the fetch
        # instruction and print the recorded commit, not stop at a malformed pin.
        shutil.copyfile(REPO_ROOT / "rdma/rustfs-ucx.rev", self.pin)
        recorded = [line.split(" = ", 1)[1] for line in self.pin.read_text().splitlines()
                    if line.startswith("rev = ")]
        self.assertEqual(len(recorded), 1)
        self.assert_refused(self.run_build(), "Run: git clone", f"checkout --detach {recorded[0]}")

    # --- build invocation -----------------------------------------------------------------------

    def test_opt_in_preserves_arguments_and_uses_separate_manifest(self):
        self.prepare_private()
        result = self.run_build("--release", "--offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["+1.98.1", "build", "--manifest-path",
            str(self.root / "rdma/Cargo.toml"), "--features", "rdma", "-j", "2",
            "--release", "--offline"])

    def test_toolchain_and_parallelism_are_explicit(self):
        self.prepare_private()
        self.env["RUSTFS_RDMA_TOOLCHAIN"] = "stable"
        self.env["CARGO_BUILD_JOBS"] = "3"
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[0], "+stable")
        self.assertEqual(result.stdout.splitlines()[-2:], ["-j", "3"])


if __name__ == "__main__":
    unittest.main()
