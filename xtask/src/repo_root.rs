// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Repository-root discovery for repository automation.
//!
//! Responsible for: finding, at runtime, the checkout an xtask invocation operates on.
//! NOT responsible for: reading anything under that root.
//! Upstream: every command that touches the tree. Downstream: the filesystem.
//!
//! The root used to be `env!("CARGO_MANIFEST_DIR")`, a compile-time constant. The guard self-test
//! compiles xtask inside a throwaway sandbox that shares `CARGO_TARGET_DIR` with the worktree, so
//! the binary a later run picked up still named the sandbox, and by then that directory was gone
//! (rustfs/gateway#393, #406). A path baked into a binary says where the binary was built, not
//! where it is running, so the root is discovered from the process's own environment every time.

use std::path::{Path, PathBuf};

/// The files that together mark a directory as this repository's root. `xtask/Cargo.toml` is in
/// the set so a crate that happens to carry an `AGENTS.md` and a manifest is not mistaken for it.
const ROOT_MARKERS: [&str; 3] = ["AGENTS.md", "Cargo.toml", "xtask/Cargo.toml"];

/// The repository root for this invocation.
///
/// Falls back to the working directory when nothing identifies a root, so a command run from
/// outside any checkout fails on the file it then cannot open rather than on a path it invented.
pub(crate) fn repo_root() -> PathBuf {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from);
    let cwd = std::env::current_dir().ok();
    discover(manifest_dir.as_deref(), cwd.as_deref()).unwrap_or_else(|| PathBuf::from("."))
}

/// Discovers the root from what the process was started with.
///
/// `manifest_dir` is the `CARGO_MANIFEST_DIR` cargo puts in the environment of a `cargo run` or
/// `cargo test` process: the manifest of the package being run, which for this binary is `xtask/`
/// inside the checkout cargo was invoked from. It is consulted first because it names that
/// checkout exactly, and it is ignored — not trusted, not repaired — when its parent is no longer
/// a root, which is what a deleted sandbox looks like. `cwd` is then walked upwards, which is how
/// a binary started without cargo finds the checkout it sits in.
pub(crate) fn discover(manifest_dir: Option<&Path>, cwd: Option<&Path>) -> Option<PathBuf> {
    if let Some(root) = manifest_dir.and_then(Path::parent).filter(|root| is_root(root)) {
        return Some(root.to_path_buf());
    }
    cwd?.ancestors().find(|dir| is_root(dir)).map(Path::to_path_buf)
}

fn is_root(dir: &Path) -> bool {
    ROOT_MARKERS.iter().all(|marker| dir.join(marker).is_file())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{ROOT_MARKERS, discover};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    /// A throwaway directory tree, removed when dropped.
    struct Tree(PathBuf);

    impl Tree {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "gateway-repo-root-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("temp tree");
            Tree(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        /// Makes `relative` look like a repository root.
        fn root(&self, relative: &str) -> PathBuf {
            let root = self.0.join(relative);
            for marker in ROOT_MARKERS {
                let file = root.join(marker);
                fs::create_dir_all(file.parent().expect("marker parent")).expect("marker dir");
                fs::write(&file, "").expect("marker file");
            }
            root
        }

        fn dir(&self, relative: &str) -> PathBuf {
            let dir = self.0.join(relative);
            fs::create_dir_all(&dir).expect("dir");
            dir
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_live_manifest_directory_names_the_checkout_it_sits_in() {
        let tree = Tree::new();
        let root = tree.root("checkout");
        let elsewhere = tree.root("other");

        assert_eq!(discover(Some(&root.join("xtask")), Some(&elsewhere)), Some(root));
    }

    #[test]
    fn a_working_directory_inside_the_checkout_walks_up_to_its_root() {
        let tree = Tree::new();
        let root = tree.root("checkout");
        let nested = tree.dir("checkout/crates/sig/src");

        assert_eq!(discover(None, Some(&nested)), Some(root));
    }

    #[test]
    fn a_deleted_sandbox_in_the_manifest_directory_does_not_poison_the_next_run() {
        // rustfs/gateway#393: the binary that a shared target directory hands to a later run may
        // still name a sandbox that no longer exists. That path must be ignored, not returned.
        let tree = Tree::new();
        let root = tree.root("checkout");
        let sandbox = tree.root("gateway-guard-test.dead");
        fs::remove_dir_all(&sandbox).expect("sandbox removed");

        assert_eq!(discover(Some(&sandbox.join("xtask")), Some(&root)), Some(root));
    }

    #[test]
    fn a_manifest_directory_whose_parent_is_not_a_root_is_ignored() {
        let tree = Tree::new();
        let root = tree.root("checkout");
        let crate_manifest = tree.dir("checkout/crates/sig");
        fs::write(crate_manifest.join("Cargo.toml"), "").expect("crate manifest");

        // `crates/` carries no root markers, so the working directory decides.
        assert_eq!(discover(Some(&crate_manifest), Some(&root)), Some(root));
    }

    #[test]
    fn a_manifest_and_a_rule_file_without_an_xtask_crate_are_not_a_root() {
        let tree = Tree::new();
        let lookalike = tree.dir("lookalike");
        fs::write(lookalike.join("AGENTS.md"), "").expect("agents");
        fs::write(lookalike.join("Cargo.toml"), "").expect("manifest");

        assert_eq!(discover(Some(&lookalike.join("xtask")), Some(&lookalike)), None);
    }

    #[test]
    fn nothing_to_discover_from_is_no_root() {
        let tree = Tree::new();
        let bare = tree.dir("bare/deeper");

        assert_eq!(discover(None, Some(&bare)), None);
        assert_eq!(discover(None, None), None);
        let _ = tree.path();
    }
}
