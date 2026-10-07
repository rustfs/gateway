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

//! The RustFS profile's posture, pinned to a golden (rustfs/backlog#2751).
//!
//! Responsible for: that a service assembled with `ServiceBuilder::rustfs_profile` and
//! `SigV4Authenticator::rustfs_profile` over the reference filesystem backend reports exactly the
//! posture `golden/rustfs-profile-posture.txt` holds — every start-up line, then the security
//! posture — and that the golden tells the profile apart from the same backend assembled without
//! it.
//! NOT responsible for: the preset's switch-by-switch census (`src/builder/rustfs_profile.rs`'s
//! unit suite), or that the client-matrix launcher assembles the same posture
//! (`compat/sut/src/service/tests/rustfs_profile_tests.rs`, which reads this golden).
//! Upstream: `rustfs-gateway`, `rustfs-gateway-fs`. Downstream: nothing.
//!
//! Regenerate deliberately, never reflexively, and say why in the pull request:
//!
//! ```bash
//! UPDATE_GOLDEN=1 cargo test -p rustfs-gateway --test integration rustfs_profile::
//! ```

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustfs_gateway::{
    Credentials, DenyAllAuthorizer, RegionSet, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials,
};
use rustfs_gateway_fs::FsBackend;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

/// A throwaway data root for the reference backend, removed when the case ends.
struct DataRoot(PathBuf);

impl DataRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rustfs-profile-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("a unique data root");
        Self(path)
    }
}

impl Drop for DataRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("the exact data root is removable");
    }
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/rustfs-profile-posture.txt")
}

/// The posture of `service`: the start-up report as logged, then the security posture, one line
/// each, every line newline-ended.
fn posture(service: &S3Service) -> String {
    format!("{}{}\n", service.startup_posture(), service.security_posture())
}

fn authenticator() -> SigV4Authenticator {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
    SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty"))
}

/// The reference backend over `root`, registered as the client-matrix launcher registers it —
/// every operation family it serves — with or without the two halves of the profile.
fn assembled(root: &DataRoot, profile: bool) -> S3Service {
    let backend = Arc::new(FsBackend::open(&root.0).expect("a usable data root"));
    let builder = ServiceBuilder::new().authorizer(DenyAllAuthorizer);
    let (builder, authenticator) = if profile {
        (builder.rustfs_profile(), authenticator().rustfs_profile())
    } else {
        (builder, authenticator())
    };
    let builder = backend.register_crud(builder.authenticator(authenticator));
    backend
        .register_cors(backend.register_encryption(backend.register_policy(backend.register_acl(
            backend.register_tagging(
                backend.register_lifecycle(
                    backend.register_listing(backend.register_versioning(backend.register_multipart(builder))),
                ),
            ),
        ))))
        .build()
        .expect("a complete assembly")
}

fn posture_line<'a>(report: &'a str, prefix: &str) -> &'a str {
    report
        .lines()
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("{prefix} is missing from:\n{report}"))
}

/// The profile's posture is the golden, verbatim. Change any switch of the preset and this diff
/// goes red.
#[test]
fn the_rustfs_profile_posture_matches_the_golden() {
    let root = DataRoot::new();
    let rendered = posture(&assembled(&root, true));
    let path = golden_path();
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("the golden directory");
        }
        fs::write(&path, &rendered).expect("write the golden");
        return;
    }
    let expected = fs::read_to_string(&path).expect("the golden exists; regenerate with UPDATE_GOLDEN=1");
    assert_eq!(
        rendered, expected,
        "the RustFS profile's posture changed. If that was intended, regenerate the golden and say why in the pull request."
    );
}

/// Negative — a golden nobody can break is not a guard: the same backend assembled without the
/// preset reports another posture on every line that carries a profile reading, names no legacy
/// switch at all, and writes no presigned-expiry line; and the golden names the one reading only
/// an assembled router can show.
#[test]
fn n_the_golden_tells_the_profile_from_the_default_assembly() {
    let root = DataRoot::new();
    let plain = posture(&assembled(&root, false));
    let expected = fs::read_to_string(golden_path()).expect("the golden exists; regenerate with UPDATE_GOLDEN=1");
    assert_ne!(plain, expected);
    for prefix in [
        "SECURITY_POSTURE ",
        "NAMING_POSTURE ",
        "PROFILE_POSTURE ",
        "credential negative cache: ",
    ] {
        assert_ne!(posture_line(&plain, prefix), posture_line(&expected, prefix), "{prefix}");
    }
    assert_eq!(posture_line(&plain, "PROFILE_POSTURE "), "PROFILE_POSTURE switches=[]");
    assert!(!plain.contains("PRESIGNED_EXPIRY_POSTURE"), "{plain}");
    assert!(expected.contains("\nPRESIGNED_EXPIRY_POSTURE rule=legacy-rustfs\n"), "{expected}");
    assert!(
        posture_line(&expected, "PROFILE_POSTURE ").contains(",select_operations_as_legacy_rustfs,"),
        "{expected}"
    );
    assert!(
        posture_line(&expected, "credential negative cache: ")
            .contains("unlimited pre-authentication layers: aggregate, credential lookup, CORS preflight, unauthenticated"),
        "{expected}"
    );
    assert!(!plain.contains("unlimited pre-authentication layers"), "{plain}");
}
