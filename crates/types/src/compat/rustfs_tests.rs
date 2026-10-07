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

//! Tests that pin the `s3s_rustfs` alias to RustFS main's own s3s declaration (rustfs/backlog#2759).
//!
//! Responsible for: proving the alias spells exactly the line RustFS main declares, so Cargo
//! unifies the two crates; that the feature behind it enables that alias alone, that the umbrella
//! includes it, and that no default feature does; that the alias pins a full commit of the upstream
//! repository; and that the seam it compiles is a compilation of its own, distinct from the release
//! seam's. NOT responsible for: what the seam converts (`compat/seam/*_tests.rs`). Upstream:
//! `super`. Downstream: none; test-only.

use std::any::TypeId;

/// RustFS main's own s3s declaration (rustfs/rustfs@6b155400 `Cargo.toml:324`).
const RUSTFS_MAIN_S3S: &str = r#"s3s = { git = "https://github.com/s3s-project/s3s", rev = "5761ddfe4c509fcac87e3b99fd5bd9e176b442c0", features = ["minio"] }"#;

const MANIFEST: &str = include_str!("../../Cargo.toml");

fn alias_line() -> &'static str {
    MANIFEST
        .lines()
        .find_map(|line| line.strip_prefix(r#"s3s_rustfs = { package = "s3s", "#))
        .expect("the s3s_rustfs alias is declared")
}

#[test]
fn the_alias_spells_rustfs_mains_own_s3s_line() {
    let theirs = RUSTFS_MAIN_S3S.strip_prefix("s3s = { ").expect("a RustFS dependency line");
    assert_eq!(alias_line().strip_suffix(", optional = true }"), theirs.strip_suffix(" }"));
}

#[test]
fn n_the_alias_pins_a_full_commit_of_the_upstream_repository_not_a_branch() {
    let line = alias_line();
    assert!(line.contains(r#"git = "https://github.com/s3s-project/s3s""#), "{line}");
    let rev = line
        .split(r#"rev = ""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a rev");
    assert_eq!(rev.len(), 40, "{line}");
    assert!(rev.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()), "{line}");
    assert!(!line.contains("branch = "), "{line}");
    assert!(!line.contains("version = "), "a git alias names no registry version: {line}");
}

#[test]
fn the_feature_enables_the_alias_alone_and_only_the_umbrella_includes_it() {
    let feature = MANIFEST
        .lines()
        .find(|line| line.starts_with("compat-s3s-rustfs = "))
        .expect("the feature is declared");
    assert_eq!(feature, r#"compat-s3s-rustfs = ["dep:s3s_rustfs", "dep:futures-core"]"#);
    let umbrella = MANIFEST
        .lines()
        .find(|line| line.starts_with("compat-s3s = "))
        .expect("the umbrella is declared");
    assert!(umbrella.contains(r#""compat-s3s-rustfs""#), "{umbrella}");
    assert!(umbrella.contains(r#""dep:s3s_rustfs""#), "{umbrella}");
    let includers: Vec<&str> = MANIFEST
        .lines()
        .filter(|line| line.contains(r#""compat-s3s-rustfs""#) || line.contains(r#""dep:s3s_rustfs""#))
        .collect();
    assert_eq!(includers, [umbrella, feature], "no default or other feature reaches the alias");
    assert!(
        !MANIFEST.lines().any(|line| line.starts_with("default = ")),
        "the types crate has no default feature"
    );
}

#[test]
fn the_feature_and_the_alias_carry_the_expiry_marker() {
    let marked = MANIFEST
        .lines()
        .filter(|line| line.contains("# DELETE BY: rustfs/backlog#2734 T4.2"))
        .count();
    assert_eq!(marked, 2, "one marker on the alias, one on the feature");
}

/// The seam compiled against the RustFS revision converts between the gateway types and a crate of
/// its own: a value of its `s3s` is not a value of the release seam's `s3s`, so a RustFS build that
/// links the former cannot be handed the latter by mistake.
#[cfg(feature = "compat-s3s-0-17-0")]
#[test]
fn the_rustfs_seam_is_a_compilation_of_its_own() {
    assert_ne!(
        TypeId::of::<super::s3s_5761ddfe::s3s::dto::GetObjectInput>(),
        TypeId::of::<super::s3s_0_17_0::s3s::dto::GetObjectInput>()
    );
    assert_ne!(
        TypeId::of::<super::s3s_5761ddfe::put_object::LegacyInput>(),
        TypeId::of::<super::s3s_0_17_0::put_object::LegacyInput>()
    );
}

#[cfg(not(feature = "compat-s3s-0-17-0"))]
#[test]
fn the_rustfs_seam_stands_alone_without_the_release_seam() {
    assert_ne!(
        TypeId::of::<super::s3s_5761ddfe::s3s::dto::GetObjectInput>(),
        TypeId::of::<crate::dto::GetObjectInput>()
    );
}
