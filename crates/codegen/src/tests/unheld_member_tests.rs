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

//! The listing-entry members the encoders write as absent when the host does not hold them
//! (rustfs/gateway#1613).
//!
//! Responsible for: the guard reaching exactly the members `ABSENT_WHEN_UNHELD` lists, in every
//! listing that writes them, and nowhere else; every listed member being a required member the
//! pinned model still has.
//! NOT responsible for: the bytes the guarded writer produces (`rustfs-gateway-core`'s
//! `codec::tests::rustfs_listing::absent_members`).
//! Upstream: `emit::codec::encode`, the pinned model. Downstream: nothing.

use std::collections::BTreeSet;

use super::codegen_tests::{artifacts, body};
use crate::emit::codec::encode::layout::{ABSENT_WHEN_UNHELD, UNHELD_UNDER_LEGACY_LAYOUT};
use crate::emit::dto::naming;

/// Every guarded member a codec file renders, as `(shape writer, element)`.
fn guarded(file: &str) -> BTreeSet<(String, String)> {
    let guard = format!("if !{UNHELD_UNDER_LEGACY_LAYOUT} {{");
    let mut writer = String::new();
    let mut out = BTreeSet::new();
    let mut lines = file.lines();
    while let Some(line) = lines.next() {
        if let Some(rest) = line.strip_prefix("fn write_") {
            writer = rest.split('(').next().unwrap_or_default().to_owned();
        }
        if line.trim() == guard {
            let next = lines.next().unwrap_or_default().trim();
            let element = next
                .strip_prefix("writer.element(\"")
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_else(|| panic!("a guard wraps one element write, not `{next}`"));
            out.insert((writer.clone(), element.to_owned()));
        }
    }
    out
}

fn codec_file(artifacts: &crate::Artifacts, operation: &str) -> String {
    body(artifacts, &format!("generated/codec/ops/{}.rs", naming::module_name(operation)))
}

fn expected(shapes: &[&str]) -> BTreeSet<(String, String)> {
    ABSENT_WHEN_UNHELD
        .iter()
        .filter(|(shape, _)| shapes.contains(shape))
        .map(|(shape, member)| (naming::module_name(shape), (*member).to_owned()))
        .collect()
}

/// Positive — each listing guards exactly the listed members of the entries it writes.
#[test]
fn every_listing_guards_the_listed_members_of_its_entries() {
    let artifacts = artifacts();
    for (operation, shapes) in [
        ("ListObjectsV2", &["Object"][..]),
        ("ListObjects", &["Object"][..]),
        ("ListObjectVersions", &["ObjectVersion", "DeleteMarkerEntry"][..]),
    ] {
        assert_eq!(guarded(&codec_file(&artifacts, operation)), expected(shapes), "{operation}");
    }
}

/// Negative — `Size` and every other required entry member are written unguarded.
#[test]
fn n_no_other_entry_member_is_guarded() {
    let artifacts = artifacts();
    for operation in ["ListObjectsV2", "ListObjects", "ListObjectVersions"] {
        for (_, element) in guarded(&codec_file(&artifacts, operation)) {
            assert!(["LastModified", "StorageClass"].contains(&element.as_str()), "{operation}: {element}");
        }
    }
}

/// Negative — no codec outside the three listings carries the guard, so a placeholder anywhere
/// else (a bucket's creation date, an upload's initiation time) still fails the encode.
#[test]
fn n_no_other_codec_carries_the_guard() {
    let artifacts = artifacts();
    let mut total = 0;
    for (path, text) in &artifacts.files {
        let path = path.to_string_lossy();
        if !path.contains("generated/codec/ops/") {
            continue;
        }
        let found = guarded(text).len();
        let listing = ["list_objects_v2.rs", "list_objects.rs", "list_object_versions.rs"]
            .iter()
            .any(|file| path.ends_with(&format!("/{file}")));
        assert!(listing || found == 0, "{path} guards {found} member(s)");
        total += found;
    }
    assert_eq!(total, 7, "two entries of two listings and two entries of the version listing");
}

/// Negative — a listed member the pinned model stops requiring, or no longer has, is no longer
/// guarded anywhere; the table cannot go stale silently.
#[test]
fn n_every_listed_member_is_guarded_somewhere() {
    let artifacts = artifacts();
    let all: BTreeSet<_> = ["ListObjectsV2", "ListObjects", "ListObjectVersions"]
        .iter()
        .flat_map(|operation| guarded(&codec_file(&artifacts, operation)))
        .collect();
    for (shape, member) in ABSENT_WHEN_UNHELD {
        assert!(
            all.contains(&(naming::module_name(shape), (*member).to_owned())),
            "{shape}.{member} is guarded nowhere"
        );
    }
}
