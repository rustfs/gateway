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

//! A copy source's bucket and version under the RustFS profile's path addressing
//! (rustfs/gateway#1115): legacy RustFS's bucket rules, and its split at the first `?versionId=`.
//!
//! Responsible for: pinning, to legacy RustFS's answers on a legacy build, a source in a bucket
//! the AWS rules reserve, a source key holding a `?`, and the version after the first
//! `?versionId=`; and the default grammar being untouched.
//! NOT responsible for: the source key's floor (`copy_source_rustfs_tests.rs`) or the default
//! grammar's own cases (`copy_source_tests.rs`).
//! Upstream: `super`. Downstream: nothing.

use std::sync::Arc;

use rustfs_gateway_types::dto::{CopyObject, CopyObjectInput};
use rustfs_gateway_types::{LegacyRustfsNameValidator, NamePolicy, SlashPolicy};

use super::*;
use crate::Decision;
use crate::authz::{authorize_input, prepare_input_under};

/// The RustFS profile's naming: the slash rule, the key floor and the path addressing.
fn rustfs() -> NamePolicy {
    NamePolicy::default()
        .with_slash_policy(SlashPolicy::RustfsLegacy)
        .with_legacy_rustfs_key_floor()
        .with_legacy_rustfs_path_split()
        .with_validator(Arc::new(LegacyRustfsNameValidator))
}

/// The bucket, key and version `CopyObject` resolves for `raw` under `names`, or the code.
fn source(raw: &str, names: &NamePolicy) -> Result<(String, String, Option<String>), ErrorCode> {
    let input = CopyObjectInput {
        copy_source: raw.to_owned(),
        ..Default::default()
    };
    let decoded = prepare_input_under::<CopyObject>(input, names).map_err(|error| error.code().clone())?;
    let authorized = authorize_input(decoded, |_| Decision::Allow).expect("authorized");
    let source = authorized
        .resources()
        .source()
        .resolve(authorized.read_proof())
        .expect("the proof covers it");
    Ok((
        source.bucket().as_str().to_owned(),
        source.key().as_str().to_owned(),
        source.version_id().map(str::to_owned),
    ))
}

fn found(bucket: &str, key: &str, version: Option<&str>) -> Result<(String, String, Option<String>), ErrorCode> {
    Ok((bucket.to_owned(), key.to_owned(), version.map(str::to_owned)))
}

/// Positive — a source in a bucket legacy RustFS created under a reserved prefix or suffix.
#[test]
fn a_bucket_the_aws_rules_reserve_is_a_copy_source() {
    assert_eq!(source("sthree-x/obj", &rustfs()), found("sthree-x", "obj", None));
    assert_eq!(source("/abc-s3alias/obj", &rustfs()), found("abc-s3alias", "obj", None));
}

/// Positive — a `?` that does not begin `versionId=` is key bytes, and the version is what follows
/// the first `?versionId=`.
#[test]
fn a_question_mark_is_key_bytes_until_the_first_version() {
    assert_eq!(source("src/obj?partNumber=1", &rustfs()), found("src", "obj?partNumber=1", None));
    assert_eq!(source("src/a?b?versionId=v1", &rustfs()), found("src", "a?b", Some("v1")));
    assert_eq!(source("src/a?versionId=v?x", &rustfs()), found("src", "a", Some("v?x")));
    assert_eq!(source("src/a?versionId=a%2Fb", &rustfs()), found("src", "a", Some("a/b")));
}

/// Negative — what legacy RustFS refuses as a copy source is still refused, `InvalidArgument`.
#[test]
fn n_a_source_legacy_rustfs_refuses_is_refused() {
    for raw in [
        "Bad_Bucket/obj",
        "1.2.3.4/obj",
        "xn--abc/obj",
        "src",
        "/src",
        "//src/obj",
        "src/obj?versionId=",
    ] {
        assert_eq!(source(raw, &rustfs()), Err(ErrorCode::INVALID_ARGUMENT), "{raw}");
    }
}

/// Negative — without the path addressing the grammar is the default one, exactly.
#[test]
fn n_the_default_grammar_is_untouched() {
    let default = NamePolicy::default();
    assert_eq!(source("sthree-x/obj", &default), Err(ErrorCode::INVALID_ARGUMENT));
    assert_eq!(source("src/obj?partNumber=1", &default), Err(ErrorCode::INVALID_ARGUMENT));
    assert_eq!(source("src/a?b?versionId=v1", &default), found("src", "a?b", Some("v1")));
    assert_eq!(source("src/a?versionId=v?x", &default), Err(ErrorCode::INVALID_ARGUMENT));
}
