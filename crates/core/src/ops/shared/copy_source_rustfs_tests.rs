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

//! A copy source's key under the RustFS profile's legacy key floor (rustfs/gateway#1107).
//!
//! Responsible for: the source key being held to the key floor the request path is held to —
//! every key legacy RustFS copies from reaches the handler as the bytes one decode produced, the
//! representation rules still refuse, and the unconditional floor is untouched — through the same
//! `prepare_input_under` the pipeline calls, for both copy operations.
//! NOT responsible for: the copy-source grammar (`copy_source_tests.rs`) or the default floor's own
//! refusals (`copy_source_security_tests.rs`).
//! Upstream: `super`. Downstream: nothing.

use rustfs_gateway_types::dto::{CopyObject, CopyObjectInput, UploadPartCopy, UploadPartCopyInput};
use rustfs_gateway_types::{NamePolicy, SlashPolicy};

use super::*;
use crate::Decision;
use crate::authz::{authorize_input, prepare_input_under};

fn legacy() -> NamePolicy {
    NamePolicy::default()
        .with_slash_policy(SlashPolicy::RustfsLegacy)
        .with_legacy_rustfs_key_floor()
}

/// The source key `CopyObject` resolves for `raw` under `names`, or the refusal's code.
fn copy_object_key(raw: &str, names: &NamePolicy) -> Result<String, ErrorCode> {
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
    Ok(source.key().as_str().to_owned())
}

/// The same through `UploadPartCopy`, so a rule that reached one copy operation and not the other
/// fails here.
fn upload_part_copy_key(raw: &str, names: &NamePolicy) -> Result<String, ErrorCode> {
    let input = UploadPartCopyInput {
        copy_source: raw.to_owned(),
        ..Default::default()
    };
    let decoded = prepare_input_under::<UploadPartCopy>(input, names).map_err(|error| error.code().clone())?;
    let authorized = authorize_input(decoded, |_| Decision::Allow).expect("authorized");
    let source = authorized
        .resources()
        .source()
        .resolve(authorized.read_proof())
        .expect("the proof covers it");
    Ok(source.key().as_str().to_owned())
}

/// Positive — every source key legacy RustFS copied from (`PUT` with `x-amz-copy-source` answered
/// 200 on a legacy build) resolves to the bytes its storage holds, for both copy operations.
#[test]
fn a_source_legacy_rustfs_copies_from_resolves_to_the_same_key() {
    for (raw, key) in [
        ("bkt/a%01b", "a\u{1}b"),
        ("bkt/a%09b", "a\tb"),
        ("bkt/a%252Fb", "a%2Fb"),
        ("bkt/%5Cx", "\\x"),
        ("bkt/C:%5Cx", "C:\\x"),
        ("bkt/a/../b", "a/../b"),
        ("bkt/a%0Ab", "a\nb"),
    ] {
        assert_eq!(copy_object_key(raw, &legacy()), Ok(key.to_owned()), "CopyObject {raw}");
        assert_eq!(upload_part_copy_key(raw, &legacy()), Ok(key.to_owned()), "UploadPartCopy {raw}");
    }
}

/// Negative — the representation rules still refuse, as they do for a path key.
#[test]
fn n_a_source_key_no_object_key_can_hold_is_still_refused() {
    for raw in ["bkt/a%00b", "bkt/"] {
        assert_eq!(copy_object_key(raw, &legacy()), Err(ErrorCode::INVALID_ARGUMENT), "{raw}");
        assert_eq!(upload_part_copy_key(raw, &legacy()), Err(ErrorCode::INVALID_ARGUMENT), "{raw}");
    }
    let overlong = format!("bkt/{}", "k".repeat(1025));
    assert_eq!(copy_object_key(&overlong, &legacy()), Err(ErrorCode::INVALID_ARGUMENT));
}

/// Negative — a single decode stays single: a doubly encoded separator is the literal text one
/// decode left, never a separator.
#[test]
fn n_the_source_key_is_decoded_once() {
    assert_eq!(copy_object_key("bkt/%252e%252e/x", &legacy()), Ok("%2e%2e/x".to_owned()));
    assert_eq!(copy_object_key("bkt/a%FFb", &legacy()), Err(ErrorCode::INVALID_ARGUMENT));
}

/// Negative — the default floor is untouched through the same entry: every key above is refused.
#[test]
fn n_the_default_floor_still_refuses_them() {
    for raw in ["bkt/a%01b", "bkt/%5Cx", "bkt/a/../b", "bkt/%252e%252e/x"] {
        assert_eq!(copy_object_key(raw, &NamePolicy::default()), Err(ErrorCode::INVALID_ARGUMENT), "{raw}");
        assert_eq!(
            upload_part_copy_key(raw, &NamePolicy::default()),
            Err(ErrorCode::INVALID_ARGUMENT),
            "{raw}"
        );
    }
}

/// Negative — the slash rule is not a key floor: with only the legacy slash rule, a source key is
/// still held to the default floor, and a copy source's key is never folded.
#[test]
fn n_the_slash_rule_alone_changes_no_source_key() {
    let slash_only = NamePolicy::default().with_slash_policy(SlashPolicy::RustfsLegacy);
    assert_eq!(copy_object_key("bkt/a%01b", &slash_only), Err(ErrorCode::INVALID_ARGUMENT));
    assert_eq!(copy_object_key("bkt//leading", &slash_only), Ok("/leading".to_owned()));
    assert_eq!(copy_object_key("bkt//leading", &legacy()), Ok("/leading".to_owned()));
}

/// Refuses every key under `secret/`, and has no opinion on anything else.
struct NoSecrets;

impl rustfs_gateway_types::NameValidator for NoSecrets {
    fn check_bucket(&self, _name: &str) -> rustfs_gateway_types::Stricter {
        rustfs_gateway_types::Stricter::NoOpinion
    }

    fn check_key(&self, key: &str) -> rustfs_gateway_types::Stricter {
        if key.starts_with("secret/") {
            rustfs_gateway_types::Stricter::Reject(rustfs_gateway_types::NameRejection::rejected_by_validator("no secrets"))
        } else {
            rustfs_gateway_types::Stricter::NoOpinion
        }
    }
}

/// Negative — the deployment's validator judges a copy source's key as it judges the path's, under
/// either floor: a key it refuses as a destination cannot be read as a source.
#[test]
fn n_the_validator_judges_the_source_under_either_floor() {
    for names in [NamePolicy::default(), legacy()] {
        let names = names.with_validator(std::sync::Arc::new(NoSecrets));
        assert_eq!(copy_object_key("bkt/secret/x", &names), Err(ErrorCode::INVALID_ARGUMENT), "{names:?}");
        assert_eq!(
            upload_part_copy_key("bkt/secret/x", &names),
            Err(ErrorCode::INVALID_ARGUMENT),
            "{names:?}"
        );
        assert_eq!(copy_object_key("bkt/public/x", &names), Ok("public/x".to_owned()), "{names:?}");
    }
}
