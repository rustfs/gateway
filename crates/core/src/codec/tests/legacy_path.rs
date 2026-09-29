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

//! Legacy RustFS's path split (rustfs/gateway#1115): the pre-routing classification and the
//! bucket and key a view then reads, agreeing with each other and with legacy RustFS.
//!
//! Responsible for: pinning [`legacy_rustfs_target`] and the view's reading under
//! [`rustfs_gateway_types::PathSplit::RustfsLegacy`] to legacy RustFS's answers on a legacy build:
//! `GET /bkt%2Fsrc` read `src` in `bkt`, `GET //bkt` was `400 InvalidBucketName`, `GET /bkt/a%FFb`
//! was `400 InvalidURI`.
//! NOT responsible for: where the pipeline applies the split (the gateway's `legacy_addressing`),
//! or the bucket rules themselves (`rustfs-gateway-types`).
//! Upstream: the parent codec test helpers. Downstream: nothing; this is a leaf test module.

use std::sync::Arc;

use rustfs_gateway_types::{ErrorCode, LegacyRustfsNameValidator, NamePolicy, SlashPolicy};

use crate::codec::tests::accepted;
use crate::codec::{CodecError, MetaView, legacy_rustfs_target};
use crate::route::TargetKind;

fn legacy() -> NamePolicy {
    NamePolicy::default()
        .with_slash_policy(SlashPolicy::RustfsLegacy)
        .with_legacy_rustfs_key_floor()
        .with_validator(Arc::new(LegacyRustfsNameValidator))
        .with_legacy_rustfs_path_split()
}

fn code(error: CodecError) -> ErrorCode {
    error.code().clone()
}

/// The pre-routing target, and, when there is one, the bucket and key the view reads under it.
fn addressed(target: &str) -> Result<(TargetKind, Option<String>, Option<String>), ErrorCode> {
    let request = accepted("GET", target, &[]);
    let kind = legacy_rustfs_target(request.raw_path().as_str(), false, &legacy()).map_err(code)?;
    let view = MetaView::of_with(&request, kind, &legacy()).map_err(code)?;
    Ok((
        kind,
        view.bucket().map(|bucket| bucket.as_str().to_owned()),
        view.key().map(|key| key.as_str().to_owned()),
    ))
}

fn object(bucket: &str, key: &str) -> Result<(TargetKind, Option<String>, Option<String>), ErrorCode> {
    Ok((TargetKind::Object, Some(bucket.to_owned()), Some(key.to_owned())))
}

fn bucket(name: &str) -> Result<(TargetKind, Option<String>, Option<String>), ErrorCode> {
    Ok((TargetKind::Bucket, Some(name.to_owned()), None))
}

// ---------------------------------------------------------------------------
// Positive: the decoded path is split at its first `/`.
// ---------------------------------------------------------------------------

#[test]
fn an_escaped_separator_ends_the_bucket() {
    assert_eq!(addressed("/bkt%2Fsrc"), object("bkt", "src"));
    assert_eq!(addressed("/bkt%2fsrc/more"), object("bkt", "src/more"));
    assert_eq!(
        addressed("/bkt/a%2Fb"),
        object("bkt", "a/b"),
        "an escaped slash in the key is a slash, as before"
    );
    assert_eq!(addressed("/bkt%2F%2Fsrc"), object("bkt", "src"), "the key then meets the slash rule");
    assert_eq!(addressed("/bkt%2F"), bucket("bkt"));
}

#[test]
fn an_escaped_bucket_label_is_decoded() {
    assert_eq!(addressed("/b%6Bt/src"), object("bkt", "src"));
    assert_eq!(addressed("/b%6Bt"), bucket("bkt"));
}

#[test]
fn the_shapes_the_literal_split_already_reads_are_unchanged() {
    assert_eq!(addressed("/"), Ok((TargetKind::Service, None, None)));
    assert_eq!(addressed("/bkt"), bucket("bkt"));
    assert_eq!(addressed("/bkt/"), bucket("bkt"));
    assert_eq!(addressed("/bkt/dir/key"), object("bkt", "dir/key"));
    assert_eq!(addressed("/bkt//key"), object("bkt", "key"));
    assert_eq!(addressed("/bkt//"), object("bkt", "/"));
}

// ---------------------------------------------------------------------------
// Negative: what legacy RustFS refuses before routing, and with what.
// ---------------------------------------------------------------------------

#[test]
fn n_an_empty_bucket_segment_is_an_invalid_bucket_name() {
    for target in ["//", "///", "//bkt", "//bkt/src", "/%2Fbkt/src", "/%2F", "/%2F%2F"] {
        assert_eq!(addressed(target), Err(ErrorCode::INVALID_BUCKET_NAME), "{target}");
    }
}

#[test]
fn n_an_undecodable_path_is_an_invalid_uri_before_anything_else() {
    assert_eq!(addressed("/bkt/a%FFb"), Err(ErrorCode::INVALID_URI));
    assert_eq!(addressed("/b%FFt/src"), Err(ErrorCode::INVALID_URI));
    // The decode is judged before the bucket: a bad bucket with a bad key is still InvalidURI.
    assert_eq!(addressed("/Bad_Bucket/a%FFb"), Err(ErrorCode::INVALID_URI));
}

#[test]
fn n_a_bucket_legacy_rustfs_refuses_is_refused_before_routing() {
    for target in [
        "/Bad_Bucket/src",
        "/KEYB/src",
        "/1.2.3.4/src",
        "/xn--abc",
        "/b%25t/src",
        "/ab",
    ] {
        assert_eq!(addressed(target), Err(ErrorCode::INVALID_BUCKET_NAME), "{target}");
    }
}

#[test]
fn n_the_bucket_is_judged_before_the_key() {
    let overlong = format!("/Bad_Bucket/{}", "k".repeat(1025));
    assert_eq!(addressed(&overlong), Err(ErrorCode::INVALID_BUCKET_NAME));
    let overlong = format!("/bkt/{}", "k".repeat(1025));
    assert_eq!(addressed(&overlong), Err(ErrorCode::KEY_TOO_LONG));
}

#[test]
fn n_a_host_named_bucket_reads_the_whole_path_as_the_key() {
    let host = |target: &str| legacy_rustfs_target(target, true, &legacy()).map_err(code);
    assert_eq!(host("/"), Ok(TargetKind::Bucket));
    assert_eq!(host("/bkt%2Fsrc"), Ok(TargetKind::Object));
    assert_eq!(host("//"), Ok(TargetKind::Object), "the key `/`");
    assert_eq!(host("/a%FF"), Err(ErrorCode::INVALID_URI));
    assert_eq!(host(&format!("/{}", "k".repeat(1025))), Err(ErrorCode::KEY_TOO_LONG));
}

#[test]
fn n_the_literal_split_is_untouched() {
    // Without the legacy split the view reads the path as it always has: an escaped separator is
    // part of the bucket label, which no rule admits.
    let request = accepted("GET", "/bkt%2Fsrc", &[]);
    let refused = MetaView::of_with(&request, TargetKind::Bucket, &NamePolicy::default()).map_err(code);
    assert_eq!(refused.map(|_| ()), Err(ErrorCode::INVALID_BUCKET_NAME));
}

#[test]
fn n_a_key_rule_other_than_its_length_is_not_judged_before_routing() {
    // Legacy RustFS routes a NUL key and its storage refuses it after authorization; the view still
    // refuses it after routing, as an ObjectKey cannot hold it.
    assert_eq!(legacy_rustfs_target("/bkt/a%00b", false, &legacy()).map_err(code), Ok(TargetKind::Object));
    assert_eq!(addressed("/bkt/a%00b"), Err(ErrorCode::INVALID_ARGUMENT));
}
