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

//! P1-04 acceptance for the closed error resolver.
//!
//! Responsible for: one observable assertion per `c-err-n001..n011` outcome.
//! NOT responsible for: rendering XML bytes or transport connection policy.
//! Upstream: `rustfs-gateway-core`. Downstream: the scalar coverage guard.

use http::StatusCode;
use rustfs_gateway_core::{
    BodyPolicy, ErrorContext, ErrorDetail, HandlerError, HandlerErrorContext, MissingObject, RedirectTarget, RegionLabel,
    ResourceVisibility, ResponseKind, resolve,
};
use rustfs_gateway_types::{BucketName, ETag, ErrorCode, ObjectKey};

#[test]
fn c_err_n001_unknown_custom_code_is_a_client_error() {
    let context = ErrorContext::ordinary(HandlerError::new(ErrorCode::custom("VendorSpecific"), "vendor refusal"))
        .expect("the bounded identifier is valid");
    let resolution = resolve(context, ResponseKind::Other);
    assert_eq!(resolution.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resolution.code(), Some(&ErrorCode::custom("VendorSpecific")));
}

#[test]
fn c_err_n002_missing_key_and_version_share_visibility_masking() {
    for kind in [MissingObject::Key, MissingObject::Version] {
        let hidden = resolve(ErrorContext::missing_object(kind, ResourceVisibility::Hidden), ResponseKind::Other);
        assert_eq!(hidden.status(), StatusCode::FORBIDDEN);
        assert_eq!(hidden.code(), Some(&ErrorCode::ACCESS_DENIED));

        let visible = resolve(ErrorContext::missing_object(kind, ResourceVisibility::Visible), ResponseKind::Other);
        assert_eq!(visible.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            visible.code(),
            Some(match kind {
                MissingObject::Key => &ErrorCode::NO_SUCH_KEY,
                MissingObject::Version => &ErrorCode::NO_SUCH_VERSION,
            })
        );
    }
}

#[test]
fn c_err_n003_delete_missing_key_does_not_hide_a_missing_bucket() {
    let missing_key = resolve(ErrorContext::delete_missing_key(), ResponseKind::Other);
    assert_eq!(missing_key.status(), StatusCode::NO_CONTENT);
    assert_eq!(missing_key.code(), None);
    assert_eq!(missing_key.body_policy(), BodyPolicy::None);

    let missing_bucket = resolve(ErrorContext::missing_bucket(), ResponseKind::Other);
    assert_eq!(missing_bucket.status(), StatusCode::NOT_FOUND);
    assert_eq!(missing_bucket.code(), Some(&ErrorCode::NO_SUCH_BUCKET));
}

#[test]
fn c_err_n004_only_an_explicit_versioned_delete_marker_is_method_not_allowed() {
    assert!(ErrorContext::versioned_delete_marker("").is_err());
    let resolution = resolve(
        ErrorContext::versioned_delete_marker("version-1").expect("a non-empty bounded version id"),
        ResponseKind::Other,
    );
    assert_eq!(resolution.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(resolution.code(), Some(&ErrorCode::METHOD_NOT_ALLOWED));
}

#[test]
fn c_err_n005_missing_content_length_is_411() {
    let context = ErrorContext::ordinary(HandlerError::new(ErrorCode::MISSING_CONTENT_LENGTH, "length required"))
        .expect("the code is context-free");
    assert_eq!(resolve(context, ResponseKind::Other).status(), StatusCode::LENGTH_REQUIRED);
}

#[test]
fn c_err_n006_entity_too_large_is_400() {
    let context =
        ErrorContext::ordinary(HandlerError::new(ErrorCode::ENTITY_TOO_LARGE, "too large")).expect("the code is context-free");
    assert_eq!(resolve(context, ResponseKind::Other).status(), StatusCode::BAD_REQUEST);
}

#[test]
fn c_err_n007_head_removes_body_and_framing_without_changing_status() {
    let context =
        ErrorContext::ordinary(HandlerError::new(ErrorCode::NO_SUCH_UPLOAD, "missing upload")).expect("the code is context-free");
    let resolution = resolve(context, ResponseKind::Head);
    assert_eq!(resolution.status(), StatusCode::NOT_FOUND);
    assert_eq!(resolution.code(), Some(&ErrorCode::NO_SUCH_UPLOAD));
    assert_eq!(resolution.body_policy(), BodyPolicy::None);
}

#[test]
fn c_err_n008_not_modified_has_an_etag_and_no_body() {
    let etag = ETag::new("abc").expect("a bounded opaque tag");
    let resolution = resolve(ErrorContext::not_modified(etag.clone()), ResponseKind::Other);
    assert_eq!(resolution.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(resolution.code(), Some(&ErrorCode::NOT_MODIFIED));
    assert_eq!(resolution.body_policy(), BodyPolicy::None);
    assert_eq!(resolution.etag(), Some(&etag));
}

#[test]
fn c_err_n009_authorization_region_mismatch_has_one_region_detail() {
    let region = RegionLabel::new("eu-west-1").expect("a bounded region");
    let resolution = resolve(ErrorContext::authorization_region_mismatch(region), ResponseKind::Other);
    assert_eq!(resolution.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resolution.code(), Some(&ErrorCode::AUTHORIZATION_HEADER_MALFORMED));
    assert_eq!(resolution.details().len(), 1);
    assert_eq!(resolution.details().first().map(ErrorDetail::element), Some("Region"));
}

#[test]
fn authorization_scope_malformed_has_no_region_detail() {
    let resolution = resolve(ErrorContext::authorization_scope_malformed(), ResponseKind::Other);
    assert_eq!(resolution.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resolution.code(), Some(&ErrorCode::AUTHORIZATION_HEADER_MALFORMED));
    assert!(resolution.details().is_empty());
}

#[test]
fn c_err_n010_cors_refusal_has_the_canonical_static_message() {
    let resolution = resolve(ErrorContext::cors_forbidden(), ResponseKind::Other);
    assert_eq!(resolution.status(), StatusCode::FORBIDDEN);
    assert_eq!(resolution.code(), Some(&ErrorCode::ACCESS_FORBIDDEN));
    assert_eq!(resolution.message(), Some("CORSResponse: no CORS rule allows this request"));
}

#[test]
fn c_err_n011_unknown_codes_never_become_server_errors() {
    for code in ["VendorSpecific", "AnotherVendorCode", "Z9"] {
        let context = ErrorContext::ordinary(HandlerError::new(ErrorCode::custom(code.to_owned()), "vendor refusal"))
            .expect("the generated identifier is valid");
        assert!(!resolve(context, ResponseKind::Other).status().is_server_error());
    }
}

#[test]
fn a_missing_key_is_hidden_from_a_caller_who_may_not_list() {
    let hidden = resolve(
        ErrorContext::missing_object(MissingObject::Key, ResourceVisibility::Hidden),
        ResponseKind::Other,
    );
    assert_eq!(hidden.code(), Some(&ErrorCode::ACCESS_DENIED));

    let visible = resolve(
        ErrorContext::missing_object(MissingObject::Key, ResourceVisibility::Visible),
        ResponseKind::Other,
    );
    assert_eq!(visible.code(), Some(&ErrorCode::NO_SUCH_KEY));
}

#[test]
fn a_bucket_owned_by_another_account_is_not_reported_as_missing() {
    let resolution = resolve(ErrorContext::foreign_bucket(), ResponseKind::Other);
    assert_eq!(resolution.code(), Some(&ErrorCode::ACCESS_DENIED));
}

#[test]
fn a_bucket_in_another_region_redirects_instead_of_failing() {
    let region = RegionLabel::new("eu-west-1").expect("a bounded region");
    let moved = resolve(ErrorContext::permanent_redirect(region.clone()), ResponseKind::Other);
    assert_eq!(moved.status(), StatusCode::MOVED_PERMANENTLY);

    let target = RedirectTarget::new("https://bucket.s3.eu-west-1.example.com").expect("a bounded redirect target");
    let fresh = resolve(ErrorContext::temporary_redirect(region, target), ResponseKind::Other);
    assert_eq!(fresh.status(), StatusCode::TEMPORARY_REDIRECT);
}

#[test]
fn owned_bucket_recreation_is_only_the_conflict_refusal() {
    let resolution = resolve(ErrorContext::owned_bucket_recreation(), ResponseKind::Other);
    assert_eq!(resolution.status(), StatusCode::CONFLICT);
    assert_eq!(resolution.code(), Some(&ErrorCode::BUCKET_ALREADY_OWNED_BY_YOU));
}

#[test]
fn a_bucket_named_redirect_preserves_the_validated_bucket() {
    let bucket = BucketName::new("bucket-one").expect("a valid bucket");
    let region = RegionLabel::new("eu-west-1").expect("a bounded region");
    let resolution = resolve(ErrorContext::permanent_redirect_for(bucket, region), ResponseKind::Other);
    assert_eq!(
        resolution
            .details()
            .iter()
            .find(|detail| detail.element() == "BucketName")
            .map(ErrorDetail::text),
        Some(std::borrow::Cow::Borrowed("bucket-one"))
    );
    assert!(BucketName::new("Invalid_Bucket").is_err());
}

#[test]
fn a_head_response_reports_that_it_may_not_carry_a_body() {
    let context =
        ErrorContext::ordinary(HandlerError::new(ErrorCode::NO_SUCH_UPLOAD, "missing upload")).expect("the code is context-free");
    let resolution = resolve(context, ResponseKind::Head);
    assert_eq!(resolution.status(), StatusCode::NOT_FOUND);
    assert_eq!(resolution.body_policy(), BodyPolicy::None);
}

#[test]
fn contextual_handler_carrier_recovers_only_a_named_context() {
    let carried: HandlerError = HandlerErrorContext::missing_object(MissingObject::Version, ResourceVisibility::Hidden).into();
    let resolution = resolve(
        ErrorContext::ordinary(carried).expect("the sealed carrier recovers its named context"),
        ResponseKind::Other,
    );
    assert_eq!(resolution.code(), Some(&ErrorCode::ACCESS_DENIED));

    let forged = HandlerError::new(ErrorCode::NO_SUCH_VERSION, "missing version");
    assert!(ErrorContext::ordinary(forged).is_err(), "an ordinary builder cannot inject context");
}

#[test]
fn a_visible_missing_object_preserves_its_key_and_masking_removes_it() {
    let visible = resolve(
        ErrorContext::missing_object_for(
            ObjectKey::new("object-one").expect("a valid key"),
            MissingObject::Key,
            ResourceVisibility::Visible,
        ),
        ResponseKind::Other,
    );
    assert_eq!(visible.code(), Some(&ErrorCode::NO_SUCH_KEY));
    assert_eq!(
        visible.details().first().map(ErrorDetail::text),
        Some(std::borrow::Cow::Borrowed("object-one"))
    );

    let hidden = resolve(
        ErrorContext::missing_object_for(
            ObjectKey::new("object-one").expect("a valid key"),
            MissingObject::Key,
            ResourceVisibility::Hidden,
        ),
        ResponseKind::Other,
    );
    assert_eq!(hidden.code(), Some(&ErrorCode::ACCESS_DENIED));
    assert!(hidden.details().is_empty());
}

#[test]
fn a_visible_missing_object_omits_a_key_that_xml_cannot_represent() {
    let resolution = resolve(
        ErrorContext::missing_object_for(
            ObjectKey::new("object\u{1}one").expect("a control character is a valid object-key byte sequence"),
            MissingObject::Version,
            ResourceVisibility::Visible,
        ),
        ResponseKind::Other,
    );

    assert_eq!(resolution.code(), Some(&ErrorCode::NO_SUCH_VERSION));
    assert!(resolution.details().is_empty());
}

#[test]
fn ordinary_extra_builders_cannot_mutate_a_contextual_carrier() {
    let carried: HandlerError = HandlerErrorContext::missing_bucket().into();
    let carried = carried.with_detail(ErrorDetail::Key(std::borrow::Cow::Borrowed("forged")));
    let resolution = resolve(
        ErrorContext::ordinary(carried).expect("the sealed carrier remains intact"),
        ResponseKind::Other,
    );
    assert_eq!(resolution.code(), Some(&ErrorCode::NO_SUCH_BUCKET));
    assert!(resolution.details().is_empty());
}
