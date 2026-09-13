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

//! GetBucketLocation: the request-context proof rustfs/backlog#1752 asked for before M1.
//!
//! Responsible for: proving, for the single real app call #1752 names, that a gateway request can
//! become an `s3s::S3Request<GetBucketLocationInput>` whose `uri`, `headers`, `extensions`,
//! `credentials` and `region` — the five context members the M1 audit found missing from
//! `Req<O>` — plus `method`, `service` and the trailer handle equal what the s3s service hands its
//! handler; that the seam's `get_bucket_location::input_to_s3s` turns the gateway's decoded input
//! into the input s3s decodes from the same bytes; and that `output_from_s3s` keeps every
//! constraint the RustFS body can answer.
//! NOT responsible for: the RustFS extensions the app body then reads (`ReqInfo`,
//! `RequestContext`, the server context slot), which the conversion never produces and the ring-2
//! adapter must install; or the response bytes, which the gateway codec writes.
//! Upstream: the harness in `super`; the seam revision bound two levels up. Downstream: nothing.

use std::collections::BTreeSet;

use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_types::dto;

use super::super::oracle;
use super::super::put_object::generated_field_count;
use super::super::seam::get_bucket_location::{GATEWAY_INPUT_MEMBERS, GATEWAY_OUTPUT_MEMBERS, input_to_s3s, output_from_s3s};
use super::{
    ACCESS_KEY, BASE_DOMAIN, CapturedInput, Compared, ContextRequest, PATH_HOST, access_key, answers, compare, differing_context,
    region_of,
};

const NONE: &[&str] = &[];

fn compared(request: &ContextRequest) -> Compared {
    let compared = compare(request).expect("both stacks reach their GetBucketLocation handler");
    assert_eq!(compared.operation, "GetBucketLocation");
    compared
}

/// The gateway's decoded input after the seam conversion, and the input s3s decoded, both as
/// `(bucket, expected_bucket_owner)`.
fn inputs(compared: &Compared) -> ((String, Option<String>), (String, Option<String>)) {
    let meta = MetaView::addressed(&compared.wire, compared.resolved.target, compared.resolved.bucket().cloned())
        .expect("the meta view the pipeline built");
    let gateway = dto::GetBucketLocation::decode(&meta, RequestBody::None).expect("the gateway codec decodes");
    let converted = input_to_s3s(gateway);
    let CapturedInput::Location(oracle) = &compared.oracle.input else {
        panic!("s3s handed the request to PutObject");
    };
    (
        (converted.bucket, converted.expected_bucket_owner),
        (oracle.bucket.clone(), oracle.expected_bucket_owner.clone()),
    )
}

fn constraint(value: Option<&'static str>) -> Option<String> {
    let output = oracle::GetBucketLocationOutput {
        location_constraint: value.map(|value| oracle::BucketLocationConstraint::from(value.to_owned())),
    };
    output_from_s3s(output)
        .location_constraint
        .map(|constraint| constraint.as_str().to_owned())
}

#[test]
fn an_anonymous_path_style_request_has_the_same_context_and_input() {
    let compared = compared(&ContextRequest::get(PATH_HOST, "/photos", "location"));

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(compared.converted.uri, "/photos?location");
    assert_eq!(compared.converted.method, http::Method::GET);
    assert!(compared.converted.credentials.is_none());
    let (gateway, oracle) = inputs(&compared);
    assert_eq!(gateway, oracle);
    assert_eq!(gateway.0, "photos");
}

#[test]
fn a_signed_path_style_request_has_the_same_principal_region_and_input() {
    let request = ContextRequest::get(PATH_HOST, "/photos", "location")
        .header("x-amz-expected-bucket-owner", b"111122223333")
        .signed("eu-west-1");
    let compared = compared(&request);

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(
        (access_key(&compared.converted), access_key(&compared.oracle)),
        (Some(ACCESS_KEY), Some(ACCESS_KEY))
    );
    assert_eq!(
        (region_of(&compared.converted), region_of(&compared.oracle)),
        (Some("eu-west-1"), Some("eu-west-1"))
    );
    assert_eq!(compared.converted.service.as_deref(), Some("s3"));
    let (gateway, oracle) = inputs(&compared);
    assert_eq!(gateway, oracle);
    assert_eq!(gateway.1.as_deref(), Some("111122223333"));
}

#[test]
fn a_signed_virtual_hosted_request_has_the_same_context_and_input() {
    let request = ContextRequest::get(&format!("photos.{BASE_DOMAIN}"), "/", "location")
        .virtual_hosted()
        .signed("us-east-1");
    let compared = compared(&request);

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(compared.converted.uri, "/?location");
    let (gateway, oracle) = inputs(&compared);
    assert_eq!(gateway, oracle);
    assert_eq!(gateway.0, "photos");
}

/// RustFS answers `None` for a bucket in the default region; the gateway codec then writes the
/// empty constraint, so the conversion must not invent one.
#[test]
fn n_an_absent_constraint_stays_absent() {
    assert_eq!(constraint(None), None);
}

/// A RustFS operator names its own region, which need not be one the model lists; the conversion
/// keeps the spelling rather than dropping or normalising it.
#[test]
fn n_a_region_the_model_does_not_list_keeps_its_spelling() {
    assert_eq!(constraint(Some("rustfs-local-1")).as_deref(), Some("rustfs-local-1"));
    assert_eq!(constraint(Some("")).as_deref(), Some(""));
}

#[test]
fn a_listed_constraint_crosses_unchanged() {
    for value in ["EU", "eu-west-1", "us-west-2"] {
        assert_eq!(constraint(Some(value)).as_deref(), Some(value));
    }
}

/// The gateway structs may not be destructured exhaustively (ADR-0004 P3), so the conversion
/// declares its members and this pins the declaration to the generated struct.
#[test]
fn n_the_conversion_declares_every_gateway_member() {
    for (type_name, members) in [
        ("GetBucketLocationInput", GATEWAY_INPUT_MEMBERS),
        ("GetBucketLocationOutput", GATEWAY_OUTPUT_MEMBERS),
    ] {
        let distinct: BTreeSet<&str> = members.iter().copied().collect();
        assert_eq!(distinct.len(), members.len(), "{type_name}: a member is declared twice");
        assert_eq!(
            members.len(),
            generated_field_count(type_name),
            "{type_name}: the conversion is behind the model"
        );
    }
}

// ── the named divergences (rd-loc) ────────────────────────────────────────────────────────────

/// The declaration both stacks open an XML body with.
const XML_DECLARATION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

fn location_request() -> ContextRequest {
    ContextRequest::get(PATH_HOST, "/photos", "location")
}

/// The gateway writes a line break after the XML declaration, as S3 does; s3s writes the root
/// element straight after it. The documents are otherwise the same bytes.
///
/// Ruling: `rd-loc-0001`
#[test]
fn the_xml_declaration_is_followed_by_a_line_break_only_on_the_gateway() {
    let (gateway, oracle) = answers(&location_request()).expect("both stacks answer");
    assert_eq!((gateway.status, oracle.status), (200, 200), "{gateway:?} {oracle:?}");
    let gateway_root = gateway.body.strip_prefix(XML_DECLARATION).expect("the gateway declares");
    let oracle_root = oracle.body.strip_prefix(XML_DECLARATION).expect("s3s declares");
    assert_eq!(gateway_root.strip_prefix('\n'), Some(oracle_root), "{gateway:?} {oracle:?}");
    assert!(oracle_root.starts_with("<LocationConstraint"), "{oracle:?}");
}

/// A known access key with a wrong signature: both stacks answer `SignatureDoesNotMatch`. The
/// gateway's message is still the one an unknown key gets, so the code is the only difference.
///
/// Ruling: `rd-loc-0002`
#[test]
fn a_forged_signature_on_a_known_key_is_signature_does_not_match_on_both_stacks() {
    let (gateway, oracle) = answers(&location_request().signed("us-east-1").forged()).expect("both stacks answer");
    assert_eq!((gateway.status, oracle.status), (403, 403), "{gateway:?} {oracle:?}");
    assert_eq!(gateway.code(), Some("SignatureDoesNotMatch"), "{gateway:?}");
    assert_eq!(oracle.code(), Some("SignatureDoesNotMatch"), "{oracle:?}");
    let (unknown, _) = answers(&location_request().signed("us-east-1").unknown_key()).expect("both stacks answer");
    assert_eq!(gateway.message(), unknown.message(), "one message for every credential rejection");
}

/// An access key neither store holds: the gateway answers `InvalidAccessKeyId` with its one
/// credential-rejection message. On s3s the code and the message are whatever the auth provider
/// returns: the harness's `SimpleAuth` answers `NotSignedUp`, and RustFS's `IAMAuth` answers
/// `InvalidAccessKeyId` with a sentence of its own. Either way the message is not the gateway's.
///
/// Ruling: `rd-loc-0003`
#[test]
fn an_unknown_access_key_is_invalid_access_key_id_on_the_gateway_and_the_auth_providers_answer_on_s3s() {
    let (gateway, oracle) = answers(&location_request().signed("us-east-1").unknown_key()).expect("both stacks answer");
    assert_eq!((gateway.status, oracle.status), (403, 403), "{gateway:?} {oracle:?}");
    assert_eq!(gateway.code(), Some("InvalidAccessKeyId"), "{gateway:?}");
    assert_eq!(gateway.message(), Some("the request was not authenticated"));
    assert_eq!(
        oracle.code(),
        Some("NotSignedUp"),
        "s3s SimpleAuth's answer for a key it does not hold: {oracle:?}"
    );
    assert_ne!(gateway.message(), oracle.message(), "{oracle:?}");
}

/// A scope region the gateway does not serve: s3s verifies it, the gateway refuses it with the
/// region to use, and verifies it like s3s under the RustFS profile — handing the handler the
/// client's region, the context s3s hands its own.
///
/// Ruling: `rd-loc-0004`
#[test]
fn a_scope_region_the_gateway_does_not_serve_is_verified_only_under_the_rustfs_profile() {
    let request = location_request().signed("ap-south-1");
    let (gateway, oracle) = answers(&request).expect("both stacks answer");
    assert_eq!(oracle.status, 200, "{oracle:?}");
    assert_eq!(gateway.status, 400, "{gateway:?}");
    assert_eq!(gateway.code(), Some("AuthorizationHeaderMalformed"), "{gateway:?}");
    assert!(gateway.body.contains("<Region>eu-west-1</Region>"), "{gateway:?}");

    let compared = compared(&request.rustfs_profile());
    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(
        (region_of(&compared.converted), region_of(&compared.oracle)),
        (Some("ap-south-1"), Some("ap-south-1"))
    );
}
