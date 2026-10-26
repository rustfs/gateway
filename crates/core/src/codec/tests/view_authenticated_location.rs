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

//! Authenticated AWS credential locations carried by codec metadata.
//!
//! Responsible for: fail-closed proof admission and location preservation across view copies.
//! NOT responsible for: signature verification, which the service integration matrix exercises.
//! Upstream: settled signature verdicts and original AWS markers. Downstream: codec consumers.

use http::{HeaderMap, HeaderValue, Request};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{
    AuthError, AuthScheme, AwsCredentialMarker, CredentialPresence, CtBytes, Identity, RawQuery, SigFamily, SigIdentity,
    SigLocation, SigService, Signature, Verdict, WireView, detect_aws_credential_marker,
};

use super::MetaView;
use crate::route::TargetKind;

fn wire() -> WireRequest<()> {
    let request = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", "example.test")
        .header("authorization", "AWS fixture:fixture")
        .body(())
        .expect("a metadata fixture");
    WireRequest::accept(request, &Limits::default()).expect("accepted fixture")
}

fn verdict(family: SigFamily, location: SigLocation) -> Verdict {
    let signature = Signature::HmacSha256(CtBytes::from_array([3; 32]));
    let proof = signature.ct_verify(&signature).expect("a matching fixture proof");
    Verdict::authenticated(
        Identity::new("fixture-access").expect("a fixture identity"),
        AuthScheme::new(family, location, SigIdentity::LongTerm, SigService::Sts),
        proof,
    )
}

fn marker(family: SigFamily, location: SigLocation) -> AwsCredentialMarker {
    let mut headers = HeaderMap::new();
    let query = match (family, location) {
        (SigFamily::V2, SigLocation::Header) => {
            headers.insert(http::header::AUTHORIZATION, HeaderValue::from_static("AWS fixture:fixture"));
            ""
        }
        (SigFamily::V4, SigLocation::Header) => {
            headers.insert(http::header::AUTHORIZATION, HeaderValue::from_static("AWS4-HMAC-SHA256 fixture"));
            ""
        }
        (SigFamily::V2, SigLocation::Query) => "AWSAccessKeyId=fixture",
        (SigFamily::V4, SigLocation::Query) => "X-Amz-Credential=fixture",
        _ => panic!("unsupported fixture shape"),
    };
    detect_aws_credential_marker(&WireView::new(&headers, RawQuery::new(query))).expect("an AWS marker")
}

/// Negative — even a displayed Authorization header is not an authenticated location by default.
#[test]
fn default_metadata_has_no_authenticated_location() {
    let wire = wire();
    let meta = MetaView::of(&wire, TargetKind::Service).expect("a service view");
    assert_eq!(meta.authenticated_aws_location(), None);
}

/// Negative — a rejected verdict cannot grant its request's marker.
#[test]
fn rejected_verdict_has_no_authenticated_location() {
    let wire = wire();
    let meta = MetaView::of(&wire, TargetKind::Service)
        .expect("a service view")
        .with_authenticated_aws_marker(
            &Verdict::reject(AuthError::AccessDenied),
            Some(marker(SigFamily::V4, SigLocation::Header)),
        );
    assert_eq!(meta.authenticated_aws_location(), None);
}

/// Negative — anonymous evidence does not become authentication when a marker is supplied.
#[test]
fn anonymous_verdict_has_no_authenticated_location() {
    let wire = wire();
    let verdict = Verdict::anonymous(CredentialPresence::NONE.into_evidence().expect("no credentials"));
    let meta = MetaView::of(&wire, TargetKind::Service)
        .expect("a service view")
        .with_authenticated_aws_marker(&verdict, Some(marker(SigFamily::V4, SigLocation::Header)));
    assert_eq!(meta.authenticated_aws_location(), None);
}

/// Negative — an authenticated custom path with no original AWS marker grants no AWS location.
#[test]
fn absent_original_marker_has_no_authenticated_location() {
    let wire = wire();
    let meta = MetaView::of(&wire, TargetKind::Service)
        .expect("a service view")
        .with_authenticated_aws_marker(&verdict(SigFamily::V4, SigLocation::Header), None);
    assert_eq!(meta.authenticated_aws_location(), None);
}

/// Negative — a query verdict cannot authenticate a different header marker.
#[test]
fn mismatched_locations_have_no_authenticated_location() {
    let wire = wire();
    let meta = MetaView::of(&wire, TargetKind::Service)
        .expect("a service view")
        .with_authenticated_aws_marker(
            &verdict(SigFamily::V4, SigLocation::Query),
            Some(marker(SigFamily::V4, SigLocation::Header)),
        );
    assert_eq!(meta.authenticated_aws_location(), None);
}

/// Negative — an algorithm disagreement cannot publish a matching location alone.
#[test]
fn mismatched_families_have_no_authenticated_location() {
    let wire = wire();
    let meta = MetaView::of(&wire, TargetKind::Service)
        .expect("a service view")
        .with_authenticated_aws_marker(
            &verdict(SigFamily::V2, SigLocation::Header),
            Some(marker(SigFamily::V4, SigLocation::Header)),
        );
    assert_eq!(meta.authenticated_aws_location(), None);
}

/// Positive — both supported families retain their truthful header or query location.
#[test]
fn authenticated_locations_preserve_header_and_query() {
    let wire = wire();
    for family in [SigFamily::V2, SigFamily::V4] {
        for location in [SigLocation::Header, SigLocation::Query] {
            let meta = MetaView::of(&wire, TargetKind::Service)
                .expect("a service view")
                .with_authenticated_aws_marker(&verdict(family, location), Some(marker(family, location)));
            assert_eq!(meta.authenticated_aws_location(), Some(location));
        }
    }
}

/// Positive — the manually reconstructed framed view retains the authenticated location.
#[test]
fn framed_metadata_preserves_authenticated_location() {
    let wire = wire();
    for family in [SigFamily::V2, SigFamily::V4] {
        for location in [SigLocation::Header, SigLocation::Query] {
            let meta = MetaView::of(&wire, TargetKind::Service)
                .expect("a service view")
                .with_authenticated_aws_marker(&verdict(family, location), Some(marker(family, location)))
                .with_framed_content_length(0);
            assert_eq!(meta.authenticated_aws_location(), Some(location));
        }
    }
}

/// Negative — reusing a view with invalid proof input clears a previously authenticated fact.
#[test]
fn invalid_proofs_clear_a_previously_authenticated_location() {
    let wire = wire();
    let header = Some(marker(SigFamily::V4, SigLocation::Header));
    let anonymous = Verdict::anonymous(CredentialPresence::NONE.into_evidence().expect("no credentials"));
    let cases = [
        (Verdict::reject(AuthError::AccessDenied), header),
        (anonymous, header),
        (verdict(SigFamily::V4, SigLocation::Header), None),
        (verdict(SigFamily::V4, SigLocation::Query), header),
        (verdict(SigFamily::V2, SigLocation::Header), header),
    ];
    let locations = cases.map(|(invalid, original)| {
        MetaView::of(&wire, TargetKind::Service)
            .expect("a service view")
            .with_authenticated_aws_marker(&verdict(SigFamily::V4, SigLocation::Header), header)
            .with_authenticated_aws_marker(&invalid, original)
            .authenticated_aws_location()
    });
    assert_eq!(locations, [None; 5]);
}
