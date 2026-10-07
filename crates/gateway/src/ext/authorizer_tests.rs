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

//! The authorizer contract's own unit suite, split out of `authorizer.rs` at the 800-line limit.
//!
//! Responsible for: the closure adapters, the `Denial` rendering, `InputAuthzRequest`'s
//! visibility question, and what a `RequestContext` built by hand or from a request hands out —
//! the scheme read off a verdict, the client facts, the raw query and its redacted `Debug`.
//! NOT responsible for: whole-service behaviour, which `tests/authz_contract.rs` and
//! `tests/authz_context_facts.rs` measure through the pipeline.
//! Upstream: `super` (`crate::ext::authorizer`). Downstream: none; this file is a test.

use super::*;

/// One accepted request, so a context can be built the way the pipeline builds one.
fn accepted(target: &str) -> WireRequest<bytes::Bytes> {
    let request = http::Request::builder()
        .uri(target)
        .header("host", "s3.example.com")
        .body(bytes::Bytes::new())
        .expect("a valid request");
    WireRequest::accept(request, &rustfs_gateway_http::Limits::default()).expect("an acceptable request")
}

fn request<'a>(operation: &'a str, identity: Option<&'a Identity>) -> AuthzRequest<'a> {
    AuthzRequest {
        operation,
        action: "s3:GetObject",
        resource: ResourceShape::Object,
        bucket: None,
        key: None,
        copy_source_identity: None,
        version_id: None,
        route_action: "s3:GetObject",
        route_bucket: None,
        route_key: None,
        identity,
        target_origin: TargetOrigin::Path,
        subject: None,
    }
}

#[test]
fn authz_headers_observed_empty_is_distinct_from_unavailable() {
    let policy = PolicySnapshot::of(std::sync::Arc::new(()));
    let now = RequestNow::from_unix_seconds(0);
    let wire = accepted("/");
    let context = RequestContext::from_request(now, &policy, AuthSchemeRef::Anonymous, None, &wire);
    assert!(context.headers().is_some(), "an observed map is still available");
    assert_eq!(context.headers().expect("available").iter_raw().count(), 1, "the host line");
    assert_eq!(context.raw_query(), Some(""), "an observed empty query is still available");
    assert!(context.client().is_none(), "nothing was installed on the accepted request");
    assert!(RequestContext::new(now, &policy).headers().is_none());
}

/// Negative — a context built by hand knows no client and no query, and its typed read path
/// answers nothing: there is no bag to read.
#[test]
fn n_a_manual_context_knows_no_client_and_no_query() {
    let policy = PolicySnapshot::empty();
    let context = RequestContext::new(RequestNow::from_unix_seconds(0), &policy);
    assert!(context.client().is_none());
    assert!(context.raw_query().is_none());
    assert!(context.server_extensions().get::<ClientFacts>().is_none());
    assert!(
        ServerExtensions::of(&TransportExtensions::default())
            .get::<ClientFacts>()
            .is_none()
    );
}

/// Negative — a rejected verdict has no scheme to report; the caller must refuse, not call it
/// anonymous.
#[test]
fn n_a_rejected_verdict_has_no_scheme() {
    let rejected = Verdict::reject(rustfs_gateway_sig::AuthError::InvalidAccessKeyId);
    assert_eq!(AuthSchemeRef::of_verdict(&rejected), None);
}

/// Negative — the context's `Debug` names the query's length and never its bytes.
#[test]
fn n_the_debug_rendering_prints_no_query() {
    let policy = PolicySnapshot::empty();
    let wire = accepted("/?X-Amz-Signature=deadbeef");
    let context =
        RequestContext::from_request(RequestNow::from_unix_seconds(0), &policy, AuthSchemeRef::SigV4Presigned, None, &wire);
    assert_eq!(context.raw_query(), Some("X-Amz-Signature=deadbeef"));
    let rendered = format!("{context:?}");
    assert!(!rendered.contains("deadbeef"), "{rendered}");
    assert!(!rendered.contains("X-Amz"), "{rendered}");
}

fn scheme(family: SigFamily, location: SigLocation) -> AuthScheme {
    AuthScheme::new(
        family,
        location,
        rustfs_gateway_sig::SigIdentity::LongTerm,
        rustfs_gateway_sig::SigService::S3,
    )
}

/// Positive — the six spellings a verdict can carry are read from its family and location.
#[test]
fn the_scheme_is_read_from_the_family_and_the_location() {
    let table = [
        (SigFamily::V4, SigLocation::Header, AuthSchemeRef::SigV4Header),
        (SigFamily::V4, SigLocation::Query, AuthSchemeRef::SigV4Presigned),
        (SigFamily::V2, SigLocation::Header, AuthSchemeRef::SigV2Header),
        (SigFamily::V2, SigLocation::Query, AuthSchemeRef::SigV2Presigned),
        (SigFamily::V4, SigLocation::FormField, AuthSchemeRef::PostPolicy),
        (SigFamily::V2, SigLocation::FormField, AuthSchemeRef::PostPolicy),
    ];
    for (family, location, expected) in table {
        assert_eq!(AuthSchemeRef::of_scheme(&scheme(family, location)), expected, "{family:?} {location:?}");
    }
}

/// Negative — a SigV4a signature is not reported as SigV4 on any carrier: a policy that names
/// SigV4 must not admit a scheme it did not name.
#[test]
fn n_a_sigv4a_signature_is_not_reported_as_sigv4() {
    for location in [SigLocation::Header, SigLocation::Query, SigLocation::FormField] {
        let reported = AuthSchemeRef::of_scheme(&scheme(SigFamily::V4a, location));
        assert_eq!(reported, AuthSchemeRef::OtherSigned, "{location:?}");
        assert!(reported.is_authenticated());
        assert!(!reported.is_presigned());
    }
}

/// Negative — only the anonymous scheme is unauthenticated, and only the query carriers are
/// presigned; a POST policy is neither anonymous nor presigned.
#[test]
fn n_only_anonymous_is_unauthenticated_and_only_query_carriers_are_presigned() {
    let all = [
        AuthSchemeRef::Anonymous,
        AuthSchemeRef::SigV4Header,
        AuthSchemeRef::SigV4Presigned,
        AuthSchemeRef::SigV2Header,
        AuthSchemeRef::SigV2Presigned,
        AuthSchemeRef::PostPolicy,
        AuthSchemeRef::OtherSigned,
    ];
    let unauthenticated: Vec<_> = all.iter().copied().filter(|scheme| !scheme.is_authenticated()).collect();
    assert_eq!(unauthenticated, [AuthSchemeRef::Anonymous]);
    let presigned: Vec<_> = all.iter().copied().filter(|scheme| scheme.is_presigned()).collect();
    assert_eq!(presigned, [AuthSchemeRef::SigV4Presigned, AuthSchemeRef::SigV2Presigned]);
}

/// Negative — the closure adapter refuses when the predicate is false, and the refusal is the
/// ordinary 403 rather than something a caller can mistake for a routing failure.
#[tokio::test]
async fn a_false_predicate_refuses_with_access_denied() {
    let authorizer = allow_when(|request| request.operation == "ListBuckets");
    let policy = PolicySnapshot::empty();
    let context = RequestContext::new(RequestNow::from_unix_seconds(0), &policy);
    assert_eq!(authorizer.authorize_route(&context, &request("GetObject", None)).await, Decision::Deny);
}

/// Negative — a denial renders nothing about the request, so it cannot become a policy oracle.
#[test]
fn a_denial_carries_nothing_from_the_request() {
    let rendered = format!("{:?}", Denial::access_denied());
    assert!(!rendered.contains("GetObject"), "{rendered}");
}

/// Negative — an anonymous request is the one with no identity, and nothing else may produce
/// that answer.
#[test]
fn anonymity_is_the_absence_of_an_identity() {
    let identity = Identity::new("AKIDEXAMPLE").expect("a valid access key id");
    assert!(request("GetObject", None).is_anonymous());
    assert!(!request("GetObject", Some(&identity)).is_anonymous());
}

/// Positive — a true predicate permits, and the adapter is usable behind `Arc<dyn _>`, which
/// is the property ADR-0002 exists to protect.
#[tokio::test]
async fn the_adapter_is_dyn_compatible() {
    let authorizer: std::sync::Arc<dyn Authorizer> = std::sync::Arc::new(allow_when(|_| true));
    let policy = PolicySnapshot::empty();
    let context = RequestContext::new(RequestNow::from_unix_seconds(0), &policy);
    let route = request("GetObject", None);
    assert_eq!(authorizer.authorize_route(&context, &route).await, Decision::Allow);
    let resources = [request("GetObject", None), request("HeadObject", None)];
    let input = InputAuthzRequest::new(&route, &resources);
    let decisions = authorizer.authorize_input(&context, &input).await;
    assert_eq!(decisions.stage(), Decision::Allow);
    assert_eq!(decisions.as_slice(), [Decision::Allow, Decision::Allow]);
    assert_eq!(decisions.visibility(), Some(Decision::Allow));
}

/// Negative — the disclosure check is a separate, non-gating ListBucket decision and retains
/// the addressed key so a prefix-scoped policy can decide the exact read target.
#[tokio::test]
async fn n_get_object_asks_for_its_missing_key_visibility_without_gating_the_read() {
    let bucket = BucketName::new("example-bucket").expect("a valid bucket name");
    let key = ObjectKey::new("private/report.txt").expect("a valid object key");
    let route = AuthzRequest {
        bucket: Some(&bucket),
        key: Some(&key),
        route_bucket: Some(&bucket),
        route_key: Some(&key),
        ..request("GetObject", None)
    };
    let input = InputAuthzRequest::new(&route, &[]);
    let visibility = input.visibility().expect("GetObject asks the auxiliary question");
    assert_eq!(visibility.action, "s3:ListBucket");
    assert_eq!(visibility.resource, ResourceShape::Bucket);
    assert_eq!(visibility.key.map(ObjectKey::as_str), Some("private/report.txt"));
    assert_eq!(visibility.route_action, "s3:GetObject");

    let decisions = input.decide_all(Decision::Allow, |request| {
        if request.action == "s3:ListBucket" {
            Decision::Deny
        } else {
            Decision::Allow
        }
    });
    assert_eq!(decisions.stage(), Decision::Allow);
    assert!(decisions.as_slice().is_empty());
    assert_eq!(decisions.visibility(), Some(Decision::Deny));
}

/// Negative — an operation that happens to reuse the GetObject IAM action does not silently
/// inherit this operation-specific error transition without its own end-to-end contract.
#[test]
fn n_a_sibling_operation_does_not_inherit_get_objects_visibility_transition() {
    let route = request("GetObjectAttributes", None);
    assert!(InputAuthzRequest::new(&route, &[]).visibility().is_none());
}

#[cfg(feature = "dangerous-allow-all-authorizer")]
#[tokio::test]
async fn the_dangerous_authorizer_requires_acknowledgement_and_allows_both_stages() {
    let acknowledgement = DangerAck::i_understand_this_disables_authorization();
    let authorizer = AllowAllAuthorizer::new(acknowledgement);
    let policy = PolicySnapshot::empty();
    let context = RequestContext::new(RequestNow::from_unix_seconds(0), &policy);
    let route = request("GetObject", None);
    assert_eq!(authorizer.authorize_route(&context, &route).await, Decision::Allow);
    let input = InputAuthzRequest::new(&route, &[]);
    let decisions = authorizer.authorize_input(&context, &input).await;
    assert_eq!(decisions.stage(), Decision::Allow);
    assert!(decisions.as_slice().is_empty());
}
