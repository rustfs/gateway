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

//! Every argument of the lifecycle contract, built out of a decoded request and nothing else.
//!
//! Responsible for: proving that a backend outside this workspace can *call*
//! [`validate_lifecycle`] — not that it is exported, which `facade_probe.rs` already covers, but
//! that its one argument, a [`dto::BucketLifecycleConfiguration`], is exactly the value
//! `PutBucketLifecycleConfiguration` hands a handler after decoding a real wire document, with no
//! bridging or re-deriving of any rule in between.
//! NOT responsible for: what the rules decide, which is `rustfs-gateway-core`'s
//! `ops/shared/lifecycle.rs` inline tests; the `decode ∘ encode` identity over the same shape,
//! which `crates/core/tests/lifecycle_roundtrip.rs` owns; or the wire shape of any one fixed
//! document, which the `lifecycle/` conformance corpus pins.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Issue #15 found `evaluate_range` exported and uncallable, and left the rest of the exported
//! surface open with the acceptance bar: **every argument of every exported constructor must be
//! constructible from `Req<O>` alone.** The lifecycle contract was never checked against that bar.
//! `validate_lifecycle` is called today only by the conformance fixture's own reference
//! implementation (`crates/conformance/src/fixture.rs`) — nothing in this workspace proves a
//! backend outside it can decode a real `PutBucketLifecycleConfiguration` write and hand the
//! result straight to the shared validator, rather than re-deriving the filter grammar, the
//! expiration mutex, the midnight rule or the id caps by hand the way the range mirror once did.
//! Unlike the tagging and precondition contracts this file joins, `validate_lifecycle` takes its
//! one argument as-is off the decoded `Input` — there is no header-string bridge to prove, only
//! that the DTO the generated codec produces is the DTO the validator wants.

use bytes::Bytes;
use rustfs_gateway::{
    Limits, MAX_LIFECYCLE_ID_CHARS, MAX_LIFECYCLE_RULES, MetaView, OperationCodec, RequestBody, TargetKind, WireRequest, dto,
    validate_lifecycle,
};

/// A request as it reaches a decoder, with whatever header lines the case needs. Every case here
/// declares the checksum header `PutBucketLifecycleConfiguration`'s `httpChecksumRequired` trait
/// demands, the same way `crates/core/tests/lifecycle_roundtrip.rs` does — the integrity claim's
/// value is a lower layer's concern and no case here exercises it.
fn accepted(headers: &[(&'static str, &'static str)], body: &str) -> dto::PutBucketLifecycleConfigurationInput {
    let mut request = http::Request::builder()
        .method("PUT")
        .uri("http://host.invalid/conf-lifecycle?lifecycle")
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    for (name, value) in headers {
        request
            .headers_mut()
            .append(http::HeaderName::from_static(name), http::HeaderValue::from_static(value));
    }
    let wire = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    let view = MetaView::of(&wire, TargetKind::Bucket).expect("the path has one label");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(body.as_bytes()));
    dto::PutBucketLifecycleConfiguration::decode(&view, body).expect("a well-formed lifecycle write is not a refusal")
}

/// The integrity header every case below carries, unexamined by anything under test.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

/// `n` numbered, prefix-scoped rules, each with a distinct `<ID>`.
fn numbered_rules_document(n: usize) -> String {
    let mut out = String::from("<LifecycleConfiguration>");
    for i in 0..n {
        out.push_str(&format!(
            "<Rule><ID>rule-{i}</ID><Prefix>logs-{i}/</Prefix><Status>Enabled</Status>\
             <Expiration><Days>30</Days></Expiration></Rule>"
        ));
    }
    out.push_str("</LifecycleConfiguration>");
    out
}

// ---------------------------------------------------------------------------------------------
// Positive — a decoded write reaches the handler and the validator accepts it.
// ---------------------------------------------------------------------------------------------

/// Positive — a single, well-formed rule decodes and the validator accepts the document exactly
/// as the decoder produced it, with no field re-derived along the way.
#[test]
fn a_well_formed_lifecycle_write_reaches_the_handler() {
    let document = "<LifecycleConfiguration><Rule><ID>archive</ID><Prefix>logs/</Prefix>\
                     <Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule>\
                     </LifecycleConfiguration>";
    let input = accepted(INTEGRITY, document);
    let configuration = input.lifecycle_configuration.expect("the document decoded to Some");
    assert_eq!(configuration.rules.len(), 1);
    validate_lifecycle(&configuration).expect("one prefix-scoped, positive-day rule is under every ceiling");
}

/// Positive — a write that omits the body entirely (deleting the lifecycle configuration through
/// an empty `PUT`, which the codec does not itself refuse) decodes to `None` — a case a backend
/// must handle without calling the validator on an absent document.
#[test]
fn a_write_with_no_body_reaches_the_handler_as_no_configuration() {
    let input = accepted(INTEGRITY, "");
    assert!(
        input.lifecycle_configuration.is_none(),
        "an empty body must not decode to a configuration with zero rules"
    );
}

/// Positive — exactly [`MAX_LIFECYCLE_RULES`] rules, each with a distinct id at
/// [`MAX_LIFECYCLE_ID_CHARS`], reaches the handler and the validator accepts the document at the
/// documented ceiling, not one past it — the same boundary
/// `ops::shared::lifecycle`'s own `the_rule_cap_and_the_id_cap_are_inclusive` pins internally,
/// reached here through the wire instead of a hand-built DTO.
#[test]
fn a_lifecycle_write_at_the_rule_and_id_ceilings_reaches_the_handler() {
    let document = numbered_rules_document(MAX_LIFECYCLE_RULES);
    let input = accepted(INTEGRITY, &document);
    let mut configuration = input.lifecycle_configuration.expect("the document decoded to Some");
    assert_eq!(configuration.rules.len(), MAX_LIFECYCLE_RULES);
    if let Some(first) = configuration.rules.first_mut() {
        first.id = Some("i".repeat(MAX_LIFECYCLE_ID_CHARS));
    }
    validate_lifecycle(&configuration).expect("exactly the documented ceiling on both axes is not past it");
}

// ---------------------------------------------------------------------------------------------
// Negative — a decoded write reaches the handler but the validator refuses it.
// ---------------------------------------------------------------------------------------------

/// Negative — a rule naming neither a `<Filter>` nor the legacy rule-level `<Prefix>` decodes
/// without complaint (the generated codec has no scope rule of its own) and is refused only once
/// the shared validator runs — proving the wire actually reaches the same scope rule the inline
/// unit tests exercise on a hand-built DTO.
#[test]
fn n_a_scopeless_rule_reaches_the_handler_and_is_refused() {
    let document = "<LifecycleConfiguration><Rule><ID>no-scope</ID><Status>Enabled</Status>\
                     <Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>";
    let input = accepted(INTEGRITY, document);
    let configuration = input.lifecycle_configuration.expect("the document decoded to Some");
    let result = validate_lifecycle(&configuration);
    assert!(result.is_err(), "a rule naming neither Filter nor Prefix says nothing about its objects");
}

/// Negative — two rules sharing the same `<ID>` decode independently (the generated codec has no
/// uniqueness rule of its own) and are refused only once the shared validator runs across the
/// whole document, not per rule.
#[test]
fn n_a_duplicated_rule_id_reaches_the_handler_and_is_refused() {
    let document = "<LifecycleConfiguration>\
                     <Rule><ID>dup</ID><Prefix>a/</Prefix><Status>Enabled</Status></Rule>\
                     <Rule><ID>dup</ID><Prefix>b/</Prefix><Status>Enabled</Status></Rule>\
                     </LifecycleConfiguration>";
    let input = accepted(INTEGRITY, document);
    let configuration = input.lifecycle_configuration.expect("the document decoded to Some");
    assert_eq!(
        configuration.rules.len(),
        2,
        "the codec decoded both rules; nothing collapsed them on the way in"
    );
    let result = validate_lifecycle(&configuration);
    assert!(result.is_err(), "the same rule id twice must be refused, not last-write-wins");
}

/// Negative — an `<Expiration>` naming both `<Days>` and `<ExpiredObjectDeleteMarker>` decodes
/// without complaint and is refused only by the shared mutex — the wire's boolean-flag member
/// reaches the validator as `Some(false)`, not absent, which is the trap
/// `n_a_delete_marker_flag_beside_days_is_malformed_even_when_false` pins on a hand-built DTO.
#[test]
fn n_an_expiration_mutex_violation_reaches_the_handler_and_is_refused() {
    let document = "<LifecycleConfiguration><Rule><ID>conflict</ID><Prefix>a/</Prefix>\
                     <Status>Enabled</Status><Expiration><Days>10</Days>\
                     <ExpiredObjectDeleteMarker>false</ExpiredObjectDeleteMarker></Expiration>\
                     </Rule></LifecycleConfiguration>";
    let input = accepted(INTEGRITY, document);
    let configuration = input.lifecycle_configuration.expect("the document decoded to Some");
    let result = validate_lifecycle(&configuration);
    assert!(
        result.is_err(),
        "Days and ExpiredObjectDeleteMarker naming the same Expiration together is refused, even when the flag is false"
    );
}

/// Negative — the rule cap is documented at [`MAX_LIFECYCLE_RULES`]; one rule past it decodes
/// cleanly (the generated codec places no cap of its own on the rule list) and is refused only by
/// the shared validator, reached from the wire rather than a hand-built `Vec`.
#[test]
fn n_one_rule_past_the_cap_reaches_the_handler_and_is_refused() {
    let document = numbered_rules_document(MAX_LIFECYCLE_RULES + 1);
    let input = accepted(INTEGRITY, &document);
    let configuration = input.lifecycle_configuration.expect("the document decoded to Some");
    assert_eq!(configuration.rules.len(), MAX_LIFECYCLE_RULES + 1);
    let result = validate_lifecycle(&configuration);
    assert!(result.is_err(), "one rule past the documented cap of MAX_LIFECYCLE_RULES is refused");
}
