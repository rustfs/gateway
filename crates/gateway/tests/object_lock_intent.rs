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

//! What a lock-state write actually hands a backend, read off a decoded request and nothing else.
//!
//! Responsible for: proving that the object-lock family's *intent* — the retention mode, the
//! retain-until instant, the version selector, the three `x-amz-object-lock-*` headers of an
//! object write, `x-amz-bucket-object-lock-enabled`, and above all
//! `x-amz-bypass-governance-retention` — survives decoding into the input a handler receives, and
//! that the shared validators can be called with it.
//! NOT responsible for: what the rules decide (`rustfs-gateway-core`'s
//! `ops/shared/object_lock.rs` inline tests), what the wire looks like
//! (`conformance/cases/lock/`), or enforcement, which does not exist yet anywhere.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Because the bypass header is the single switch that weakens GOVERNANCE protection, and a
//! header that is parsed and then dropped is invisible to every assertion that looks at a
//! response. `conformance/cases/lock/c-lock-0023` proves the value is *parsed* — an unreadable
//! one is refused rather than guessed — and `c-lock-0009` proves the AWS CLI's capitalised
//! spelling is accepted. Neither can see whether the decoded `true` ever reaches a handler,
//! because this gateway enforces nothing and so answers `200` either way. That is exactly the
//! shape of the defect this repository keeps producing: a check that cannot fail, reading like
//! one that passed.
//!
//! So the assertions below read the decoded input directly. Nothing here spells a wire value as a
//! literal on both sides: every expected value is derived from the header text the request
//! carried, and a binding that stopped populating its field turns these red rather than leaving
//! them green and meaningless.

use rustfs_gateway::{
    Limits, MetaView, ObjectLockRejection, OperationCodec, RequestBody, TargetKind, Timestamp, WireRequest, dto,
    validate_legal_hold, validate_object_write_lock, validate_retention,
};

/// 2026-01-01T00:00:00Z, the instant every clock-dependent assertion below is measured against.
const NOW: i64 = 1_767_225_600;

/// A retention document naming a mode and an instant well past [`NOW`].
const RETENTION: &str =
    "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00.000Z</RetainUntilDate></Retention>";

/// A request as it reaches a decoder, with whatever header lines the case needs.
fn accepted(method: &'static str, uri: &'static str, headers: &[(&'static str, &'static str)]) -> WireRequest<()> {
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    for (name, value) in headers {
        request
            .headers_mut()
            .append(http::HeaderName::from_static(name), http::HeaderValue::from_static(value));
    }
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// What a backend has after `decode` of a retention write, and the only thing these cases read.
fn decoded_retention(uri: &'static str, headers: &[(&'static str, &'static str)]) -> dto::PutObjectRetentionInput {
    let request = accepted("PUT", uri, headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::PutObjectRetention::decode(&view, RequestBody::Buffered(RETENTION.as_bytes().to_vec().into()))
        .expect("a well-formed retention write is not a refusal")
}

/// The integrity claim every write in this family demands, so the decoder reaches the body.
const MD5: (&str, &str) = ("content-md5", "nRP4r9dIhDgQ95myRGb8sw==");

// ── the bypass switch ────────────────────────────────────────────────────────────────────────

/// The capitalised spelling the AWS CLI sends arrives at the handler as `Some(true)`.
///
/// Not `200`, which is what a response assertion can see and what a decoder that threw the header
/// away would also produce. The measurement is the field.
#[test]
fn the_capitalised_bypass_spelling_reaches_the_handler_as_true() {
    let input = decoded_retention(
        "http://host.invalid/conf-lock/doc.txt?retention",
        &[MD5, ("x-amz-bypass-governance-retention", "True")],
    );
    assert_eq!(
        input.bypass_governance_retention,
        Some(true),
        "the bypass intent must reach the handler, not merely be accepted on the wire"
    );
}

/// Negative — an explicit `false` arrives as `Some(false)`, distinct from the absent case.
///
/// The three states are different instructions: bypass, do not bypass, and said nothing. A
/// decoder that collapsed the last two would be indistinguishable from this one on every
/// response, and would silently lose a client's explicit refusal to bypass.
#[test]
fn n_an_explicit_false_is_not_the_same_as_an_absent_header() {
    let explicit = decoded_retention(
        "http://host.invalid/conf-lock/doc.txt?retention",
        &[MD5, ("x-amz-bypass-governance-retention", "False")],
    );
    let absent = decoded_retention("http://host.invalid/conf-lock/doc.txt?retention", &[MD5]);
    assert_eq!(explicit.bypass_governance_retention, Some(false));
    assert_eq!(absent.bypass_governance_retention, None);
    assert_ne!(explicit.bypass_governance_retention, absent.bypass_governance_retention);
}

/// Negative — an unreadable value is refused outright, and never resolves to `true`.
///
/// The direction is the security property: a parser that fell back to `true` for anything it
/// could not read would hand the governance bypass to a typo. Asserting the refusal here as well
/// as on the wire is deliberate — this is the layer where the fallback would live.
#[test]
fn n_an_unreadable_bypass_value_is_refused_rather_than_resolved() {
    for spelling in ["yes", "1", "TrUe1", ""] {
        let mut request = http::Request::builder()
            .method("PUT")
            .uri("http://host.invalid/conf-lock/doc.txt?retention")
            .header("host", "host.invalid")
            .header("content-md5", MD5.1)
            .body(())
            .expect("well formed");
        request.headers_mut().append(
            http::HeaderName::from_static("x-amz-bypass-governance-retention"),
            http::HeaderValue::from_str(spelling).expect("a header value"),
        );
        let request = WireRequest::accept(request, &Limits::default()).expect("acceptable");
        let view = MetaView::of(&request, TargetKind::Object).expect("both labels");
        let outcome = dto::PutObjectRetention::decode(&view, RequestBody::Buffered(RETENTION.as_bytes().to_vec().into()));
        assert!(outcome.is_err(), "{spelling:?} must be refused, never read as a bypass");
    }
}

// ── the document and the version selector ────────────────────────────────────────────────────

/// The mode and the instant reach the handler, and the validator can be called with them.
///
/// The expected instant is parsed from the same text the body carried rather than written twice,
/// so a decoder that lost the milliseconds — or the whole member — fails here instead of matching
/// a literal somebody kept in step by hand.
#[test]
fn the_retention_document_reaches_the_handler_and_the_validator_accepts_it() {
    let input = decoded_retention("http://host.invalid/conf-lock/doc.txt?retention", &[MD5]);
    assert_eq!(input.retention.mode, Some(dto::Mode::GOVERNANCE));
    // The expected instant is spelled as epoch seconds rather than re-parsed from the same text,
    // which is the stronger check of the two: a decoder that stored the header verbatim, or that
    // read the calendar date wrongly, cannot match a number it never saw.
    assert_eq!(input.retention.retain_until_date, Some(Timestamp::from_secs(1_893_456_000)));
    assert_eq!(validate_retention(&input.retention, NOW), Ok(()));
}

/// Negative — the same document is refused once the clock passes the instant it names.
///
/// Both directions of the future-only rule against one decoded document: the value that made the
/// case above pass is the value that makes this one fail, so neither outcome can be a constant.
#[test]
fn n_the_same_document_is_refused_against_a_clock_past_its_instant() {
    let input = decoded_retention("http://host.invalid/conf-lock/doc.txt?retention", &[MD5]);
    let after = input
        .retention
        .retain_until_date
        .as_ref()
        .map_or(0, Timestamp::secs)
        .saturating_add(1);
    assert_eq!(
        validate_retention(&input.retention, after),
        Err(ObjectLockRejection::RetainUntilNotInFuture)
    );
}

/// The version selector reaches the handler, so a backend that serves versions can read it.
///
/// What a backend does with it is the backend's: the conformance fixture selects the named
/// version (`c-lock-0040`, `c-lock-0042`) and refuses an id that names nothing (`c-lock-0028`).
/// This is the codec half those cases stand on: the parameter arrives decoded, exactly once.
#[test]
fn the_version_selector_reaches_the_handler_decoded_once() {
    let input = decoded_retention("http://host.invalid/conf-lock/doc.txt?retention&versionId=v%2F1", &[MD5]);
    assert_eq!(input.version_id.as_deref(), Some("v/1"), "the value is percent-decoded exactly once");
}

/// The legal-hold status reaches the handler and the validator can be called with it.
#[test]
fn the_legal_hold_status_reaches_the_handler() {
    const HOLD: &str = "<LegalHold><Status>ON</Status></LegalHold>";
    let request = accepted(
        "PUT",
        "http://host.invalid/conf-lock/doc.txt?legal-hold",
        &[("content-md5", "oK1+ndJbG6HuGA87LDxznw==")],
    );
    let view = MetaView::of(&request, TargetKind::Object).expect("both labels");
    let input = dto::PutObjectLegalHold::decode(&view, RequestBody::Buffered(HOLD.as_bytes().to_vec().into()))
        .expect("a well-formed hold write is not a refusal");
    assert_eq!(input.legal_hold.status, Some(dto::Status::ON));
    assert_eq!(validate_legal_hold(&input.legal_hold), Ok(()));
}

/// Negative — the governance token reaches the handler on a bucket lock write.
///
/// Nothing in this workspace consults it, which is precisely why it is measured: a header that
/// only enforcement will read is a header nothing else can notice the loss of.
#[test]
fn n_the_bucket_object_lock_token_reaches_the_handler() {
    const CONFIG: &str = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
    let request = accepted(
        "PUT",
        "http://host.invalid/conf-lock?object-lock",
        &[
            ("content-md5", "CJIyG/nMmkjfQ1+FuEdwUA=="),
            ("x-amz-bucket-object-lock-token", "conformance-token"),
        ],
    );
    let view = MetaView::of(&request, TargetKind::Bucket).expect("the path has a bucket label");
    let input = dto::PutObjectLockConfiguration::decode(&view, RequestBody::Buffered(CONFIG.as_bytes().to_vec().into()))
        .expect("a well-formed lock write is not a refusal");
    assert_eq!(input.token.as_deref(), Some("conformance-token"));
    assert_eq!(input.object_lock_configuration.object_lock_enabled, Some(dto::ObjectLockEnabled::ENABLED));
}

// ── the object-write headers ─────────────────────────────────────────────────────────────────
//
// `PutObject` carries the three `x-amz-object-lock-*` headers into a stored lock state the
// conformance corpus can read back (`c-lock-0036`). `CopyObject` and `CreateMultipartUpload` carry
// the same three into an input no fixture read observes, so these assertions read the decoded
// input: present reaches the handler, absent stays `None`, and an unreadable value is refused.

/// The three headers, with the one date format they accept.
const LOCK_HEADERS: [(&str, &str); 3] = [
    ("x-amz-object-lock-mode", "COMPLIANCE"),
    ("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z"),
    ("x-amz-object-lock-legal-hold", "ON"),
];

/// What the three headers decoded to, as plain text and seconds, for either operation.
type LockTriple = (Option<String>, Option<i64>, Option<String>);

fn copy_lock(headers: &[(&'static str, &'static str)]) -> Result<LockTriple, ()> {
    let mut all = vec![("x-amz-copy-source", "/conf-lock/source.txt")];
    all.extend_from_slice(headers);
    let request = accepted("PUT", "http://host.invalid/conf-lock/doc.txt", &all);
    let view = MetaView::of(&request, TargetKind::Object).expect("both labels");
    let input = dto::CopyObject::decode(&view, RequestBody::None).map_err(|_| ())?;
    Ok((
        input.object_lock_mode.map(|mode| mode.as_str().to_owned()),
        input.object_lock_retain_until_date.as_ref().map(Timestamp::secs),
        input.object_lock_legal_hold_status.map(|status| status.as_str().to_owned()),
    ))
}

fn upload_lock(headers: &[(&'static str, &'static str)]) -> Result<LockTriple, ()> {
    let request = accepted("POST", "http://host.invalid/conf-lock/doc.txt?uploads", headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("both labels");
    let input = dto::CreateMultipartUpload::decode(&view, RequestBody::None).map_err(|_| ())?;
    Ok((
        input.object_lock_mode.map(|mode| mode.as_str().to_owned()),
        input.object_lock_retain_until_date.as_ref().map(Timestamp::secs),
        input.object_lock_legal_hold_status.map(|status| status.as_str().to_owned()),
    ))
}

/// All three headers reach both handlers, the ISO 8601 instant as the second it names.
#[test]
fn the_three_lock_headers_reach_the_copy_and_upload_handlers() {
    let expected = Ok((Some("COMPLIANCE".to_owned()), Some(1_893_456_000), Some("ON".to_owned())));
    assert_eq!(copy_lock(&LOCK_HEADERS), expected);
    assert_eq!(upload_lock(&LOCK_HEADERS), expected);
}

/// Negative — absent headers are `None`, not a default lock.
#[test]
fn n_absent_lock_headers_are_none_on_both_handlers() {
    assert_eq!(copy_lock(&[]), Ok((None, None, None)));
    assert_eq!(upload_lock(&[]), Ok((None, None, None)));
}

/// Negative — a retain-until date in HTTP-date form is refused on both, never read as an instant.
///
/// The header is the one request header in ISO 8601 (`q-timestamp-0011`); every other date header
/// is an HTTP date, which is exactly the format a binding written by habit would accept here.
#[test]
fn n_an_http_date_retain_until_is_refused_on_both_handlers() {
    let headers = [
        ("x-amz-object-lock-mode", "GOVERNANCE"),
        ("x-amz-object-lock-retain-until-date", "Tue, 01 Jan 2030 00:00:00 GMT"),
    ];
    assert_eq!(copy_lock(&headers), Err(()));
    assert_eq!(upload_lock(&headers), Err(()));
}

/// Negative — the header twin of the document rules refuses what the decoder carries through.
///
/// The mode and hold enums are open, so an out-of-set value decodes; `validate_object_write_lock`
/// is where it stops, and it has to be callable with exactly what the handler received.
#[test]
fn n_an_out_of_set_mode_decodes_and_the_shared_rule_refuses_it() {
    let headers = [
        ("x-amz-object-lock-mode", "ARCHIVE"),
        ("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z"),
    ];
    let (mode, until, hold) = upload_lock(&headers).expect("an open enum value decodes");
    let until = until.map(Timestamp::from_secs);
    assert_eq!(
        validate_object_write_lock(mode.as_deref(), until.as_ref(), hold.as_deref(), NOW),
        Err(ObjectLockRejection::WriteHeaderValueUnknown)
    );
}

// ── the bucket-creation switch ───────────────────────────────────────────────────────────────

fn create_bucket_lock(value: &'static str) -> Result<Option<bool>, ()> {
    let request = accepted("PUT", "http://host.invalid/conf-lock", &[("x-amz-bucket-object-lock-enabled", value)]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("the path has a bucket label");
    dto::CreateBucket::decode(&view, RequestBody::None)
        .map(|input| input.object_lock_enabled_for_bucket)
        .map_err(|_| ())
}

/// The capitalised spelling enables object lock at creation, like the bypass header's.
#[test]
fn the_capitalised_bucket_lock_spelling_reaches_the_handler_as_true() {
    assert_eq!(create_bucket_lock("True"), Ok(Some(true)));
    assert_eq!(create_bucket_lock("FALSE"), Ok(Some(false)));
}

/// Negative — an unreadable value is refused, never read as "enable object lock".
///
/// Turning object lock on is irreversible, so a guess in the `true` direction is a bucket that can
/// never be unlocked; the conservative direction here is the refusal.
#[test]
fn n_an_unreadable_bucket_lock_value_is_refused() {
    for value in ["yes", "1", "enabled"] {
        assert_eq!(create_bucket_lock(value), Err(()), "{value:?}");
    }
}
