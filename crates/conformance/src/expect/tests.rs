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

//! Tests for the expectation engine.
//!
//! Responsible for: proving each assertion fires — an assertion that cannot be shown to fail is
//! an assertion that is not there. Negative cases outnumber positive ones by construction: for
//! every "this holds" there is at least one "and this is what breaks it".
//! NOT responsible for: the corpus (`crate::corpus`) or the transport (`crate::sut`).
//! Upstream: `super`. Downstream: nothing.

use super::*;
use crate::observation::{ConnectionState, Observation, Outcome, StreamTermination};
use crate::toml;

struct Goldens(Vec<(&'static str, &'static [u8])>);

impl GoldenSource for Goldens {
    fn read_golden(&self, relative: &str) -> Result<Vec<u8>, String> {
        self.0
            .iter()
            .find(|(name, _)| *name == relative)
            .map(|(_, bytes)| bytes.to_vec())
            .ok_or_else(|| format!("no such golden `{relative}`"))
    }
}

fn no_goldens() -> Goldens {
    Goldens(Vec::new())
}

fn expectation(source: &str) -> Value {
    toml::parse(source).expect("valid TOML")
}

fn rules(judgement: &Judgement) -> Vec<&str> {
    judgement.diagnostics.iter().map(|d| d.rule.as_str()).collect()
}

fn ok_response() -> Observation {
    Observation::response(
        200,
        vec![
            ("Content-Type".to_owned(), "application/xml".to_owned()),
            ("ETag".to_owned(), "\"abc\"".to_owned()),
        ],
        b"<Error><Code>NoSuchKey</Code><Message>gone</Message><RequestId>rid</RequestId></Error>".to_vec(),
    )
}

#[test]
fn a_satisfied_expectation_produces_no_diagnostics() {
    let expect = expectation("kind = \"response\"\nstatus = 200\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert!(judgement.is_clean(), "{:?}", judgement.diagnostics);
}

#[test]
fn a_wrong_status_names_expected_and_actual() {
    let expect = expectation("kind = \"response\"\nstatus = 412\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/status"]);
    assert!(judgement.diagnostics[0].message.contains("expected status 412, observed 200"));
}

#[test]
fn a_wrong_kind_is_reported_even_when_the_status_matches() {
    let expect = expectation("kind = \"stream_error\"\nstatus = 200\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/kind"]);
}

#[test]
fn every_failing_assertion_is_reported_not_just_the_first() {
    let expect = expectation("kind = \"response\"\nstatus = 404\nheaders_absent = [\"etag\"]\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/status", "expect/headers_absent"]);
}

#[test]
fn header_absence_is_case_insensitive_by_default() {
    let expect = expectation("kind = \"response\"\nstatus = 200\nheaders_absent = [\"etag\"]\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/headers_absent"]);
}

#[test]
fn a_star_value_asserts_presence_with_any_value() {
    let expect = expectation("kind = \"response\"\nstatus = 200\n[headers_present]\n\"etag\" = \"*\"\n");
    assert!(judge(&expect, &ok_response(), "/expect", &no_goldens()).is_clean());
}

#[test]
fn a_missing_header_is_reported_with_what_was_on_the_wire() {
    let expect = expectation("kind = \"response\"\nstatus = 200\n[headers_present]\n\"x-amz-version-id\" = \"*\"\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/headers_present"]);
    assert!(judgement.diagnostics[0].message.contains("no such header"));
}

#[test]
fn headers_exact_rejects_a_header_the_case_did_not_declare() {
    let expect = expectation("kind = \"response\"\nstatus = 200\n[headers_exact]\n\"content-type\" = \"application/xml\"\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/headers_exact"]);
    assert!(judgement.diagnostics[0].message.contains("ETag"));
}

#[test]
fn headers_exact_ignores_the_hop_by_hop_set() {
    let mut observed = ok_response();
    observed.headers.push(("Connection".to_owned(), "keep-alive".to_owned()));
    observed
        .headers
        .push(("Date".to_owned(), "Fri, 02 Jan 2026 03:04:05 GMT".to_owned()));
    let expect = expectation(
        "kind = \"response\"\nstatus = 200\n[headers_exact]\n\"content-type\" = \"application/xml\"\n\"etag\" = \"\\\"abc\\\"\"\n",
    );
    assert!(judge(&expect, &observed, "/expect", &no_goldens()).is_clean());
}

#[test]
fn header_name_bytes_exact_makes_casing_significant() {
    let expect =
        expectation("kind = \"response\"\nstatus = 200\nheader_name_bytes_exact = true\n[headers_present]\n\"etag\" = \"*\"\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/headers_present"]);
}

#[test]
fn header_order_catches_a_swap() {
    let expect = expectation("kind = \"response\"\nstatus = 200\nheader_order = [\"etag\", \"content-type\"]\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/header_order"]);
}

#[test]
fn an_error_code_is_asserted_against_the_element_not_the_status() {
    let expect = expectation("kind = \"response\"\nstatus = 200\n[error]\ncode = \"NoSuchBucket\"\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/error.code"]);
    assert!(judgement.diagnostics[0].message.contains("<Code>NoSuchKey</Code>"));
}

#[test]
fn a_required_request_id_that_is_absent_fails() {
    let mut observed = ok_response();
    observed.body = b"<Error><Code>NoSuchKey</Code></Error>".to_vec();
    let expect = expectation("kind = \"response\"\nstatus = 200\n[error]\nrequest_id_present = true\n");
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/error.request_id_present"]);
}

#[test]
fn an_exact_body_mismatch_reports_the_byte_offset_and_a_window() {
    let mut observed = ok_response();
    observed.body = b"hello world".to_vec();
    let expect = expectation("kind = \"response\"\nstatus = 200\n[body]\nexact_utf8 = \"hello WORLD\"\n");
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/body.exact_utf8"]);
    assert!(
        judgement.diagnostics[0].message.contains("byte 6"),
        "{}",
        judgement.diagnostics[0].message
    );
    assert!(judgement.diagnostics[0].message.contains("observed: hello world"));
}

#[test]
fn redaction_lets_a_server_minted_value_be_pinned_byte_for_byte() {
    let mut observed = ok_response();
    observed.body = b"<Error><Code>X</Code><RequestId>9f2c</RequestId></Error>".to_vec();
    let expect = expectation(
        "kind = \"response\"\nstatus = 200\n[body]\nredact = [\"RequestId\"]\nexact_utf8 = \"<Error><Code>X</Code><RequestId>__REDACTED__</RequestId></Error>\"\n",
    );
    assert!(judge(&expect, &observed, "/expect", &no_goldens()).is_clean());
}

#[test]
fn redaction_does_not_hide_a_difference_outside_the_redacted_element() {
    let mut observed = ok_response();
    observed.body = b"<Error><Code>Y</Code><RequestId>9f2c</RequestId></Error>".to_vec();
    let expect = expectation(
        "kind = \"response\"\nstatus = 200\n[body]\nredact = [\"RequestId\"]\nexact_utf8 = \"<Error><Code>X</Code><RequestId>__REDACTED__</RequestId></Error>\"\n",
    );
    assert_eq!(
        rules(&judge(&expect, &observed, "/expect", &no_goldens())),
        vec!["expect/body.exact_utf8"]
    );
}

#[test]
fn a_golden_matches_with_one_trailing_newline_stripped() {
    let goldens = Goldens(vec![("goldens/a.xml", b"<A></A>\n")]);
    let mut observed = ok_response();
    observed.body = b"<A></A>".to_vec();
    let expect = expectation("kind = \"response\"\nstatus = 200\n[body]\ngolden = \"goldens/a.xml\"\n");
    assert!(judge(&expect, &observed, "/expect", &goldens).is_clean());
}

#[test]
fn a_missing_golden_fails_the_case_rather_than_passing_it() {
    let expect = expectation("kind = \"response\"\nstatus = 200\n[body]\ngolden = \"goldens/absent.xml\"\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/body.golden"]);
}

#[test]
fn an_empty_element_written_the_other_way_is_caught() {
    let goldens = Goldens(vec![("goldens/a.xml", b"<A><Prefix/></A>")]);
    let mut observed = ok_response();
    observed.body = b"<A><Prefix></Prefix></A>".to_vec();
    let expect = expectation("kind = \"response\"\nstatus = 200\n[body]\ngolden = \"goldens/a.xml\"\n");
    assert_eq!(rules(&judge(&expect, &observed, "/expect", &goldens)), vec!["expect/body.golden"]);
}

#[test]
fn a_dropped_xmlns_is_caught_by_the_xml_block() {
    let mut observed = ok_response();
    observed.body = b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>".to_vec();
    let expect = expectation(
        "kind = \"response\"\nstatus = 200\n[body.xml]\nroot = \"ListBucketResult\"\nxmlns = \"http://s3.amazonaws.com/doc/2006-03-01/\"\n",
    );
    assert_eq!(rules(&judge(&expect, &observed, "/expect", &no_goldens())), vec!["expect/body.xml.xmlns"]);
}

#[test]
fn a_reordered_element_is_caught() {
    let mut observed = ok_response();
    observed.body = b"<R><B>1</B><A>2</A></R>".to_vec();
    let expect = expectation("kind = \"response\"\nstatus = 200\n[body.xml]\nelement_order = [\"A\", \"B\"]\n");
    assert_eq!(
        rules(&judge(&expect, &observed, "/expect", &no_goldens())),
        vec!["expect/body.xml.element_order"]
    );
}

#[test]
fn a_paired_empty_element_requirement_rejects_a_self_closing_one() {
    let mut observed = ok_response();
    observed.body = b"<R><Prefix/></R>".to_vec();
    let expect = expectation("kind = \"response\"\nstatus = 200\n[body.xml]\nempty_elements = \"paired\"\n");
    assert_eq!(
        rules(&judge(&expect, &observed, "/expect", &no_goldens())),
        vec!["expect/body.xml.empty_elements"]
    );
}

#[test]
fn a_body_size_and_a_digest_are_both_checked() {
    let mut observed = ok_response();
    observed.body = b"hello world".to_vec();
    let expect = expectation(
        "kind = \"response\"\nstatus = 200\n[body]\nsize = 5\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
    );
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/body.sha256", "expect/body.size"]);
}

/// Negative — and the reason `not_contains_utf8` is the one body assertion redaction is not applied
/// to. A leaked credential appearing inside the very element a case redacts is the case this exists
/// for; normalising it away first would report the leak as absent.
#[test]
fn redaction_does_not_excuse_forbidden_bytes_inside_the_redacted_element() {
    let mut observed = ok_response();
    observed.body = b"<Error><Code>X</Code><StringToSign>AWS4-HMAC-SHA256 Credential</StringToSign></Error>".to_vec();
    let expect = expectation(
        "kind = \"response\"\nstatus = 200\n[body]\nredact = [\"StringToSign\"]\nnot_contains_utf8 = [\"AWS4-HMAC-SHA256 Credential\"]\n",
    );
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/body.not_contains_utf8"]);
}

/// A case cannot write an opaque value it did not mint, so the only way to assert *where* one sits
/// is to name the placeholder. That needs `contains_utf8` judged against the redacted body.
#[test]
fn contains_can_name_a_server_minted_value_by_its_placeholder() {
    let mut observed = ok_response();
    observed.body = b"<List><IsTruncated>true</IsTruncated><Next>612f312e747874-b3c2d2e1</Next></List>".to_vec();
    let expect = expectation(
        "kind = \"response\"\nstatus = 200\n[body]\nredact = [\"Next\"]\ncontains_utf8 = [\"<Next>__REDACTED__</Next>\"]\n",
    );
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert!(rules(&judgement).is_empty(), "{:?}", rules(&judgement));
}

/// Negative — the same expectation against an element that is present and blank. Redaction must not
/// fill it, or "present and not empty" collapses into "present", and a cursor element with nothing
/// in it is the dead end the assertion exists to catch.
#[test]
fn an_empty_element_does_not_satisfy_a_redacted_placeholder() {
    let mut observed = ok_response();
    observed.body = b"<List><IsTruncated>true</IsTruncated><Next></Next></List>".to_vec();
    let expect = expectation(
        "kind = \"response\"\nstatus = 200\n[body]\nredact = [\"Next\"]\ncontains_utf8 = [\"<Next>__REDACTED__</Next>\"]\nnot_contains_utf8 = [\"<Next></Next>\"]\n",
    );
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert_eq!(
        rules(&judgement),
        vec!["expect/body.contains_utf8", "expect/body.not_contains_utf8"],
        "both halves of the assertion have to fire, or one of them was never really asserting"
    );
}

#[test]
fn the_two_byte_counters_are_not_interchangeable() {
    let mut observed = ok_response();
    observed.outcome = Outcome::StreamError;
    observed.stream_termination = Some(StreamTermination::ErrorDocument);
    observed.body_bytes_before_error = Some(10);
    observed.request_body_bytes_sent_at_response = Some(0);
    let expect = expectation(
        "kind = \"stream_error\"\nstream_termination = \"error_document\"\nstatus = 200\nbody_bytes_before_error = 0\n[request_progress]\nbody_bytes_sent_at_response = 0\n",
    );
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/body_bytes_before_error"]);
}

#[test]
fn a_refusal_that_arrived_after_the_payload_fails_the_progress_assertion() {
    let mut observed = ok_response();
    observed.request_body_bytes_sent_at_response = Some(24);
    let expect = expectation("kind = \"response\"\nstatus = 200\n[request_progress]\nbody_bytes_sent_at_response = 0\n");
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/request_progress.body_bytes_sent_at_response"]);
    assert!(
        judgement.diagnostics[0]
            .message
            .contains("consumed the payload before refusing")
    );
}

#[test]
fn an_unrecorded_counter_fails_rather_than_passing_vacuously() {
    let expect = expectation("kind = \"response\"\nstatus = 200\n[request_progress]\nbody_fully_sent = false\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/request_progress.body_fully_sent"]);
}

#[test]
fn a_late_response_fails_the_termination_budget() {
    let mut observed = ok_response();
    observed.elapsed_ms = 6000;
    let expect = expectation("kind = \"response\"\nstatus = 200\n[timing]\nterminate_within_ms = 5000\n");
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/timing.terminate_within_ms"]);
}

#[test]
fn a_connection_that_was_torn_down_fails_an_open_expectation() {
    let mut observed = ok_response();
    observed.connection_after = Some(ConnectionState::Closed);
    let expect = expectation("kind = \"response\"\nstatus = 200\nconnection_after = \"open\"\n");
    assert_eq!(
        rules(&judge(&expect, &observed, "/expect", &no_goldens())),
        vec!["expect/connection_after"]
    );
}

#[test]
fn a_capture_binds_a_value_for_the_next_exchange() {
    let mut observed = ok_response();
    observed.body = b"<R><NextContinuationToken>tok-1</NextContinuationToken></R>".to_vec();
    let expect = expectation("kind = \"response\"\nstatus = 200\n[capture.next_token]\nxml_text = \"NextContinuationToken\"\n");
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert!(judgement.is_clean(), "{:?}", judgement.diagnostics);
    assert_eq!(judgement.captures.get("next_token").map(String::as_str), Some("tok-1"));
}

#[test]
fn a_capture_with_no_source_element_fails_instead_of_binding_nothing() {
    let expect = expectation("kind = \"response\"\nstatus = 200\n[capture.upload_id]\nxml_text = \"UploadId\"\n");
    let judgement = judge(&expect, &ok_response(), "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/capture"]);
}

#[test]
fn an_event_stream_frame_shortfall_is_reported() {
    let mut observed = ok_response();
    observed.outcome = Outcome::EventStream;
    let expect = expectation("kind = \"event_stream\"\n[[events]]\ntype = \"Records\"\nmin_count = 1\n");
    let judgement = judge(&expect, &observed, "/expect", &no_goldens());
    assert_eq!(rules(&judgement), vec!["expect/events.min_count"]);
}
