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

//! Compile-time or regression support for this module.
//!
//! Responsible for: exercising the contract named by this file.
//! NOT responsible for: implementing the production behavior under test.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;
use crate::toml;

fn block(source: &str) -> Value {
    toml::parse(source).expect("valid TOML")
}

fn target() -> Conn {
    Conn::new(std::path::PathBuf::from("."))
}

// -- What `[connection]` asks for ---------------------------------------------------------------

/// Negative — every instruction this transport cannot carry out is refused **by name**, so the
/// report says which capability was missing instead of reporting a wrong answer.
///
/// `pipeline` is on this list even though the bytes could be written that way, and the reason is in
/// the message: writing two requests onto one connection is not the same as making them race.
#[test]
fn every_instruction_this_transport_cannot_carry_out_is_refused_by_name() {
    for (source, expected) in [
        ("pipeline = true\n", "pipeline"),
        ("[tls]\nenabled = true\n", "tls"),
        ("read_window_bytes = 16\n", "read_window_bytes"),
        ("idle_timeout_ms = 100\n", "idle_timeout_ms"),
    ] {
        let error = read_connection(Some(&block(source))).expect_err("must be refused");
        assert!(format!("{error}").contains(expected), "{source}: {error}");
    }
}

/// Positive — `reuse` is the one instruction that is carried out, in both directions.
///
/// `false` is not quietly given the same treatment as `true`: `c-mpu-0039` and `c-mpu-0043` each
/// assert something about a *second* connection, and answering them over the first would be
/// answering a different case.
#[test]
fn connection_reuse_is_read_in_both_directions() {
    assert_eq!(read_connection(Some(&block("reuse = true\n"))), Ok(true));
    assert_eq!(read_connection(Some(&block("reuse = false\n"))), Ok(false));
    assert_eq!(read_connection(None), Ok(true), "one connection unless a case says otherwise");
}

// -- Framing ------------------------------------------------------------------------------------

/// Negative — the length the *head* declares is what frames the body, not the payload that follows.
///
/// `c-mpu-0027` announces five gigabytes and writes ten bytes. Signing the ten and framing the ten
/// would send a request that is not the one the case wrote, and the over-cap refusal it is about
/// would never fire.
#[test]
fn the_declared_length_is_the_headers_and_not_the_payloads() {
    let headers = vec![
        ("host".to_owned(), "s3.example.com".to_owned()),
        ("Content-Length".to_owned(), "5368709121".to_owned()),
    ];
    assert_eq!(declared_content_length(&headers), Some(5_368_709_121));
    assert_eq!(declared_content_length(&[("host".to_owned(), "x".to_owned())]), None);
}

/// Negative — a raw head goes on the wire as the case wrote it, and gains only what a signature
/// costs.
///
/// `c-mpu-0045`'s whole subject is the `content-length` that is *not* in its head. A transport that
/// rebuilt the head from a parse — or that helpfully supplied the missing framing header — would
/// send a request the case is not about and answer it correctly, which is the worst of the two
/// possible failures.
#[test]
fn a_raw_head_keeps_its_own_bytes_and_gains_only_a_signature() {
    let request = block(concat!(
        "raw_head_utf8 = \"PUT /conf-mpu/k?partNumber=1 HTTP/1.1\\r\\nhost: s3.localhost\\r\\n",
        "x-amz-content-sha256: UNSIGNED-PAYLOAD\\r\\n\\r\\n\"\n",
        "sign = { mode = \"sigv4_unsigned_payload\", service = \"s3\", region = \"us-east-1\" }\n",
    ));
    let conn = target();
    let wire = conn.inner.read_wire(&request).expect("the request is read");
    let stamp = crate::time::parse_rfc3339(crate::time::DEFAULT_FIXED).expect("a clock");
    let head = conn.head(&wire, &stamp).expect("the head is built");
    let text = String::from_utf8(head.bytes).expect("utf-8");
    assert!(
        text.starts_with("PUT /conf-mpu/k?partNumber=1 HTTP/1.1\r\nhost: s3.localhost\r\n"),
        "{text}"
    );
    assert!(text.contains("x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n"), "{text}");
    assert!(text.to_ascii_lowercase().contains("authorization: aws4-hmac-sha256"), "{text}");
    assert!(
        !text.to_ascii_lowercase().contains("content-length"),
        "the missing framing header is the case: {text}"
    );
    assert_eq!(head.declared_length, 0);
    assert!(text.ends_with("\r\n\r\n"), "the head still ends in one blank line: {text:?}");
}

/// Positive — a structured head supplies the host and the framing the case left implicit, which is
/// what makes an ordinary case writable without spelling out a wire message.
#[test]
fn a_structured_head_supplies_the_host_and_the_framing() {
    let request = block(concat!(
        "method = \"PUT\"\ntarget = \"/conf/k\"\n",
        "body = { utf8 = \"hello world\" }\n",
        "sign = { mode = \"sigv4_header\", service = \"s3\", region = \"us-east-1\" }\n",
    ));
    let conn = target();
    let wire = conn.inner.read_wire(&request).expect("the request is read");
    let stamp = crate::time::parse_rfc3339(crate::time::DEFAULT_FIXED).expect("a clock");
    let head = conn.head(&wire, &stamp).expect("the head is built");
    let text = String::from_utf8(head.bytes).expect("utf-8");
    assert!(text.starts_with("PUT /conf/k HTTP/1.1\r\n"), "{text}");
    assert!(text.contains("host: s3.example.com\r\n"), "{text}");
    assert_eq!(head.declared_length, 11);
}

/// Negative — the method that decides whether an answer has a body is read off the *raw head*,
/// where a case that wrote one put its request line.
///
/// Taking it from `request.method` instead reads an empty string for every raw-head case, and an
/// empty method is not `HEAD`, so a `HEAD` written as a raw head would be read for a body that is
/// never coming.
#[test]
fn the_method_of_a_raw_head_comes_from_its_request_line() {
    let request = block("raw_head_utf8 = \"HEAD /conf/k HTTP/1.1\\r\\nhost: s3.localhost\\r\\n\\r\\n\"\n");
    let conn = target();
    let wire = conn.inner.read_wire(&request).expect("the request is read");
    assert_eq!(wire.method, "", "a raw head declares no `method` of its own");
    let stamp = crate::time::parse_rfc3339(crate::time::DEFAULT_FIXED).expect("a clock");
    let head = conn.head(&wire, &stamp).expect("the head is built");
    assert_eq!(request_method(&wire, &head), "HEAD");
}

// -- Control chunks -----------------------------------------------------------------------------

/// Negative — a control action this transport does not perform is refused rather than dropped.
///
/// A case that scripts a connection-level act and is answered from a connection that never
/// performed it is a false green, and it is the exact shape the in-process target refuses whole.
#[test]
fn an_unperformed_control_action_is_refused_rather_than_dropped() {
    let request = block(concat!(
        "method = \"PUT\"\ntarget = \"/conf/k\"\n",
        "[[chunks]]\nutf8 = \"x\"\n",
        "[[chunks]]\naction = \"stop_reading\"\nduration_ms = 10\n",
    ));
    let conn = target();
    let wire = conn.inner.read_wire(&request).expect("the request is read");
    assert_eq!(wire.control_actions().collect::<Vec<_>>(), vec!["stop_reading"]);

    let listener = Listener::start(
        conn.inner.assemble(0, 0).expect("the service assembles"),
        honour_the_services_intent(),
        Announce::Matching,
    )
    .expect("a listener binds");
    let pacer = Arc::new(Pacer::new());
    listener.enqueue_pacer(&pacer);
    let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
    let error =
        control(&mut connection, &pacer, &mut 0, "stop_reading", 0, 10, Duration::from_millis(50)).expect_err("must be refused");
    assert!(format!("{error}").contains("stop_reading"), "{error}");
}

/// Negative — a control chunk the case wrote survives into the step list beside its bytes, in order.
///
/// Flattening a chunk sequence into "payload plus a note about a close" loses the ordering, and the
/// ordering is the case: `c-mpu-0043` writes twenty-nine bytes *and then* half-closes, and the same
/// two acts the other way round assert nothing at all.
#[test]
fn a_chunk_sequence_keeps_its_control_acts_in_order() {
    let request = block(concat!(
        "method = \"PUT\"\ntarget = \"/conf/k\"\n",
        "[[chunks]]\nraw_utf8 = \"abc\"\n",
        "[[chunks]]\naction = \"half_close\"\ndelay_ms = 50\n",
        "[[chunks]]\nraw_utf8 = \"de\"\n",
    ));
    let wire = target().inner.read_wire(&request).expect("the request is read");
    let shape: Vec<String> = wire
        .steps
        .iter()
        .map(|step| match step {
            ChunkStep::Data(bytes) => format!("data:{}", bytes.len()),
            ChunkStep::Control { action, delay_ms, .. } => format!("{action}:{delay_ms}"),
        })
        .collect();
    assert_eq!(shape, vec!["data:3", "half_close:50", "data:2"]);
}

// -- The safety net -----------------------------------------------------------------------------

/// Negative — the budget is capped however long a case declares, because a wedged exchange must not
/// hold a whole run.
#[test]
fn the_wedge_budget_is_bounded_at_both_ends() {
    assert_eq!(budget_of(None), DEFAULT_BUDGET);
    assert_eq!(budget_of(Some(0)), DEFAULT_BUDGET, "a zero budget is no budget");
    assert_eq!(budget_of(Some(2_000)), Duration::from_millis(2_000));
    assert_eq!(budget_of(Some(120_000)), MAX_BUDGET);
}

/// Negative — an exchange that wedged is an environment failure, not a byte count.
///
/// The distinction is the whole reason `SutError` exists: a skip says "this was not measured", and
/// reporting the frames that happened to have been written before a timeout would say "this was
/// measured and the answer is nine".
#[test]
fn a_wedged_exchange_is_reported_as_unmeasured_rather_than_as_a_count() {
    let request = block(concat!(
        "method = \"PUT\"\ntarget = \"/conf/k\"\n",
        "[[chunks]]\nraw_utf8 = \"never released\"\n",
    ));
    let conn = target();
    let wire = conn.inner.read_wire(&request).expect("the request is read");
    let listener = Listener::start(
        conn.inner.assemble(0, 0).expect("the service assembles"),
        honour_the_services_intent(),
        Announce::Matching,
    )
    .expect("a listener binds");
    // No pacer is enqueued, so the server binds a detached one and this rendezvous is never
    // signalled — a peer that says nothing, which is what the net is for.
    let pacer = Arc::new(Pacer::new());
    let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
    let error = write_body(&mut connection, &pacer, &wire, 14, Duration::from_millis(30)).expect_err("must not report");
    assert!(format!("{error}").contains("wedged"), "{error}");
    assert_eq!(connection.body_written(), 0);
}
