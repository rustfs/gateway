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
use crate::socket::SERVER_READ_TIMEOUT;
use crate::toml;
use std::io::Read;
use std::net::TcpListener as RawTcpListener;
use std::sync::mpsc;
use std::time::Instant;

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

/// Positive — the batch opens two independently observed client endpoints, dispatches both
/// requests, and only then reads their responses.
#[test]
fn concurrent_dispatch_uses_two_real_sockets() {
    let mut conn = target();
    conn.prepare("s-concurrent-0001", None).expect("the empty fixture prepares");
    let connection = block("concurrent = true\n");
    let request = block(concat!(
        "method = \"GET\"\ntarget = \"/missing-bucket/key\"\n",
        "sign = { mode = \"sigv4_header\", service = \"s3\", region = \"us-east-1\", credential = \"valid\" }\n",
    ));
    let plans = [
        ExchangePlan {
            case_id: "s-concurrent-0001",
            index: 0,
            request: request.clone(),
            clock: None,
            connection: Some(&connection),
            timeout_ms: Some(2_000),
            transport: rustfs_gateway::Transport::Hyper,
            profile: crate::sut::Profile::Aws,
        },
        ExchangePlan {
            case_id: "s-concurrent-0001",
            index: 1,
            request,
            clock: None,
            connection: Some(&connection),
            timeout_ms: Some(2_000),
            transport: rustfs_gateway::Transport::Hyper,
            profile: crate::sut::Profile::Aws,
        },
    ];
    let observations = conn.exchange_concurrent(&plans).expect("both sockets are driven");
    assert_eq!(observations.len(), 2);
    assert!(observations.iter().all(|observation| observation.status.is_some()));
    assert!(
        observations
            .iter()
            .all(|observation| observation.connection_after == Some(ConnectionState::Open)),
        "{:?}",
        observations
            .iter()
            .map(|observation| (observation.status, observation.connection_after))
            .collect::<Vec<_>>()
    );
}

/// Negative — a one-request batch cannot masquerade as concurrency.
#[test]
fn concurrent_dispatch_requires_two_exchanges() {
    let mut conn = target();
    let connection = block("concurrent = true\n");
    let plan = ExchangePlan {
        case_id: "s-concurrent-0002",
        index: 0,
        request: block("method = \"GET\"\ntarget = \"/\"\n"),
        clock: None,
        connection: Some(&connection),
        timeout_ms: Some(2_000),
        transport: rustfs_gateway::Transport::Hyper,
        profile: crate::sut::Profile::Aws,
    };
    let error = conn.exchange_concurrent(&[plan]).expect_err("one exchange is not concurrent");
    assert!(error.to_string().contains("at least two"), "{error}");
}

/// Negative — reuse would collapse the independent-client meaning of the new dimension.
#[test]
fn concurrent_dispatch_refuses_reuse() {
    let error = read_concurrent_connection(Some(&block("concurrent = true\nreuse = true\n"))).expect_err("reuse must be refused");
    assert!(error.to_string().contains("reuse"), "{error}");
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
    let error = control(
        &mut connection,
        &pacer,
        &mut 0,
        "stop_reading",
        0,
        10,
        Instant::now() + Duration::from_millis(50),
    )
    .expect_err("must be refused");
    assert!(format!("{error}").contains("stop_reading"), "{error}");
}

/// Negative — peer handover and a teardown delay share one absolute exchange budget.
#[test]
fn a_control_delay_cannot_outlive_the_exchange_deadline() {
    for action in ["half_close", "close"] {
        let listener = RawTcpListener::bind("127.0.0.1:0").expect("a loopback listener binds");
        let addr = listener.local_addr().expect("the listener has an address");
        let server = std::thread::spawn(move || listener.accept().expect("the client connects"));
        let mut connection = Connection::open(addr).expect("the listener accepts");
        let (mut peer, _) = server.join().expect("the listener exits");
        let error = control(
            &mut connection,
            &Arc::new(Pacer::new()),
            &mut 0,
            action,
            80,
            0,
            Instant::now() + Duration::from_millis(100),
        )
        .expect_err("the delay exceeds the deadline");
        assert!(format!("{error}").contains("exhausted its declared timeout"), "{action}: {error}");
        assert!(!connection.torn_down(), "{action}: an invalid delay must not tear down the socket");

        peer.set_read_timeout(Some(Duration::from_millis(20)))
            .expect("the peer gets an observation budget");
        let mut byte = [0_u8; 1];
        let read = peer.read(&mut byte);
        assert!(
            matches!(
                read,
                Err(ref error)
                    if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
            ),
            "{action}: the peer observed a premature socket change: {read:?}"
        );
    }
}

/// Negative and positive control — teardown delay is reserved before waiting on the peer.
#[test]
fn teardown_delay_is_subtracted_from_the_peer_handover_budget() {
    assert_eq!(
        teardown_handover_budget("half_close", 80, Duration::from_millis(100)).expect("the delay fits"),
        Duration::from_millis(20)
    );
    let error = teardown_handover_budget("close", 101, Duration::from_millis(100)).expect_err("the delay does not fit");
    assert!(format!("{error}").contains("close control chunk"), "{error}");
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
            ChunkStep::Data(bytes, delay_ms) => format!("data:{}:{delay_ms}", bytes.len()),
            ChunkStep::Control { action, delay_ms, .. } => format!("{action}:{delay_ms}"),
        })
        .collect();
    assert_eq!(shape, vec!["data:3:0", "half_close:50", "data:2:0"]);
}

/// Positive and negative control — data-chunk delay is an arrival deadline, not inert prose.
///
/// The first byte has no delay and is released as soon as the real peer asks for it. The second
/// byte carries a 50 ms delay, so the listener must not observe it before that interval has passed.
/// Measuring both bytes on the accepted socket rules out a parser-only implementation that reads
/// `delay_ms` but still writes both chunks together.
#[test]
fn data_chunk_delay_sets_a_not_before_arrival_deadline() {
    let request = block(concat!(
        "method = \"PUT\"\ntarget = \"/conf/k\"\n",
        "[[chunks]]\nraw_utf8 = \"a\"\ndelay_ms = 0\n",
        "[[chunks]]\nraw_utf8 = \"b\"\ndelay_ms = 50\n",
        "[[chunks]]\nraw_utf8 = \"c\"\ndelay_ms = 250\n",
    ));
    let wire = target().inner.read_wire(&request).expect("the request is read");
    let listener = RawTcpListener::bind("127.0.0.1:0").expect("a loopback listener binds");
    let addr = listener.local_addr().expect("the listener has an address");
    let pacer = Arc::new(Pacer::new());
    let server_pacer = Arc::clone(&pacer);
    let (observed_tx, observed_rx) = mpsc::sync_channel(1);

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the client connects");
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).expect("the request head arrives");
            head.push(byte[0]);
        }

        let mut body = [0_u8; 3];
        server_pacer.server_wants_body();
        stream.read_exact(&mut body[..1]).expect("the zero-delay chunk arrives");
        server_pacer.server_wants_body();
        stream.read_exact(&mut body[1..2]).expect("the delayed chunk arrives");
        let second_arrival = Instant::now();
        std::thread::sleep(Duration::from_millis(300));
        server_pacer.server_wants_body();
        stream.read_exact(&mut body[2..]).expect("the already eligible chunk arrives");
        observed_tx.send((body, second_arrival)).expect("the observation is returned");
    });

    let mut connection = Connection::open(addr).expect("the listener accepts");
    connection
        .write(b"PUT /conf/k HTTP/1.1\r\nhost: s3.example.com\r\ncontent-length: 3\r\n\r\n")
        .expect("the request head is written");
    let write_started = Instant::now();
    write_body(&mut connection, &pacer, &wire, 3, write_started + Duration::from_secs(1)).expect("the paced body is written");

    let (body, second_arrival) = observed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("the listener reports arrival times");
    server.join().expect("the listener exits");
    assert_eq!(body, *b"abc", "timing controls must not change payload bytes");
    assert!(
        second_arrival.duration_since(write_started) >= Duration::from_millis(45),
        "the 50 ms chunk arrived only {:?} after the writer started",
        second_arrival.duration_since(write_started)
    );
    assert_eq!(pacer.delay_waits_started(), 1, "only the 50 ms chunk should enter a non-zero delay wait");
}

/// Negative — an early response cancels the production writer's not-before wait.
///
/// The server waits until the writer has entered the five-second delay before answering, so a
/// direct sleep in the writer cannot satisfy the test through scheduling luck.
#[test]
fn an_answer_interrupts_the_production_body_writer() {
    let request = block(concat!(
        "method = \"PUT\"\ntarget = \"/conf/k\"\n",
        "[[chunks]]\nraw_utf8 = \"a\"\ndelay_ms = 0\n",
        "[[chunks]]\nraw_utf8 = \"b\"\ndelay_ms = 5000\n",
    ));
    let wire = target().inner.read_wire(&request).expect("the request is read");
    let listener = RawTcpListener::bind("127.0.0.1:0").expect("a loopback listener binds");
    let addr = listener.local_addr().expect("the listener has an address");
    let pacer = Arc::new(Pacer::new());
    let server_pacer = Arc::clone(&pacer);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the client connects");
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).expect("the request head arrives");
            head.push(byte[0]);
        }
        let mut first = [0_u8; 1];
        server_pacer.server_wants_body();
        stream.read_exact(&mut first).expect("the first chunk arrives");
        server_pacer.server_wants_body();
        assert!(server_pacer.await_delay_wait(Duration::from_secs(1)), "the writer entered its delay");
        server_pacer.server_answered();
        let mut catch_up = [0_u8; 1];
        stream.read_exact(&mut catch_up).expect("the catch-up byte arrives");
    });

    let mut connection = Connection::open(addr).expect("the listener accepts");
    connection
        .write(b"PUT /conf/k HTTP/1.1\r\nhost: s3.example.com\r\ncontent-length: 2\r\n\r\n")
        .expect("the request head is written");
    let started = Instant::now();
    let progress =
        write_body(&mut connection, &pacer, &wire, 2, started + Duration::from_secs(6)).expect("the answer interrupts the delay");
    server.join().expect("the listener exits");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the answer was held for {:?}",
        started.elapsed()
    );
    assert_eq!(progress.sent_at_response, 1, "the delayed byte was not sent before the answer");
    assert_eq!(connection.body_written(), 2, "catch-up preserves the reusable-connection contract");
}

/// Negative — an authored delay longer than the remaining exchange budget fails immediately.
#[test]
fn a_data_chunk_delay_cannot_outlive_the_exchange_deadline() {
    let request = block(concat!(
        "method = \"PUT\"\ntarget = \"/conf/k\"\n",
        "[[chunks]]\nraw_utf8 = \"a\"\ndelay_ms = 100\n",
    ));
    let wire = target().inner.read_wire(&request).expect("the request is read");
    let listener = RawTcpListener::bind("127.0.0.1:0").expect("a loopback listener binds");
    let addr = listener.local_addr().expect("the listener has an address");
    let server = std::thread::spawn(move || listener.accept().expect("the client connects"));
    let mut connection = Connection::open(addr).expect("the listener accepts");
    let error = write_body(
        &mut connection,
        &Arc::new(Pacer::new()),
        &wire,
        1,
        Instant::now() + Duration::from_millis(20),
    )
    .expect_err("the delay exceeds the deadline");
    server.join().expect("the listener exits");
    assert!(format!("{error}").contains("beyond the remaining exchange timeout"), "{error}");
    assert_eq!(connection.body_written(), 0);
}

// -- The safety net -----------------------------------------------------------------------------

/// Negative — the listener safety net must never preempt a delay the exchange budget accepts.
#[test]
fn the_server_read_timeout_outlives_every_accepted_exchange() {
    assert!(
        SERVER_READ_TIMEOUT > budget_of(Some(i64::MAX)),
        "the server read timeout {SERVER_READ_TIMEOUT:?} can preempt the maximum exchange budget {MAX_BUDGET:?}"
    );
}

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
    let error =
        write_body(&mut connection, &pacer, &wire, 14, Instant::now() + Duration::from_millis(30)).expect_err("must not report");
    assert!(format!("{error}").contains("wedged"), "{error}");
    assert_eq!(connection.body_written(), 0);
}
