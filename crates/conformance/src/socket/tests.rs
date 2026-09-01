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

//! The socket harness's own contracts.
//!
//! Responsible for: the framing rules this module parses by hand, the close policy it applies, and
//! the four-corner proof that `connection_after` is asked of the socket rather than read off a
//! `Connection:` header.
//! NOT responsible for: what any conformance case concludes — that is the corpus — or for the
//! client half of an exchange, which is `crate::conn`.
//! Upstream: `crate::socket`. Downstream: the repository verification gate.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

/// Negative — a head with no blank line is not a head, however much of it arrived.
#[test]
fn an_unterminated_head_has_no_end() {
    assert_eq!(find_head_end(b"GET / HTTP/1.1\r\nhost: x\r\n"), None);
    assert_eq!(find_head_end(b""), None);
}

/// Positive — the end is just past the blank line, so the next byte is the first body byte.
#[test]
fn the_head_ends_just_past_the_blank_line() {
    let head = b"GET / HTTP/1.1\r\nhost: x\r\n\r\nBODY";
    let end = find_head_end(head).expect("a terminated head");
    assert_eq!(&head[end..], b"BODY");
}

/// Negative — a chunked request declares no length, so the framing must not fall back to a
/// `Content-Length` that a smuggling pair supplied alongside it.
#[test]
fn a_chunked_head_declares_no_length() {
    let head = b"PUT /b/k HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\ncontent-length: 9\r\n\r\n";
    assert_eq!(parse_head(head).expect("parsable").declared_length, None);
}

/// Negative — a request with no framing headers has a zero-length body, not an unbounded one.
///
/// RFC 9112 §6.3. Reading such a request until the peer closed would hang every body-less `GET`
/// on a keep-alive connection, which is the defect this pins.
#[test]
fn a_head_with_no_framing_frames_an_empty_body() {
    let parsed = parse_head(b"PUT /b/k HTTP/1.1\r\nhost: x\r\n\r\n").expect("parsable");
    assert_eq!(parsed.declared_length, Some(0));
    assert_eq!(parsed.method, "PUT");
    assert_eq!(parsed.target, "/b/k");
    // And the head still carries no `content-length`, so the service can still answer `411`.
    assert!(
        !parsed
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    );
}

/// Positive — a declared length survives parsing, because it is what frames the body.
#[test]
fn a_declared_length_is_read() {
    let parsed = parse_head(b"PUT /b/k HTTP/1.1\r\nhost: x\r\ncontent-length: 11\r\n\r\n").expect("parsable");
    assert_eq!(parsed.declared_length, Some(11));
}

/// Negative — a response head that is not a status line yields nothing rather than a zero.
#[test]
fn a_malformed_response_head_is_not_a_status() {
    assert_eq!(parse_response_head("not a status line\r\n\r\n"), None);
    assert_eq!(parse_response_head("HTTP/1.1 nope OK\r\n\r\n"), None);
}

/// Positive — wire casing and wire order survive, because `header_order` and
/// `header_name_bytes_exact` are assertions no normalised map could answer.
#[test]
fn a_response_head_keeps_wire_order_and_casing() {
    let (status, headers) =
        parse_response_head("HTTP/1.1 403 Forbidden\r\nContent-Type: application/xml\r\nX-Amz-Id-2: k\r\n\r\n")
            .expect("parsable");
    assert_eq!(status, 403);
    assert_eq!(headers[0].0, "Content-Type");
    assert_eq!(headers[1].0, "X-Amz-Id-2");
}

/// **Negative — the service's verdict is what closes the connection, and this is where a
/// harness-side rule would show up instead.**
///
/// Both bodies below are abandoned. The one the service said `MayKeepAlive` about is small
/// enough to drain and the connection survives; the one it said `Close` about does not, and no
/// amount of drainability rescues it. A policy that ignored the intent would answer the same
/// for both — which is what "an undrained body closes" did, and the corpus refutes it:
/// `c-object-0013` leaves eleven bytes unread and asserts `open`, `c-sig-0001` leaves
/// twenty-four and asserts `closed`.
#[test]
fn the_intent_decides_and_the_remainder_only_narrows_it() {
    let small = BodyDisposition {
        declared: Some(11),
        consumed: 0,
        drained: false,
    };
    assert_eq!(
        honour_the_services_intent()(&small, ConnectionIntent::MayKeepAlive),
        ConnectionDisposition::Keep
    );
    assert_eq!(
        honour_the_services_intent()(&small, ConnectionIntent::Close),
        ConnectionDisposition::Close,
        "the service's close is not overridden by a body that could have been drained"
    );
}

/// Negative — `MayKeepAlive` over a remainder too large to read is still a close.
///
/// Its own documentation says so: the variant promises the connection survives *if* the
/// remainder is drained, and four megabytes is the transfer a refusal exists to avoid. A
/// transport that read `MayKeepAlive` as "keep" would perform it.
#[test]
fn a_remainder_too_large_to_drain_closes_despite_a_permissive_intent() {
    let abandoned = BodyDisposition {
        declared: Some(4_000_000),
        consumed: 8192,
        drained: false,
    };
    assert!(abandoned.leaves_unread_bytes());
    assert!(abandoned.undrained_bytes() > MAX_LINGER_DRAIN_BYTES);
    assert_eq!(
        honour_the_services_intent()(&abandoned, ConnectionIntent::MayKeepAlive),
        ConnectionDisposition::Close
    );
    // A chunked body that never ended owes an unknowable amount, which is not a licence to
    // guess a small one.
    let unbounded = BodyDisposition {
        declared: None,
        consumed: 8192,
        drained: false,
    };
    assert_eq!(unbounded.undrained_bytes(), u64::MAX);
}

/// Negative — a drained body is not a close, or every exchange would end the connection and
/// `connection_after = "open"` would be unobservable.
#[test]
fn a_drained_body_is_not_a_close() {
    let drained = BodyDisposition {
        declared: Some(11),
        consumed: 11,
        drained: true,
    };
    assert!(!drained.leaves_unread_bytes());
    assert_eq!(drained.undrained_bytes(), 0);
    assert_eq!(
        honour_the_services_intent()(&drained, ConnectionIntent::MayKeepAlive),
        ConnectionDisposition::Keep
    );
}

/// Negative — the control policy never closes, whatever it is handed. The header-versus-socket
/// proof runs against this, and a version that closed under some condition would make the proof
/// vacuous.
#[test]
fn the_control_policy_never_closes() {
    for drained in [true, false] {
        for intent in [ConnectionIntent::MayKeepAlive, ConnectionIntent::Close] {
            let disposition = BodyDisposition {
                declared: Some(9),
                consumed: 0,
                drained,
            };
            assert_eq!(never_close()(&disposition, intent), ConnectionDisposition::Keep);
        }
    }
}

// -- The socket-versus-header proof -------------------------------------------------------
//
// Everything below drives a real listener on a real port. The two that matter are the pair:
// one server announces `close` and does not close, the other announces `close` and does close,
// and the observer must tell them apart. A harness that read the header would report `closed`
// for both, and the corpus would then carry two assertions that cannot fail.

/// A listener over a service assembled from the facade, on a port the kernel chose.
fn listener(policy: ClosePolicy, announce: Announce) -> Listener {
    let target = crate::inprocess::InProcess::new(std::path::PathBuf::from("."));
    let service = target
        .assemble(0, 0, crate::sut::Profile::Aws)
        .expect("the service assembles");
    Listener::start(service, policy, announce).expect("a loopback listener binds")
}

/// Performs one exchange and reports what the socket was left in.
fn exchange_then_observe(listener: &Listener) -> (RawResponse, ConnectionState) {
    let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
    connection
        .write(b"GET /?x=1 HTTP/1.1\r\nhost: s3.example.com\r\n\r\n")
        .expect("the request is written");
    let response = connection.read_response(Duration::from_secs(10)).expect("a response arrives");
    (response, connection.observe())
}

fn announced_close(response: &RawResponse) -> bool {
    response
        .headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("connection") && value.eq_ignore_ascii_case("close"))
}

/// **Negative — the assertion this whole module exists to make falsifiable.**
///
/// The server announces `Connection: close` on every response and never closes anything. A
/// harness that inferred the connection state from the response header would report `closed`
/// here; one that asks the socket reports `open`. If this test ever goes red with `closed`,
/// `observe_connection` has started reading the header and every `connection_after` assertion
/// in the corpus has quietly stopped measuring anything.
#[test]
fn a_response_announcing_close_over_a_socket_that_stayed_up_is_observed_open() {
    let listener = listener(never_close(), Announce::AlwaysClose);
    let (response, state) = exchange_then_observe(&listener);
    assert!(
        announced_close(&response),
        "the control server must announce close: {:?}",
        response.headers
    );
    assert_eq!(
        state,
        ConnectionState::Open,
        "the socket stayed up, so the observation must be `open` however the response was headed"
    );
}

/// Positive — the other half of the pair. Same announcement, and this time the socket really
/// does close, so the observation moves. One test without the other proves nothing: a stuck
/// `open` would satisfy the negative above on its own.
#[test]
fn a_socket_the_server_actually_closed_is_observed_closed() {
    let listener = listener(Arc::new(|_body, _intent| ConnectionDisposition::Close), Announce::AlwaysClose);
    let (response, state) = exchange_then_observe(&listener);
    assert!(announced_close(&response));
    assert_eq!(state, ConnectionState::Closed);
}

/// **Negative — the same proof in the opposite direction.**
///
/// The server closes the socket while announcing `keep-alive`. A harness reading the header
/// reports `open` and is wrong. Both lies are needed: an observer stuck at a single answer
/// satisfies whichever one control happens to agree with it, so one control alone proves
/// nothing about the other.
#[test]
fn a_socket_closed_while_announcing_keep_alive_is_still_observed_closed() {
    let listener = listener(Arc::new(|_body, _intent| ConnectionDisposition::Close), Announce::AlwaysKeepAlive);
    let (response, state) = exchange_then_observe(&listener);
    assert!(!announced_close(&response), "{:?}", response.headers);
    assert_eq!(
        state,
        ConnectionState::Closed,
        "the socket was closed, so the observation must be `closed` however the response was headed"
    );
}

/// **Positive — the lingering close, on a real socket, with the peer still writing.**
///
/// This is the arrangement every early refusal produces and the one the byte-budgeted drain
/// could not survive: the server has answered and decided to close, and a megabyte the service
/// never asked for is on its way. RFC 9112 §9.6 is about precisely this — a full close over
/// unread octets sends `RST`, and the reset can erase the response the peer has not finished
/// reading. So there are two claims here and they are one fact each: the answer arrives intact,
/// *and* the socket ends in a close rather than a reset.
///
/// The megabyte is sixteen times the 64 KiB budget this drain used to stop at, which is what
/// makes it a measurement of the drain rather than of the kernel's buffers.
#[test]
fn a_megabyte_arriving_after_the_refusal_ends_in_a_close_and_not_a_reset() {
    let listener = listener(Arc::new(|_body, _intent| ConnectionDisposition::Close), Announce::Matching);
    let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
    connection
        .write(b"GET /?x=1 HTTP/1.1\r\nhost: s3.example.com\r\ncontent-length: 1048576\r\n\r\n")
        .expect("the head is written");
    // Tolerated rather than expected: a server that abandoned the connection makes this write
    // fail, and that is a finding for the assertions below to report rather than a panic here.
    let written = connection.write_body(&vec![b'x'; 1024 * 1024]);
    let response = connection.read_response(Duration::from_secs(10));
    assert!(
        response.is_ok(),
        "the refusal must survive the close it announces: {:?} (body write: {written:?})",
        response.err()
    );
    assert_eq!(
        connection.observe(),
        ConnectionState::Closed,
        "a close over undrained octets is a reset, and the corpus spells the two differently"
    );
}

/// **Negative — the control for the test above, and the shape it is a fix for.**
///
/// A server that answers and then closes over octets it never read is observed `reset`. Both halves
/// of the pair are needed: an observer that had lost the ability to say `reset` at all would satisfy
/// the positive above no matter what the drain did, which is the one-directional control this
/// repository has been caught by before. It is also the exact behaviour `close_orderly` had while it
/// stopped at [`MAX_LINGER_DRAIN_BYTES`], so this is the observation `c-object-0015` was making
/// before the drain became time-bounded.
///
/// The ordering is `peek` rather than a sleep or a channel, and that is what makes it a measurement
/// rather than a race: the bare server blocks until the client's post-response octets are provably
/// sitting in its receive buffer, and only then goes away without reading them. Eight kibibytes
/// rather than a megabyte, because a megabyte would block the client's write against a server that
/// is not reading and deadlock the pair — and one unread octet is all an abortive close needs.
#[test]
fn a_server_that_closes_without_lingering_is_observed_reset() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let addr = listener.local_addr().expect("the kernel assigned one");
    let served = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let mut seen = Vec::new();
        let mut block = [0_u8; 4096];
        while find_head_end(&seen).is_none() {
            match stream.read(&mut block) {
                Ok(0) | Err(_) => return,
                Ok(read) => seen.extend_from_slice(block.get(..read).unwrap_or_default()),
            }
        }
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        let _ = stream.flush();
        // Wait for octets this server will never read, without consuming them.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let mut waiting = [0_u8; 1];
        let _ = stream.peek(&mut waiting);
        // No half-close and no drain: the socket goes away with those octets still unread.
        drop(stream);
    });
    let mut connection = Connection::open(addr).expect("the listener accepts");
    connection
        .write(b"GET /?x=1 HTTP/1.1\r\nhost: s3.example.com\r\ncontent-length: 8192\r\n\r\n")
        .expect("the head is written");
    let response = connection
        .read_response(Duration::from_secs(10))
        .expect("the refusal arrives before the reset");
    assert_eq!(response.status, 400);
    connection
        .write_body(&vec![b'x'; 8192])
        .expect("octets the server chose not to read");
    served.join().expect("the bare server thread joins");
    assert_eq!(
        connection.observe(),
        ConnectionState::Reset,
        "an abortive close must still be reported as one, or `closed` stops being a claim"
    );
}

/// Negative — a reset after the response head is a truncated response, not a reset without an answer.
#[test]
fn a_reset_after_the_response_head_is_classified_as_truncated() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let addr = listener.local_addr().expect("the kernel assigned one");
    let served = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        let mut seen = Vec::new();
        let mut block = [0_u8; 4096];
        while find_head_end(&seen).is_none() {
            let read = stream.read(&mut block).expect("read request head");
            seen.extend_from_slice(&block[..read]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\npart")
            .expect("write partial response");
        stream.flush().expect("flush partial response");
        let mut waiting = [0_u8; 1];
        stream.peek(&mut waiting).expect("observe unread request body");
    });
    let mut connection = Connection::open(addr).expect("the listener accepts");
    connection
        .write(b"PUT / HTTP/1.1\r\nhost: example.test\r\ncontent-length: 8192\r\n\r\n")
        .expect("write request head");
    connection.write_body(&vec![b'x'; 8192]).expect("write request body");

    let failure = connection
        .read_response_classified("PUT", Duration::from_secs(2))
        .expect_err("partial response cannot complete");
    served.join().expect("server exits");

    assert_eq!(failure, ReadFailure::Truncated);
}

/// Negative — the server never writes two `Content-Length` headers.
///
/// A duplicate is the exact shape `WireReject::DuplicateContentLength` refuses, so a server
/// that emitted one would be generating the smuggling primitive this suite exists to detect —
/// and every response it framed would be one the corpus's own rules call malformed.
#[test]
fn a_response_carries_exactly_one_content_length() {
    let listener = listener(never_close(), Announce::Matching);
    let (response, _) = exchange_then_observe(&listener);
    let lengths = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .count();
    assert_eq!(lengths, 1, "{:?}", response.headers);
}

/// Positive — a kept connection really is reusable, which is what `open` claims. Asserted by
/// using it: a second request on the same socket is answered.
#[test]
fn a_connection_observed_open_carries_another_request() {
    let listener = listener(never_close(), Announce::Matching);
    let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
    for _ in 0..2 {
        connection
            .write(b"GET /?x=1 HTTP/1.1\r\nhost: s3.example.com\r\n\r\n")
            .expect("written");
        let response = connection.read_response(Duration::from_secs(10)).expect("answered");
        assert!(response.status > 0);
        assert_eq!(connection.observe(), ConnectionState::Open);
    }
}

// -- The framing rules --------------------------------------------------------------------

/// Negative — a request that framed no body leaves nothing unread, however little was polled.
///
/// The older `!drained` says the opposite, and this is the only place that says so: no case in
/// the corpus separates the two today, because the codec drains what it is given. So this test
/// is the whole of the guard, and it pins the shape that will separate them — a refusal that
/// answers a body-less request without touching its body, which under `!drained` is a
/// connection closed for carrying bytes nobody sent.
#[test]
fn a_body_that_framed_nothing_leaves_nothing_unread() {
    let empty = BodyDisposition {
        declared: Some(0),
        consumed: 0,
        drained: false,
    };
    assert!(!empty.leaves_unread_bytes());
    assert_eq!(
        honour_the_services_intent()(&empty, ConnectionIntent::MayKeepAlive),
        ConnectionDisposition::Keep
    );
}

/// Negative — a declared length that was only partly consumed leaves the rest, whatever the
/// drained flag says. Arithmetic, not a flag: the flag is set by the reader and the bytes are
/// owed by the peer.
#[test]
fn a_partly_consumed_declared_body_still_owes_bytes() {
    let short = BodyDisposition {
        declared: Some(24),
        consumed: 12,
        drained: false,
    };
    assert!(short.leaves_unread_bytes());
    // And chunked framing, where there is no arithmetic to do it with, falls back to the flag.
    let chunked = BodyDisposition {
        declared: None,
        consumed: 12,
        drained: false,
    };
    assert!(chunked.leaves_unread_bytes());
}

/// Negative — three answers have no body whatever their headers claim, and one does.
///
/// Both ends of this connection ask the same function. They used to disagree by construction:
/// the writer put `content-length` on a `304` that had none, and the reader then waited for a
/// body that was never coming — a hang that reads in a report as a server which never replied.
#[test]
fn a_head_a_204_and_a_304_carry_no_body() {
    assert!(!carries_a_body("HEAD", 200));
    assert!(!carries_a_body("head", 200));
    assert!(!carries_a_body("GET", 204));
    assert!(!carries_a_body("GET", 304));
    assert!(!carries_a_body("GET", 100));
    assert!(carries_a_body("GET", 200));
    assert!(carries_a_body("PUT", 400));
}

// -- The rendezvous ------------------------------------------------------------------------

/// Negative — a service that answered without ever asking releases the client with `Answered`,
/// not with `More`.
///
/// If this ever returns `More`, the client writes a frame the server never asked for and
/// `body_bytes_sent_at_response = 0` becomes unsatisfiable — which is the same defect as the
/// inversion, pointing the other way.
#[test]
fn an_answer_that_never_asked_for_the_body_stops_the_client() {
    let pacer = Pacer::new();
    pacer.server_answered();
    let mut satisfied = 0;
    assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(50)), Demand::Answered);
    assert_eq!(satisfied, 0, "nothing was released");
}

/// Negative — one demand releases one frame, not every frame.
///
/// The counter is why. A flag would be cleared by the first waiter and then set again by the
/// second poll, and a client that read it as "the server is hungry" would empty its whole chunk
/// list into the socket on a single demand — which is exactly the unpaced write this module
/// exists to avoid.
#[test]
fn one_demand_releases_one_frame() {
    let pacer = Pacer::new();
    let mut satisfied = 0;
    pacer.server_wants_body();
    assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(50)), Demand::More);
    assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(50)), Demand::Wedged);
    pacer.server_wants_body();
    assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(50)), Demand::More);
}

/// Negative — a silent peer is `Wedged` and never `More`.
///
/// The safety net has to be distinguishable from a demand, or a wedged exchange would be
/// reported as a byte count somebody measured.
#[test]
fn a_silent_peer_is_wedged_rather_than_hungry() {
    let pacer = Pacer::new();
    let mut satisfied = 0;
    assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(20)), Demand::Wedged);
    assert!(!pacer.answered());
}

/// Negative — a handover is complete when the server asks again, not only when the body ends.
///
/// A truncating case never reaches the body's end: `c-mpu-0043` announces a megabyte, writes
/// twenty-nine bytes and half-closes. Waiting for `ended` alone held that case for its whole
/// twenty-second budget and failed it on the timing assertion — for the wrong reason, since
/// what it is about is what the server does with a short body.
#[test]
fn a_handover_completes_when_the_server_asks_again() {
    let pacer = Pacer::new();
    let mut satisfied = 0;
    pacer.server_wants_body();
    assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(50)), Demand::More);
    pacer.server_wants_body();
    assert_eq!(
        pacer.await_handover(&mut satisfied, Duration::from_millis(50)),
        Demand::More,
        "a server asking for more has taken what it was given"
    );
}

/// Negative — a reset forgets an answer, so the next exchange on a reused connection does not
/// start already released.
#[test]
fn a_reset_pacer_does_not_carry_the_previous_answer() {
    let pacer = Pacer::new();
    pacer.server_answered();
    assert!(pacer.answered());
    pacer.reset();
    assert!(!pacer.answered());
    let mut satisfied = 0;
    assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(20)), Demand::Wedged);
}

// -- The pacing proof ----------------------------------------------------------------------
//
// The pair below is to pacing what the four-corner matrix above is to `connection_after`. One
// client waits for the server; one does not. They send the same bytes to the same server and
// get the same answer, and the number the corpus asserts on comes out differently. If the two
// ever agree, pacing has stopped happening and `body_bytes_sent_at_response` has gone back to
// measuring the kernel buffer.

/// Writes a `PUT` head, then its body only when the server asks for it.
fn paced_put(listener: &Listener, body: &[u8]) -> (u64, RawResponse) {
    let pacer = Arc::new(Pacer::new());
    listener.enqueue_pacer(&pacer);
    let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
    connection.write(&put_head(body.len())).expect("the head is written");
    let mut satisfied = 0;
    if pacer.await_demand(&mut satisfied, Duration::from_secs(5)) == Demand::More {
        connection.write_body(body).expect("the body is written");
    }
    let response = connection
        .read_response_classified("PUT", Duration::from_secs(10))
        .expect("a response arrives");
    (connection.body_written(), response)
}

/// Writes the same request without waiting for anything — the control.
fn unpaced_put(listener: &Listener, body: &[u8]) -> (u64, RawResponse) {
    let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
    connection.write(&put_head(body.len())).expect("the head is written");
    connection.write_body(body).expect("the body is written");
    let response = connection
        .read_response_classified("PUT", Duration::from_secs(10))
        .expect("a response arrives");
    (connection.body_written(), response)
}

fn put_head(length: usize) -> Vec<u8> {
    format!("PUT /conf/k HTTP/1.1\r\nhost: s3.example.com\r\ncontent-length: {length}\r\n\r\n").into_bytes()
}

/// **Negative — the assertion pacing exists to keep falsifiable.**
///
/// The request is anonymous, so it is refused before the service asks for a byte of the body. A
/// paced client has therefore written *nothing* when the answer arrives, which is what
/// `c-sig-0001` asserts. If this ever reports the whole body, the client has stopped waiting on
/// the server and every early-refusal assertion in the corpus is being judged against the size
/// of a socket buffer.
#[test]
fn a_refusal_that_never_read_the_body_finds_a_paced_client_had_sent_none_of_it() {
    let listener = listener(never_close(), Announce::Matching);
    let body = b"twenty-four bytes payload";
    let (written, response) = paced_put(&listener, body);
    assert!(response.status >= 400, "the request must be refused: {}", response.status);
    assert_eq!(written, 0, "the answer came before the body was asked for");
}

/// Positive — the other half of the pair, and the reason one test alone proves nothing.
///
/// Same server, same bytes, same answer; the only difference is that this client did not wait.
/// It has written the whole body by the time the identical refusal arrives, because on a
/// loopback socket the payload is in the kernel before the server reads the head. A harness
/// built this way reports "the client had sent all of it" for `c-sig-0001` and the case inverts
/// while still reading as measured.
#[test]
fn an_unpaced_client_has_written_the_whole_body_before_the_same_refusal_arrives() {
    let listener = listener(never_close(), Announce::Matching);
    let body = b"twenty-four bytes payload";
    let (paced, refusal) = paced_put(&listener, body);
    let (unpaced, same_refusal) = unpaced_put(&listener, body);
    assert_eq!(refusal.status, same_refusal.status, "the server answered both the same way");
    assert_eq!(unpaced, body.len() as u64);
    assert_ne!(paced, unpaced, "pacing is what makes the two numbers different");
}

/// Positive — pacing is not a way of always reporting zero.
///
/// A service that does read the body releases every frame, so a client that paced its way
/// through the whole payload reports the whole payload. Without this, "wait for the server"
/// could be implemented as "never write anything" and the negative above would still be green.
#[test]
fn a_service_that_reads_the_body_gets_all_of_it_from_a_paced_client() {
    let listener = listener(never_close(), Announce::Matching);
    // Two pacers, and they must stay two. `serve` raises `server_answered` on whichever pacer
    // it was handed, the moment the service returns — and this service does not read the body,
    // so it returns at once. Sharing one pacer put that answer in a race with the demand raised
    // below, and `await_demand` reports `Answered` ahead of `More` when both are set, so the
    // assertion turned on which thread the runner scheduled first. It failed about one run in
    // three on a loaded machine and never on an idle one. Nothing here needs the served pacer:
    // `Connection` does not hold one, and `write_body` only writes and counts.
    let serving = Arc::new(Pacer::new());
    listener.enqueue_pacer(&serving);
    let pacer = Arc::new(Pacer::new());
    let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
    let body = b"hello world";
    connection.write(&put_head(body.len())).expect("written");
    // Stand in for a service that pulls the body: the rendezvous is between two threads and
    // this is the other one. What is under test is that a demand really releases the frame.
    let asking = Arc::clone(&pacer);
    std::thread::spawn(move || asking.server_wants_body());
    let mut satisfied = 0;
    assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_secs(5)), Demand::More);
    connection.write_body(body).expect("written");
    assert_eq!(connection.body_written(), body.len() as u64);
    // The separation asserted rather than assumed, and in both directions: the served pacer is
    // the one that carries the answer, and the rendezvous under test never does. Waiting for
    // the answer first is what makes the pair deterministic — without the wait the second line
    // would pass merely by being early. Sharing one pacer fails here on any machine, which is
    // the point: the defect this replaced only failed on a loaded one.
    let mut served = 0;
    assert_eq!(serving.await_demand(&mut served, Duration::from_secs(5)), Demand::Answered);
    assert!(!pacer.answered());
}

/// Negative — two listeners are on two different ports without either of them naming one.
///
/// This is the whole of the port-collision argument: nothing here picks a port, so nothing can
/// pick the same one twice, however many run at once.
#[test]
fn two_listeners_never_share_a_port() {
    let first = listener(never_close(), Announce::Matching);
    let second = listener(never_close(), Announce::Matching);
    assert_ne!(first.addr().port(), second.addr().port());
    assert_ne!(first.addr().port(), 0, "the kernel assigned a real port");
}
