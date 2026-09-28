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

//! Regression coverage for authored HTTP/2 frame execution.
//!
//! Responsible for: the refusals, the exact wire image of a script, the peer-frame reader, and the
//! HPACK decoder, against the real production drivers and against loopback peers that record or
//! script every octet.
//! NOT responsible for: implementing the behavior under test.
//! Upstream: the test harness and `super`. Downstream: the repository verification gate.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use super::*;
use crate::conn::tests::{ANONYMOUS_GET_ROOT_HPACK, h2_plan, h2_request};
use crate::observation::ObservedH2ControlFrame;
use crate::sut::Sut;
use crate::toml;
use crate::value::Value;

const HEAD: &str = "method = \"GET\"\ntarget = \"/\"\nhttp_version = \"h2\"\n";

fn block(source: &str) -> Value {
    toml::parse(source).expect("valid TOML")
}

fn read(request: &Value) -> Wire {
    Conn::new(std::path::PathBuf::from("."))
        .inner
        .read_wire(request)
        .expect("the request is read")
}

fn compile_error(source: &str) -> String {
    compile(&read(&block(source)))
        .expect_err("the script must be refused")
        .to_string()
}

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fields(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

#[cfg(feature = "production-transports")]
fn production(driver: ProductionDriver, case_id: &str) -> Conn {
    let mut conn = Conn::production(std::path::PathBuf::from("."), driver);
    conn.prepare(case_id, None).expect("the empty fixture prepares");
    conn
}

/// A loopback peer: accepts one connection, reads exactly `expect` octets, then runs `answer`.
fn peer(expect: usize, answer: impl FnOnce(&mut TcpStream) + Send + 'static) -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener binds");
    let addr = listener.local_addr().expect("the listener has an address");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the client connects");
        stream.set_nonblocking(false).expect("the accepted socket blocks");
        let mut received = vec![0_u8; expect];
        stream.read_exact(&mut received).expect("the client's octets arrive");
        answer(&mut stream);
        received
    });
    (addr, handle)
}

/// The anonymous `GET /` script, compiled.
fn anonymous_script() -> Script {
    compile(&read(&h2_request(ANONYMOUS_GET_ROOT_HPACK))).expect("the script compiles")
}

/// The preface magic, the empty SETTINGS frame, and the 19-octet stream-1 HEADERS frame, spelled
/// out octet by octet rather than derived from the writer under test.
fn anonymous_wire_image() -> Vec<u8> {
    let mut image = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    image.extend(hex("000000 04 00 00000000"));
    image.extend(hex("000013 01 05 00000001"));
    image.extend(hex(ANONYMOUS_GET_ROOT_HPACK));
    image
}

// -- Against the real production drivers ---------------------------------------------------------

/// Positive, the other direction of `conn::tests::production_hyper_executes_an_authored_h2_headers_script`
/// — a different authored header block draws a different status from the same server, so the
/// observed status is the peer's and not a constant; the Huffman-coded head and the DATA body are
/// decoded too. The request is `c-cors-0043`'s: headerless OPTIONS is rejected before routing
/// with 400 BadRequest, matching the captured AWS response.
#[cfg(feature = "production-transports")]
#[test]
fn a_non_preflight_options_draws_a_different_status_from_the_same_server() {
    let mut conn = Conn::production(std::path::PathBuf::from("."), ProductionDriver::Hyper);
    conn.prepare("s-h2-0002", Some(&block("[[buckets]]\nname = \"conf-cors-rt\"\n")))
        .expect("the bucket fixture prepares");
    // `:method OPTIONS` and `:path /conf-cors-rt/key.txt` are literals without indexing on static
    // names 2 and 4; `:scheme http` and `:authority` are as in the anonymous GET.
    let header_block = concat!(
        "02074f5054494f4e53",
        "86",
        "04152f636f6e662d636f72732d72742f6b65792e747874",
        "410e73332e6578616d706c652e636f6d",
    );
    let observation = conn
        .exchange(&h2_plan("s-h2-0002", h2_request(header_block), None))
        .expect("the authored frames are executed");
    assert_eq!(observation.status, Some(400), "{observation:?}");
    assert_eq!(observation.outcome, Outcome::Response, "{observation:?}");
    assert_eq!(observation.header("content-type"), Some("application/xml"), "{observation:?}");
    assert!(observation.body_text().contains("<Code>BadRequest</Code>"), "{}", observation.body_text());
}

/// Negative — the self-held driver is HTTP/1.1 only and must not be handed a frame script.
#[cfg(feature = "production-transports")]
#[test]
fn the_self_held_driver_refuses_authored_h2_frames() {
    let mut conn = production(ProductionDriver::SelfHeld, "s-h2-0003");
    let error = conn
        .exchange(&h2_plan("s-h2-0003", h2_request(ANONYMOUS_GET_ROOT_HPACK), None))
        .expect_err("the self-held driver speaks HTTP/1.1 only");
    assert!(error.to_string().contains("self-held driver speaks HTTP/1.1 only"), "{error}");
}

/// Negative — the test socket harness frames HTTP/1.1 by hand and refuses a frame script.
#[test]
fn the_test_socket_harness_refuses_authored_h2_frames() {
    let mut conn = Conn::new(std::path::PathBuf::from("."));
    conn.prepare("s-h2-0004", None).expect("the empty fixture prepares");
    let error = conn
        .exchange(&h2_plan("s-h2-0004", h2_request(ANONYMOUS_GET_ROOT_HPACK), None))
        .expect_err("the test harness speaks HTTP/1.1 only");
    assert!(error.to_string().contains("test socket harness frames HTTP/1.1 only"), "{error}");
}

/// Negative — an external endpoint refuses a frame script before connecting.
#[test]
fn an_external_endpoint_refuses_authored_h2_frames() {
    let mut conn = Conn::external(std::path::PathBuf::from("."), "http://127.0.0.1:9").expect("the endpoint parses");
    let error = conn
        .exchange(&h2_plan("s-h2-0005", h2_request(ANONYMOUS_GET_ROOT_HPACK), None))
        .expect_err("external HTTP/2 is not implemented");
    assert!(
        error
            .to_string()
            .contains("external endpoint HTTP/2 framing is not implemented"),
        "{error}"
    );
}

/// Negative — TLS is refused before a single frame is written; this slice is cleartext only.
#[cfg(feature = "production-transports")]
#[test]
fn tls_is_refused_before_an_h2_script_is_written() {
    let mut conn = production(ProductionDriver::Hyper, "s-h2-0006");
    let tls = block("[tls]\nenabled = true\n");
    let error = conn
        .exchange(&h2_plan("s-h2-0006", h2_request(ANONYMOUS_GET_ROOT_HPACK), Some(&tls)))
        .expect_err("TLS is not negotiated here");
    assert!(error.to_string().contains("`[connection.tls]`"), "{error}");
}

/// Negative and positive — a later exchange that asks to reuse the connection is refused, and the
/// same exchange with `reuse = false` runs on a fresh connection.
#[cfg(feature = "production-transports")]
#[test]
fn a_later_exchange_cannot_reuse_an_h2_connection() {
    let mut conn = production(ProductionDriver::Hyper, "s-h2-0007");
    let mut plan = h2_plan("s-h2-0007", h2_request(ANONYMOUS_GET_ROOT_HPACK), None);
    plan.index = 1;
    let error = conn.exchange(&plan).expect_err("reuse across exchanges is not implemented");
    assert!(error.to_string().contains("reuse the connection"), "{error}");

    let fresh = block("reuse = false\n");
    let mut plan = h2_plan("s-h2-0007", h2_request(ANONYMOUS_GET_ROOT_HPACK), Some(&fresh));
    plan.index = 1;
    let observation = conn.exchange(&plan).expect("a fresh connection is opened");
    assert_eq!(observation.status, Some(403), "{observation:?}");
}

/// Negative — the actual peer rejects an invalid stream with GOAWAY and receive-side EOF.
///
/// Stream 2 is even, so a client may not open it, and the real server answers with a connection
/// error rather than a status.
#[cfg(feature = "production-transports")]
#[test]
fn a_peer_goaway_preserves_the_protocol_error_and_independent_eof() {
    let mut conn = production(ProductionDriver::Hyper, "s-h2-0008");
    let request = block(&format!(
        "{HEAD}[[h2_frames]]\ntype = \"settings\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 2\nflags = [\"end_stream\", \"end_headers\"]\n\
         payload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\n"
    ));
    let observed = conn
        .exchange(&h2_plan("s-h2-0008", request, None))
        .expect("GOAWAY and receive-side termination are measured");
    assert_eq!(observed.outcome, Outcome::ConnectionReset);
    assert_eq!(observed.status, None);
    assert_eq!(observed.socket_read_after, Some(crate::observation::SocketReadState::Eof));
    assert_eq!(
        observed.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::GoAway {
            last_stream_id: 0,
            error_code: 1
        }]),
        "the real peer reports PROTOCOL_ERROR for the unchanged invalid stream",
    );
}

/// Negative — a structured request asking for `h2` without frames is still refused by name.
#[cfg(feature = "production-transports")]
#[test]
fn a_structured_h2_request_without_frames_is_still_refused() {
    let mut conn = production(ProductionDriver::Hyper, "s-h2-0009");
    let request = block("method = \"GET\"\ntarget = \"/\"\nhttp_version = \"h2\"\n");
    let error = conn
        .exchange(&h2_plan("s-h2-0009", request, None))
        .expect_err("no HPACK encoder builds a structured request");
    assert!(error.to_string().contains("needs a real HTTP/2 framing layer"), "{error}");
}

// -- What a script may declare ------------------------------------------------------------------

#[test]
fn frames_without_an_h2_request_version_are_refused() {
    let error = compile_error("method = \"GET\"\ntarget = \"/\"\n[[h2_frames]]\ntype = \"headers\"\nstream_id = 1\n");
    assert!(error.contains("needs `request.http_version = \"h2\"`"), "{error}");
}

#[test]
fn a_flag_foreign_to_its_frame_type_is_refused() {
    for (kind, flag) in [
        ("headers", "ack"),
        ("data", "end_headers"),
        ("continuation", "end_stream"),
        ("settings", "end_stream"),
        ("headers", "bogus"),
    ] {
        let error = compile_error(&format!("{HEAD}[[h2_frames]]\ntype = \"{kind}\"\nstream_id = 1\nflags = [\"{flag}\"]\n"));
        assert!(error.contains(&format!("`{flag}`, which is not a {kind} flag")), "{error}");
    }
}

#[test]
fn a_stream_id_must_be_declared_and_fit_31_bits() {
    let missing = compile_error(&format!("{HEAD}[[h2_frames]]\ntype = \"headers\"\n"));
    assert!(missing.contains("no stream_id"), "{missing}");
    for id in ["2147483648", "4294967296"] {
        let error = compile_error(&format!("{HEAD}[[h2_frames]]\ntype = \"headers\"\nstream_id = {id}\n"));
        assert!(error.contains("is not a 31-bit stream identifier"), "{error}");
    }
}

#[test]
fn fields_of_other_frame_types_are_refused() {
    let error = compile_error(&format!(
        "{HEAD}[[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nerror_code = \"CANCEL\"\n"
    ));
    assert!(error.contains("error_code` belongs to rst_stream and goaway"), "{error}");
    let error = compile_error(&format!("{HEAD}[[h2_frames]]\ntype = \"data\"\nstream_id = 1\nincrement = 10\n"));
    assert!(error.contains("increment` belongs to window_update"), "{error}");
}

#[test]
fn request_fields_the_frames_would_replace_are_refused() {
    let frames = "[[h2_frames]]\ntype = \"headers\"\nstream_id = 1\n";
    for (extra, field) in [
        ("headers = { x-amz-date = \"x\" }\n", "headers/raw_headers/host"),
        ("host = \"elsewhere\"\n", "headers/raw_headers/host"),
        ("body = { utf8 = \"x\" }\n", "body/chunks"),
        (
            "sign = { mode = \"sigv4_header\", service = \"s3\", region = \"us-east-1\", credential = \"valid\" }\n",
            "sign",
        ),
    ] {
        let error = compile_error(&format!("{HEAD}{extra}{frames}"));
        assert!(error.contains(&format!("`request.{field}` cannot accompany")), "{extra}: {error}");
    }
}

#[test]
fn a_script_must_open_a_stream() {
    let none = compile_error(&format!("{HEAD}[[h2_frames]]\ntype = \"settings\"\n"));
    assert!(none.contains("declares no HEADERS frame"), "{none}");
}

/// Positive — every envelope is fixed as declared: order, type, flags, stream id, length, payload,
/// and delay, plus the header-table size the authored SETTINGS advertises.
#[test]
fn envelopes_keep_the_declared_order_and_fields() {
    let script = compile(&read(&block(&format!(
        "{HEAD}[[h2_frames]]\ntype = \"settings\"\npayload_hex = \"000100002000\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 5\nflags = [\"end_headers\", \"padded\"]\n\
         payload_hex = \"0182\"\ndelay_ms = 7\n\
         [[h2_frames]]\ntype = \"continuation\"\nstream_id = 5\nflags = [\"end_headers\"]\n\
         [[h2_frames]]\ntype = \"data\"\nstream_id = 5\nflags = [\"end_stream\"]\npayload_hex = \"6869\"\n"
    ))))
    .expect("the script compiles");
    let image: Vec<Vec<u8>> = script.envelopes.iter().map(Envelope::bytes).collect();
    assert_eq!(
        image,
        vec![
            hex("000006 04 00 00000000 000100002000"),
            hex("000002 01 0c 00000005 0182"),
            hex("000000 09 04 00000005"),
            hex("000002 00 01 00000005 6869"),
        ]
    );
    let delays: Vec<u64> = script.envelopes.iter().map(|envelope| envelope.delay_ms).collect();
    assert_eq!(delays, [0, 7, 0, 0]);
    assert_eq!(script.stream_id, 5);
    assert_eq!(script.header_table_size, 8_192);
}

// -- Against loopback peers ---------------------------------------------------------------------

/// Positive — the peer receives the preface magic and then exactly the authored frames, and a peer
/// that hangs up without a frame is a reset, not a response.
#[test]
fn the_peer_receives_the_preface_and_exactly_the_authored_frames() {
    let expected = anonymous_wire_image();
    let (addr, peer) = peer(expected.len(), |_| {});
    let observation = execute(addr, &anonymous_script(), Duration::from_secs(2)).expect("the hang-up is observed");
    assert_eq!(peer.join().expect("the peer exits"), expected);
    assert_eq!(observation.outcome, Outcome::ConnectionReset, "{observation:?}");
    assert_eq!(observation.status, None);
    assert_eq!(observation.http_version, None);
}

/// Negative — a peer that says nothing inside the budget is a hang, with no status invented.
#[test]
fn a_silent_peer_is_a_hang_and_not_a_response() {
    let (release, held) = mpsc::channel::<()>();
    let (addr, peer) = peer(anonymous_wire_image().len(), move |_| {
        let _ = held.recv();
    });
    let observation = execute(addr, &anonymous_script(), Duration::from_millis(300)).expect("the silence is observed");
    release.send(()).expect("the peer is waiting");
    peer.join().expect("the peer exits");
    assert_eq!(observation.outcome, Outcome::Hang, "{observation:?}");
    assert_eq!(observation.status, None);
}

/// Positive — a response split across HEADERS and CONTINUATION, a padded DATA frame, and a
/// Huffman-coded trailer block are read back as one status, head, body, and trailer set, around a
/// peer SETTINGS frame that belongs to the connection rather than the stream.
#[test]
fn a_continued_head_padded_body_and_trailers_are_read_back() {
    let (addr, peer) = peer(anonymous_wire_image().len(), |stream| {
        let mut frames = hex("000000 04 00 00000000");
        // `:status 404` is static index 13.
        frames.extend(hex("000001 01 00 00000001 8d"));
        // `content-type: text/plain`, literal without indexing on static name 31.
        frames.extend(hex("00000d 09 04 00000001 0f10 0a 746578742f706c61696e"));
        // Two octets of body behind one octet of pad length and two of padding.
        frames.extend(hex("000005 00 08 00000001 02 6869 0000"));
        // `x-sum: no-cache`, a literal name and a Huffman-coded value.
        frames.extend(hex("00000e 01 05 00000001 00 05 782d73756d 86 a8eb10649cbf"));
        stream.write_all(&frames).expect("the response is written");
    });
    let observation = execute(addr, &anonymous_script(), Duration::from_secs(2)).expect("the response is read");
    peer.join().expect("the peer exits");
    assert_eq!(observation.outcome, Outcome::Response, "{observation:?}");
    assert_eq!(observation.status, Some(404));
    assert_eq!(observation.http_version.as_deref(), Some("h2"));
    assert_eq!(observation.headers, fields(&[("content-type", "text/plain")]));
    assert_eq!(observation.body, b"hi");
    assert_eq!(observation.trailers, fields(&[("x-sum", "no-cache")]));
}

/// A peer RST_STREAM is now an observed stream reset, with its exact wire code and no response.
#[test]
fn a_peer_reset_is_observed_rather_than_reported_as_a_response() {
    let (addr, peer) = peer(anonymous_wire_image().len(), |stream| {
        stream
            .write_all(&hex("000004 03 00 00000001 00000008"))
            .expect("the reset is written");
    });
    let observation = execute(addr, &anonymous_script(), Duration::from_secs(2)).expect("peer reset is observable");
    peer.join().expect("the peer exits");
    assert_eq!(observation.outcome, Outcome::StreamReset, "{observation:?}");
    assert_eq!(observation.status, None, "a stream reset is not an HTTP response");
    assert_eq!(
        observation.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::ResetStream {
            stream_id: 1,
            error_code: 8
        }]),
        "the actual peer frame retains stream 1 and CANCEL"
    );
}

/// Both directions — an authored delay holds its frame back at least that long, and a frame without
/// one is not held.
#[test]
fn a_frame_delay_is_a_not_before_wait() {
    const DELAY_MS: u64 = 150;
    for delay_ms in [0, DELAY_MS] {
        let script = compile(&read(&block(&format!(
            "{HEAD}[[h2_frames]]\ntype = \"settings\"\n\
             [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_stream\", \"end_headers\"]\n\
             payload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\ndelay_ms = {delay_ms}\n"
        ))))
        .expect("the script compiles");
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener binds");
        let addr = listener.local_addr().expect("the listener has an address");
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("the client connects");
            stream.set_nonblocking(false).expect("the accepted socket blocks");
            let mut preface_and_settings = [0_u8; 33];
            stream.read_exact(&mut preface_and_settings).expect("the preface arrives");
            let settled = Instant::now();
            let mut headers = [0_u8; 28];
            stream.read_exact(&mut headers).expect("the HEADERS frame arrives");
            settled.elapsed()
        });
        // Every wait the writer asks for is recorded and still really slept, so the arrival gap
        // below measures the wire while this list states the pacing without any wall-clock bound.
        let mut waits = Vec::new();
        let observation = execute_paced(addr, &script, Duration::from_secs(2), &mut |delay| {
            waits.push(delay);
            std::thread::sleep(delay);
        })
        .expect("the exchange is observed");
        let gap = peer.join().expect("the peer exits");
        if delay_ms == 0 {
            assert!(waits.is_empty(), "an undelayed script asked for waits {waits:?}");
        } else {
            assert_eq!(waits, [Duration::from_millis(DELAY_MS)], "the declared delay is the one wait");
            let held = Duration::from_millis(DELAY_MS - 5);
            assert!(gap >= held, "a {delay_ms}ms frame arrived after only {gap:?}");
            assert!(observation.harness_wait_ms >= DELAY_MS - 5, "{observation:?}");
        }
    }
}

/// Negative — a delay the budget cannot hold is refused before it is slept.
#[test]
fn a_frame_delay_cannot_outlive_the_exchange_budget() {
    let script = compile(&read(&block(&format!(
        "{HEAD}[[h2_frames]]\ntype = \"settings\"\ndelay_ms = 5000\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\npayload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\n"
    ))))
    .expect("the script compiles");
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener binds");
    let started = Instant::now();
    let error = execute(
        listener.local_addr().expect("the listener has an address"),
        &script,
        Duration::from_millis(200),
    )
    .expect_err("the delay is beyond the budget");
    assert!(error.to_string().contains("beyond the remaining exchange timeout"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(1), "the delay was slept: {:?}", started.elapsed());
}

// -- HPACK ---------------------------------------------------------------------------------------

/// Positive — RFC 7541 C.4.1 and C.4.2: Huffman-coded literals and a dynamic-table reference.
#[test]
fn hpack_decodes_the_rfc7541_huffman_request_sequence() {
    let mut decoder = hpack::Decoder::new(DEFAULT_HEADER_TABLE_SIZE);
    let first = fields(&[
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/"),
        (":authority", "www.example.com"),
    ]);
    assert_eq!(decoder.decode(&hex("828684418cf1e3c2e5f23a6ba0ab90f4ff")), Ok(first.clone()));
    let mut second = first;
    second.push(("cache-control".to_owned(), "no-cache".to_owned()));
    assert_eq!(decoder.decode(&hex("828684be5886a8eb10649cbf")), Ok(second));
}

/// Negative — every representation RFC 7541 forbids is refused rather than guessed at.
#[test]
fn hpack_refuses_what_rfc7541_forbids() {
    for (header_block, why) in [
        ("80", "index 0"),
        ("be", "beyond both tables"),
        ("3fe21f", "exceeds the advertised 4096"),
        ("8220", "follows a header field"),
        ("40036162", "ends inside a string literal"),
        ("408100", "padded with something other"),
        ("4084ffffffff", "EOS"),
    ] {
        let error = hpack::Decoder::new(DEFAULT_HEADER_TABLE_SIZE)
            .decode(&hex(header_block))
            .expect_err(header_block);
        assert!(error.contains(why), "{header_block}: {error}");
    }
}

/// Positive — an authored DATA frame follows its HEADERS on the wire octet for octet, with its
/// END_STREAM flag and payload intact.
#[test]
fn an_authored_data_frame_follows_its_headers_on_the_wire() {
    let script = compile(&read(&block(&format!(
        "{HEAD}[[h2_frames]]\ntype = \"settings\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_headers\"]\n\
         payload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\n\
         [[h2_frames]]\ntype = \"data\"\nstream_id = 1\nflags = [\"end_stream\"]\npayload_hex = \"68656c6c6f\"\n"
    ))))
    .expect("the script compiles");
    let mut expected = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    expected.extend(hex("000000 04 00 00000000"));
    expected.extend(hex("000013 01 04 00000001"));
    expected.extend(hex(ANONYMOUS_GET_ROOT_HPACK));
    expected.extend(hex("000005 00 01 00000001 68656c6c6f"));
    let (addr, peer) = peer(expected.len(), |_| {});
    execute(addr, &script, Duration::from_secs(2)).expect("the hang-up is observed");
    assert_eq!(peer.join().expect("the peer exits"), expected);
}

mod h2_reset_tests;

mod h2_goaway_tests;

mod h2_window_tests;

mod h2_authored_flow_tests;

mod h2_duplex_tests;

#[cfg(feature = "production-transports")]
mod h2_corpus_tests;

mod h2_client_control_tests;

mod h2_ping_tests;

mod h2_streams_tests;
