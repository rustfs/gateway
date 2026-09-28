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
//! Responsible for: authored HTTP/2 frames over TLS to an external `https://` endpoint — the `h2`
//! ALPN negotiation, the exact octets inside the session, and refusals when the peer selects
//! anything else.
//! NOT responsible for: certificate policy (`conn::external_tls`) or the production listener's own
//! ALPN configuration.
//! Upstream: `Conn::external_with_ca`; downstream: a loopback rustls peer that records every octet.
//! Evidence: https://www.rfc-editor.org/rfc/rfc9113.html#section-3.2 — over TLS, HTTP/2 is in use
//! only when both sides agree on the `h2` token through ALPN.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::*;

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct TempPem(std::path::PathBuf);

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A TLS peer offering `alpn`: it records the application octets it receives until it has
/// `expect` of them (or the client stops), then writes `answer` and holds the session open.
type PeerStream = StreamOwned<ServerConnection, TcpStream>;

fn tls_peer(alpn: &[&[u8]], expect: usize, answer: Vec<u8>) -> (String, TempPem, thread::JoinHandle<Vec<u8>>) {
    tls_peer_with(alpn, expect, move |stream| {
        stream.write_all(&answer).expect("the answer is written");
        stream.flush().expect("the answer is flushed");
        thread::sleep(Duration::from_millis(300));
    })
}

/// [`tls_peer`], with what the peer does after reading `expect` octets handed in.
fn tls_peer_with(
    alpn: &[&[u8]],
    expect: usize,
    then: impl FnOnce(&mut PeerStream) + Send + 'static,
) -> (String, TempPem, thread::JoinHandle<Vec<u8>>) {
    tls_peer_paced(alpn, expect, Duration::ZERO, then)
}

/// [`tls_peer_with`], waiting `before_reading` after the handshake and then reading slowly, so the
/// client's writes back up and stay backed up.
fn tls_peer_paced(
    alpn: &[&[u8]],
    expect: usize,
    before_reading: Duration,
    then: impl FnOnce(&mut PeerStream) + Send + 'static,
) -> (String, TempPem, thread::JoinHandle<Vec<u8>>) {
    let certified = rcgen::generate_simple_self_signed(["127.0.0.1".to_owned()]).expect("generate certificate");
    let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rustfs-gateway-conformance-h2-ca-{}-{sequence}.pem", std::process::id()));
    std::fs::write(&path, certified.cert.pem()).expect("write temporary CA");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .expect("configure test TLS server");
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS listener");
    let address = listener.local_addr().expect("TLS listener address");
    let handle = thread::spawn(move || {
        let Ok((socket, _)) = listener.accept() else { return Vec::new() };
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bounded peer reads");
        let mut stream = StreamOwned::new(ServerConnection::new(config).expect("TLS session"), socket);
        let mut received = Vec::new();
        let mut block = [0_u8; 4096];
        if !before_reading.is_zero() {
            while stream.conn.is_handshaking() {
                if stream.conn.complete_io(&mut stream.sock).is_err() {
                    return received;
                }
            }
            thread::sleep(before_reading);
        }
        while received.len() < expect {
            match stream.read(&mut block) {
                Ok(0) | Err(_) => return received,
                Ok(read) => received.extend_from_slice(&block[..read]),
            }
            // A paced peer keeps reading slowly, so the client's socket stays full to the end.
            if !before_reading.is_zero() {
                thread::sleep(Duration::from_micros(500));
            }
        }
        then(&mut stream);
        received
    });
    (format!("https://{address}"), TempPem(path), handle)
}

fn exchange(endpoint: &str, ca: &TempPem) -> Result<Observation, SutError> {
    let mut conn = Conn::external_with_ca(std::path::PathBuf::from("."), endpoint, Some(&ca.0)).expect("the endpoint parses");
    conn.prepare("s-h2-tls", None).expect("no setup");
    conn.exchange(&h2_plan("s-h2-tls", h2_request(ANONYMOUS_GET_ROOT_HPACK), None))
}

/// Positive — with `h2` selected, the peer receives the preface and exactly the authored frames
/// inside the session, and its answer is observed.
#[test]
fn an_h2_script_runs_inside_a_tls_session_that_selected_h2() {
    let expected = anonymous_wire_image();
    let (endpoint, ca, peer) = tls_peer(&[b"h2"], expected.len(), hex("000000 04 00 00000000 000001 01 05 00000001 88"));
    let observed = exchange(&endpoint, &ca).expect("the script runs over TLS");
    assert_eq!(peer.join().expect("the peer exits"), expected);
    assert_eq!(observed.outcome, Outcome::Response, "{observed:?}");
    assert_eq!(observed.status, Some(200));
    assert_eq!(observed.http_version.as_deref(), Some("h2"));
}

/// Negative — inside TLS the socket carries records, not frames, so request progress and the
/// receive-side socket state are reported unavailable rather than inferred.
#[test]
fn tls_request_progress_and_socket_state_are_unavailable() {
    let expected = anonymous_wire_image();
    let (endpoint, ca, peer) = tls_peer(&[b"h2"], expected.len(), hex("000001 01 05 00000001 88"));
    let observed = exchange(&endpoint, &ca).expect("the script runs over TLS");
    peer.join().expect("the peer exits");
    assert_eq!(observed.request_body_bytes_sent_at_response, None, "{observed:?}");
    assert_eq!(observed.socket_read_after, None, "{observed:?}");
    assert_eq!(observed.connection_after, None, "{observed:?}");
}

/// Negative — the client offers only `h2`, so a peer that speaks only `http/1.1` ends the
/// handshake with `no_application_protocol`, before a single frame octet is written.
#[test]
fn a_peer_speaking_only_http1_fails_the_handshake_before_any_frame_is_written() {
    let (endpoint, ca, peer) = tls_peer(&[b"http/1.1"], 1, Vec::new());
    let error = exchange(&endpoint, &ca).expect_err("h2 was not negotiated");
    assert!(error.to_string().contains("NoApplicationProtocol"), "{error}");
    assert!(peer.join().expect("the peer exits").is_empty(), "no application octet was written");
}

/// Negative — a peer that selects no protocol is refused too: prior knowledge is not assumed over TLS.
#[test]
fn a_peer_selecting_no_protocol_is_refused_before_any_frame_is_written() {
    let (endpoint, ca, peer) = tls_peer(&[], 1, Vec::new());
    let error = exchange(&endpoint, &ca).expect_err("h2 was not negotiated");
    assert!(error.to_string().contains("selected no ALPN protocol, not `h2`"), "{error}");
    assert!(peer.join().expect("the peer exits").is_empty(), "no application octet was written");
}

/// Negative — an untrusted certificate is an environment failure, as for HTTP/1.1 over TLS.
#[test]
fn an_untrusted_certificate_is_refused_for_an_h2_script() {
    let (endpoint, _ca, peer) = tls_peer(&[b"h2"], 1, Vec::new());
    let mut conn = Conn::external(std::path::PathBuf::from("."), &endpoint).expect("the endpoint parses");
    conn.prepare("s-h2-tls", None).expect("no setup");
    let error = conn
        .exchange(&h2_plan("s-h2-tls", h2_request(ANONYMOUS_GET_ROOT_HPACK), None))
        .expect_err("the certificate is not trusted");
    assert!(error.to_string().contains("invalid peer certificate"), "{error}");
    peer.join().expect("the peer exits");
}

/// Negative and positive — a peer that drops TCP without `close_notify` before any frame is an end
/// of stream carrying a truncation note; one that sends `close_notify` first carries none. Neither
/// is reported as a measured socket state.
#[test]
fn a_tls_end_of_stream_is_noted_only_without_close_notify() {
    for (clean, label) in [(false, "dropped"), (true, "close_notify")] {
        let expected = anonymous_wire_image();
        let (endpoint, ca, peer) = tls_peer_with(&[b"h2"], expected.len(), move |stream| {
            if clean {
                stream.conn.send_close_notify();
                stream.flush().expect("the alert is flushed");
            }
            let _ = stream.sock.shutdown(std::net::Shutdown::Both);
        });
        let observed = exchange(&endpoint, &ca).expect("the end of stream is observed");
        peer.join().expect("the peer exits");
        assert_eq!(observed.outcome, Outcome::ConnectionReset, "{label}: {observed:?}");
        assert_eq!(observed.socket_read_after, None, "{label}: {observed:?}");
        let noted = observed.notes.iter().any(|note| note.contains("without a close_notify"));
        assert_eq!(noted, !clean, "{label}: {:?}", observed.notes);
    }
}

/// Positive — a frame far larger than one TLS record, written to a peer that reads slowly, reaches
/// the peer intact: plaintext the session accepted is flushed as the socket drains.
#[test]
fn a_large_frame_through_a_slow_reader_arrives_intact() {
    let payload = "61".repeat(4 << 20);
    let script = format!(
        "{HEAD}[[h2_frames]]\ntype = \"settings\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_headers\"]\npayload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\n\
         [[h2_frames]]\ntype = \"data\"\nstream_id = 1\nflags = [\"end_stream\"]\npayload_hex = \"{payload}\"\n"
    );
    let mut expected = anonymous_wire_image();
    expected[24 + 9 + 4] = END_HEADERS;
    expected.extend(hex("400000 00 01 00000001"));
    expected.extend(vec![b'a'; 4 << 20]);
    let (endpoint, ca, peer) = tls_peer_paced(&[b"h2"], expected.len(), Duration::from_millis(300), |stream| {
        stream
            .write_all(&hex("000001 01 05 00000001 88"))
            .expect("the answer is written");
        stream.flush().expect("the answer is flushed");
        thread::sleep(Duration::from_millis(300));
    });
    let mut conn = Conn::external_with_ca(std::path::PathBuf::from("."), &endpoint, Some(&ca.0)).expect("the endpoint parses");
    conn.prepare("s-h2-tls", None).expect("no setup");
    let observed = conn
        .exchange(&h2_plan("s-h2-tls", block(&script), None))
        .expect("the script runs over TLS");
    let received = peer.join().expect("the peer exits");
    assert_eq!(received.len(), expected.len());
    assert!(received == expected, "the octets inside the session differ");
    assert_eq!(observed.status, Some(200), "{observed:?}");
    assert!(observed.notes.is_empty(), "{:?}", observed.notes);
}

/// Negative — when the answer arrives while TLS records carrying authored frames are still queued
/// behind a peer that stopped reading, the script is reported unfinished rather than written.
#[test]
fn records_still_queued_when_the_answer_arrives_are_reported_unwritten() {
    let payload = "61".repeat(8 << 20);
    let script = format!(
        "{HEAD}[[h2_frames]]\ntype = \"settings\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_headers\"]\npayload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\n\
         [[h2_frames]]\ntype = \"data\"\nstream_id = 1\nflags = [\"end_stream\"]\npayload_hex = \"{payload}\"\n"
    );
    // The peer reads only the preface, SETTINGS and HEADERS, answers, and stops reading.
    let (endpoint, ca, peer) = tls_peer_with(&[b"h2"], anonymous_wire_image().len(), |stream| {
        stream
            .write_all(&hex("000001 01 05 00000001 88"))
            .expect("the answer is written");
        stream.flush().expect("the answer is flushed");
        thread::sleep(Duration::from_millis(500));
    });
    let mut conn = Conn::external_with_ca(std::path::PathBuf::from("."), &endpoint, Some(&ca.0)).expect("the endpoint parses");
    conn.prepare("s-h2-tls", None).expect("no setup");
    let observed = conn
        .exchange(&h2_plan("s-h2-tls", block(&script), None))
        .expect("the answer is observed");
    peer.join().expect("the peer exits");
    assert_eq!(observed.status, Some(200), "{observed:?}");
    assert!(
        observed
            .notes
            .iter()
            .any(|note| note.contains("before all authored HTTP/2 frame bytes were written")),
        "{:?}",
        observed.notes
    );
}
