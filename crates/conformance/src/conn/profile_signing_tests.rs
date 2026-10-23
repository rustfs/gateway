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

//! External profile signing controls measured from the bytes received by a bounded TCP peer.
//!
//! Responsible for: SHA-header selection, authored-byte preservation and signer-mode boundaries.
//! NOT responsible for: native service acceptance, external fixtures or signature verification.
//! Upstream: `Conn::exchange`; downstream: the unit-test harness and a loopback capture peer.

use super::Conn;
use crate::sut::{ExchangePlan, Profile, Sut};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
// Independent standard SHA-256 test vector for the literal payload "abc".
const ABC_SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
// These signing controls share the bounded process-wide endpoint resolver, not a concurrency target.
static CAPTURE: Mutex<()> = Mutex::new(());

struct Captured {
    head: String,
    body: Vec<u8>,
}

impl Captured {
    fn headers(&self, wanted: &str) -> Vec<&str> {
        self.head
            .split("\r\n")
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.trim())
            .collect()
    }

    fn signed_headers(&self) -> Vec<&str> {
        let authorization = self.headers("authorization");
        authorization
            .first()
            .and_then(|value| value.split("SignedHeaders=").nth(1))
            .and_then(|value| value.split(',').next())
            .map(|value| value.split(';').collect())
            .unwrap_or_default()
    }

    fn query(&self) -> Vec<(&str, &str)> {
        self.head
            .split("\r\n")
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|target| target.split_once('?'))
            .map(|(_, query)| query.split('&').filter_map(|pair| pair.split_once('=')).collect())
            .unwrap_or_default()
    }
}

fn capture(profile: Profile, source: &str, body_len: usize) -> Captured {
    let lease = CAPTURE.lock().expect("capture resource lease");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind capture peer");
    listener.set_nonblocking(true).expect("bounded accept");
    let endpoint = format!("http://{}", listener.local_addr().expect("capture address"));
    let cancelled = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&cancelled);
    let progress = Arc::new(AtomicU8::new(0));
    let observed = Arc::clone(&progress);
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                        return Err(("accept cancelled or expired", ErrorKind::TimedOut));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(("accept", error.kind())),
            }
        };
        observed.store(1, Ordering::Release);
        // Accepted sockets may inherit the listener's nonblocking mode on this platform.
        stream
            .set_nonblocking(false)
            .map_err(|error| ("blocking read mode", error.kind()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|error| ("read timeout", error.kind()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|error| ("write timeout", error.kind()))?;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= 65_536 || Instant::now() >= deadline {
                return Err(("head limit or deadline", ErrorKind::TimedOut));
            }
            let mut byte = [0];
            stream.read_exact(&mut byte).map_err(|error| ("read head", error.kind()))?;
            head.push(byte[0]);
        }
        // The fixture's known payload length is independent of malformed authored framing.
        let mut body = vec![0; body_len];
        stream.read_exact(&mut body).map_err(|error| ("read body", error.kind()))?;
        observed.store(2, Ordering::Release);
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .map_err(|error| ("write response", error.kind()))?;
        observed.store(3, Ordering::Release);
        Ok(Captured {
            head: String::from_utf8(head).map_err(|_| ("UTF-8 head", ErrorKind::InvalidData))?,
            body,
        })
    });
    let mut sut = Conn::external(".".into(), &endpoint).expect("external capture target");
    sut.prepare("c-profile-signing-0001", None).expect("empty setup");
    let request = crate::toml::parse(source).expect("authored test request");
    let result = sut.exchange(&ExchangePlan {
        case_id: "c-profile-signing-0001",
        index: 0,
        request,
        clock: None,
        connection: None,
        timeout_ms: Some(2_000),
        deadline: None,
        transport: crate::sut::Transport::Conn,
        profile,
    });
    cancelled.store(true, Ordering::Release);
    let captured = peer.join().expect("capture peer joined");
    drop(lease);
    // Only print static, allowlisted classifications, never the actual signing error or request.
    let failure = match &result {
        Err(crate::sut::SutError::Environment(reason))
            if reason.contains("DNS resolver capacity is unavailable while the bounded worker is occupied") =>
        {
            "bounded DNS resolver queue is full"
        }
        Err(crate::sut::SutError::Environment(reason)) => [
            "the request could not be tampered with: the tamper names a component the signed request does not have",
            "the request could not be tampered with: this tamper component needs a target",
            "the SigV2 request could not be presigned",
            "the SigV2 request could not be signed",
            "the request could not be signed",
            "cannot connect",
            "cannot write",
            "external endpoint sent unframed bytes",
        ]
        .into_iter()
        .find(|known| reason.starts_with(known))
        .unwrap_or("another environment refusal"),
        Err(crate::sut::SutError::TransportLimit(_)) => "transport limit",
        Err(crate::sut::SutError::NotWired { .. }) => "not wired",
        Ok(_) => "none",
    };
    let progress = progress.load(Ordering::Acquire);
    assert!(
        result.is_ok(),
        "external exchange failed: {failure}; accepted={}, read_complete={}, responded={}, peer_error={:?}",
        progress >= 1,
        progress >= 2,
        progress >= 3,
        captured.as_ref().err()
    );
    assert_eq!(result.expect("checked exchange").status, Some(204), "peer response was observed");
    captured.expect("peer observed one complete request")
}

fn empty_request(sign: &str) -> String {
    format!("method = \"GET\"\ntarget = \"/bucket/key\"\n[sign]\n{sign}\n")
}

#[test]
fn rustfs_empty_payload_sends_one_signed_sha_header() {
    let wire = capture(Profile::Rustfs, &empty_request("mode = \"sigv4_header\""), 0);
    assert_eq!(wire.headers("x-amz-content-sha256"), [EMPTY_SHA]);
    assert!(wire.signed_headers().contains(&"x-amz-content-sha256"));
}

#[test]
fn rustfs_nonempty_payload_preserves_the_real_digest_and_body() {
    let wire = capture(
        Profile::Rustfs,
        "method = \"PUT\"\ntarget = \"/bucket/key\"\n[[chunks]]\nutf8 = \"abc\"\n[sign]\nmode = \"sigv4_header\"",
        3,
    );
    assert_eq!(wire.headers("x-amz-content-sha256"), [ABC_SHA]);
    assert_eq!(wire.body, b"abc");
    assert!(wire.signed_headers().contains(&"x-amz-content-sha256"));
}

#[test]
fn omitted_sign_mode_keeps_default_sigv4_header_signing() {
    let wire = capture(Profile::Rustfs, &empty_request(""), 0);
    assert_eq!(wire.headers("x-amz-content-sha256"), [EMPTY_SHA]);
    assert!(wire.signed_headers().contains(&"x-amz-content-sha256"));
}

#[test]
fn literal_payload_hash_is_not_replaced_by_the_empty_digest() {
    // The existing payload_literal module's accepted exact-digest test vector.
    let literal = "c32cace75647e3e184b9dce888af087f63740976550541874c37a1037b196b56";
    let source = empty_request(&format!(
        "mode = \"sigv4_header\"\npayload_hash = \"literal\"\npayload_hash_literal = \"{literal}\""
    ));
    let wire = capture(Profile::Rustfs, &source, 0);
    assert_eq!(wire.headers("x-amz-content-sha256"), [literal]);
    assert!(wire.signed_headers().contains(&"x-amz-content-sha256"));
}

#[test]
fn raw_nonempty_payload_keeps_its_digest_body_and_authored_framing() {
    let raw = "PUT /bucket/key HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\nX-Authored:  keep  spaces\r\n";
    let source = format!(
        "raw_head_utf8 = {raw:?}\n[[chunks]]\nutf8 = \"abc\"\n[sign]\nmode = \"sigv4_header\"\n",
        raw = format!("{raw}\r\n")
    );
    let wire = capture(Profile::Rustfs, &source, 3);
    assert!(wire.head.starts_with(raw), "authored payload prefix must remain byte-exact");
    assert_eq!(wire.headers("content-length"), ["3"]);
    assert_eq!(wire.headers("x-amz-content-sha256"), [ABC_SHA]);
    assert_eq!(wire.body, b"abc");
    assert!(wire.signed_headers().contains(&"x-amz-content-sha256"));
}

#[test]
fn other_profiles_do_not_inherit_the_rustfs_empty_header() {
    for profile in [Profile::Aws, Profile::Minio] {
        let wire = capture(profile, &empty_request("mode = \"sigv4_header\""), 0);
        assert!(wire.headers("x-amz-content-sha256").is_empty());
        assert!(!wire.signed_headers().contains(&"x-amz-content-sha256"));
    }
}

#[test]
fn unsigned_requests_do_not_acquire_signing_headers() {
    for mode in ["anonymous", "none"] {
        let wire = capture(Profile::Rustfs, &empty_request(&format!("mode = \"{mode}\"")), 0);
        assert!(wire.headers("x-amz-content-sha256").is_empty());
        assert!(wire.headers("authorization").is_empty());
    }
}

#[test]
fn requests_without_a_sign_spec_remain_unsigned() {
    let wire = capture(Profile::Rustfs, "method = \"GET\"\ntarget = \"/bucket/key\"", 0);
    assert!(wire.headers("x-amz-content-sha256").is_empty());
    assert!(wire.headers("authorization").is_empty());
}

#[test]
fn sigv2_headers_are_not_rewritten_as_sigv4() {
    let wire = capture(Profile::Rustfs, &empty_request("mode = \"sigv2_header\""), 0);
    assert!(wire.headers("x-amz-content-sha256").is_empty());
    assert!(
        wire.headers("authorization")
            .first()
            .is_some_and(|value| value.starts_with("AWS "))
    );
}

#[test]
fn presigned_v2_retains_exact_query_names_without_a_sha_header() {
    let wire = capture(Profile::Rustfs, &empty_request("mode = \"presigned_v2\""), 0);
    assert!(wire.headers("x-amz-content-sha256").is_empty());
    assert!(wire.headers("authorization").is_empty());
    let query = wire.query();
    assert!(query.iter().any(|(name, _)| *name == "Signature"));
    assert!(query.iter().any(|(name, _)| *name == "AWSAccessKeyId"));
}

#[test]
fn presigned_v4_retains_its_algorithm_without_a_sha_header() {
    let wire = capture(Profile::Rustfs, &empty_request("mode = \"presigned_v4\""), 0);
    assert!(wire.headers("x-amz-content-sha256").is_empty());
    assert!(wire.headers("authorization").is_empty());
    let query = wire.query();
    assert!(query.iter().any(|(name, _)| *name == "X-Amz-Signature"));
    assert!(
        query
            .iter()
            .any(|(name, value)| *name == "X-Amz-Algorithm" && *value == "AWS4-HMAC-SHA256")
    );
}

#[test]
fn unsigned_payload_is_not_replaced_by_the_empty_digest() {
    let wire = capture(Profile::Rustfs, &empty_request("mode = \"sigv4_unsigned_payload\""), 0);
    assert_eq!(wire.headers("x-amz-content-sha256"), ["UNSIGNED-PAYLOAD"]);
}

#[test]
fn explicitly_empty_hash_is_not_replaced_by_the_nonempty_body_digest() {
    let wire = capture(
        Profile::Rustfs,
        "method = \"PUT\"\ntarget = \"/bucket/key\"\n[[chunks]]\nutf8 = \"abc\"\n[sign]\nmode = \"sigv4_header\"\npayload_hash = \"empty\"",
        3,
    );
    assert_eq!(wire.headers("x-amz-content-sha256"), [EMPTY_SHA]);
    assert_eq!(wire.body, b"abc");
    assert!(wire.signed_headers().contains(&"x-amz-content-sha256"));
}

#[test]
fn an_authored_bad_hash_is_not_repaired_or_duplicated() {
    let wire = capture(
        Profile::Rustfs,
        "method = \"GET\"\ntarget = \"/bucket/key\"\nheaders = { X-Amz-Content-Sha256 = \"authored-bad-hash\" }\n[sign]\nmode = \"sigv4_header\"",
        0,
    );
    assert_eq!(wire.headers("x-amz-content-sha256"), ["authored-bad-hash"]);
}

#[test]
fn raw_framing_is_not_rewritten_when_signing_adds_the_hash() {
    let raw = "GET /bucket/key HTTP/1.1\r\nHost: example.test\r\nX-Authored:  keep  spaces\r\n";
    let source = format!("raw_head_utf8 = {raw:?}\n[sign]\nmode = \"sigv4_header\"\n", raw = format!("{raw}\r\n"));
    let wire = capture(Profile::Rustfs, &source, 0);
    assert!(wire.head.starts_with(raw), "authored prefix must remain byte-exact");
    assert!(wire.headers("content-length").is_empty());
    assert_eq!(wire.headers("x-amz-content-sha256"), [EMPTY_SHA]);
}

#[test]
fn raw_duplicate_hashes_are_not_repaired_or_collapsed() {
    let raw = "GET /bucket/key HTTP/1.1\r\nHost: example.test\r\nX-Amz-Content-Sha256: first-bad\r\nx-amz-content-sha256: second-bad\r\n";
    let source = format!("raw_head_utf8 = {raw:?}\n[sign]\nmode = \"sigv4_header\"\n", raw = format!("{raw}\r\n"));
    let wire = capture(Profile::Rustfs, &source, 0);
    assert!(wire.head.starts_with(raw), "authored duplicate prefix must remain byte-exact");
    assert_eq!(wire.headers("x-amz-content-sha256"), ["first-bad", "second-bad"]);
}

#[test]
fn payload_hash_tampering_is_not_repaired_after_signing() {
    let source =
        empty_request("mode = \"sigv4_header\"\n[sign.tamper]\ncomponent = \"payload_hash\"\nnew_value = \"tampered-payload\"");
    let wire = capture(Profile::Rustfs, &source, 0);
    assert_eq!(wire.headers("x-amz-content-sha256"), ["tampered-payload"]);
}

#[test]
fn query_tampering_reaches_the_peer() {
    let source = "method = \"GET\"\ntarget = \"/bucket/key?changed=no\"\n[sign]\nmode = \"sigv4_header\"\n[sign.tamper]\ncomponent = \"canonical_query\"\ntarget = \"changed\"\nnew_value = \"yes\"";
    let wire = capture(Profile::Rustfs, source, 0);
    assert!(wire.head.starts_with("GET /bucket/key?changed=yes HTTP/1.1\r\n"));
}

#[test]
fn explicit_undersigning_is_not_repaired() {
    let source = empty_request("mode = \"sigv4_header\"\nsigned_headers = [\"host\", \"x-amz-date\"]");
    let wire = capture(Profile::Rustfs, &source, 0);
    assert_eq!(wire.headers("x-amz-content-sha256"), [EMPTY_SHA]);
    assert_eq!(wire.signed_headers(), ["host", "x-amz-date"]);
}
