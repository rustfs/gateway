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

//! The shadow proxy: the copy of a connection read back as requests, the bytes forwarded
//! unchanged both ways, a stalled diff never slowing the traffic, and the verdict per request.
//!
//! Responsible for: `tee.rs` (framing, pipelining, pieces, caps, loss) and `shadow.rs` (the proxy
//! against a scripted upstream on loopback, and `judge`).
//! NOT responsible for: the diff itself.
//! Upstream: `tee.rs`, `shadow.rs`. Downstream: none.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::shadow::{Counters, Judge, Proxy, judge, judge_all, request_of};
use crate::tee::{Captured, Event, Tee};

fn requests(events: Vec<Event>) -> Vec<Captured> {
    events
        .into_iter()
        .map(|event| match event {
            Event::Request(captured) => captured,
            other => panic!("not a request: {other:?}"),
        })
        .collect()
}

/// Positive — a request arriving one byte at a time is one request, its body exact.
#[test]
fn a_request_in_single_bytes_is_one_request() {
    let bytes = b"PUT /bkt/k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello";
    let mut tee = Tee::new(1 << 20);
    let mut events = Vec::new();
    for byte in bytes {
        events.extend(tee.feed(&[*byte]));
    }
    let captured = requests(events);
    assert_eq!(captured.len(), 1);
    assert_eq!((captured[0].method.as_str(), captured[0].target.as_str()), ("PUT", "/bkt/k"));
    assert_eq!(captured[0].body, b"hello");
    assert!(!captured[0].chunked);
}

/// Negative — pipelined requests are read in order, and a chunked body is de-framed, extensions
/// and trailers included; a body that has not fully arrived yields nothing yet.
#[test]
fn pipelined_and_chunked_requests_are_read_in_order() {
    let mut tee = Tee::new(1 << 20);
    let first = b"GET /bkt/a HTTP/1.1\r\nHost: h\r\n\r\nPUT /bkt/b HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r";
    let captured = requests(tee.feed(first));
    assert_eq!(captured.len(), 1, "the chunked body is not complete");
    let rest = b"\n0\r\nx-trailer: t\r\n\r\nDELETE /bkt/c HTTP/1.1\r\nHost: h\r\n\r\n";
    let captured = requests(tee.feed(rest));
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].body, b"abcde");
    assert!(captured[0].chunked);
    assert_eq!(captured[1].target, "/bkt/c");
}

/// Negative — a body over the cap is reported and skipped, and the next request is still found.
#[test]
fn a_body_over_the_cap_is_skipped_and_the_next_request_found() {
    let mut tee = Tee::new(4);
    let events = tee.feed(b"PUT /bkt/big HTTP/1.1\r\nContent-Length: 10\r\n\r\n0123");
    assert_eq!(
        events,
        vec![Event::Oversize {
            method: "PUT".to_owned(),
            target: "/bkt/big".to_owned()
        }]
    );
    let captured = requests(tee.feed(b"456789GET /bkt/next HTTP/1.1\r\n\r\n"));
    assert_eq!(captured[0].target, "/bkt/next");
}

/// Negative — bytes that stop being HTTP/1.1 end the copy once, with the reason, and later bytes
/// are ignored rather than misread.
#[test]
fn the_copy_gives_up_once_on_what_is_not_http() {
    for (bytes, why) in [
        (&b"\x16\x03\x01\x02\x00 not http\r\n\r\n"[..], "not an HTTP/1.1 request"),
        (b"PUT /k HTTP/1.1\r\nContent-Length: x\r\n\r\n", "not a length"),
        (b"PUT /k HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", "more than one"),
        (b"PUT /k HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", "not hex"),
        (
            b"PUT /k HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXY0\r\n\r\n",
            "not followed by CRLF",
        ),
    ] {
        let mut tee = Tee::new(1 << 20);
        let events = tee.feed(bytes);
        assert!(matches!(events.as_slice(), [Event::Lost(reason)] if reason.contains(why)), "{events:?}");
        assert!(tee.feed(b"GET / HTTP/1.1\r\n\r\n").is_empty());
    }
    let mut tee = Tee::new(1 << 20);
    let events = tee.feed(b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\nGET /x HTTP/1.1\r\n\r\n");
    assert_eq!(requests(events).len(), 1, "the upgrade request is read, nothing after it");
}

/// An upstream that records every byte it receives and answers each connection with `answer`
/// once the client stops sending.
fn upstream(answer: &'static [u8]) -> (SocketAddr, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let address = listener.local_addr().expect("its address");
    let (sender, receiver) = sync_channel(8);
    thread::spawn(move || {
        for connection in listener.incoming() {
            let Ok(mut connection) = connection else { return };
            let mut received = Vec::new();
            let _ = connection.read_to_end(&mut received);
            let _ = connection.write_all(answer);
            let _ = connection.shutdown(Shutdown::Write);
            let _ = sender.send(received);
        }
    });
    (address, receiver)
}

fn proxy(upstream: SocketAddr, queue: usize, judge: Judge) -> (SocketAddr, Arc<Counters>, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let address = listener.local_addr().expect("its address");
    let (sender, receiver) = sync_channel(queue);
    let counters = Arc::new(Counters::default());
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    thread::spawn(move || {
        let mut lines = Vec::new();
        judge_all(&receiver, &judge, &mut SharedLog(sink, &mut lines));
    });
    let proxy = Arc::new(Proxy::new(upstream, 1 << 20, sender, Arc::clone(&counters)));
    thread::spawn(move || proxy.serve(&listener));
    (address, counters, log)
}

/// A log the test reads while the judging thread writes it.
struct SharedLog<'a>(Arc<Mutex<Vec<u8>>>, &'a mut Vec<u8>);

impl Write for SharedLog<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.1.extend_from_slice(bytes);
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn exchange(proxy: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut client = TcpStream::connect(proxy).expect("the proxy accepts");
    client.write_all(request).expect("the proxy reads");
    client.shutdown(Shutdown::Write).expect("half-close");
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).expect("the proxy answers");
    answer
}

fn log_lines(log: &Arc<Mutex<Vec<u8>>>, at_least: usize) -> Vec<String> {
    for _ in 0..500 {
        let text = String::from_utf8_lossy(&log.lock().expect("the log")).into_owned();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() >= at_least {
            return lines;
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("the log never reached {at_least} lines");
}

/// Negative — the upstream receives exactly the client's bytes and the client exactly the
/// upstream's, whatever the copy made of them; each request gets a log line.
#[test]
fn bytes_pass_unchanged_both_ways_and_each_request_is_judged() {
    const ANSWER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let (upstream, received) = upstream(ANSWER);
    let seen: Judge = Arc::new(|captured: &Captured| format!("seen {}", captured.body.len()));
    let (address, counters, log) = proxy(upstream, 16, seen);
    let request: &[u8] = b"GET /bkt/a HTTP/1.1\r\nHost: h\r\n\r\nPUT /bkt/b HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n\x00trailing garbage";
    assert_eq!(exchange(address, request), ANSWER);
    assert_eq!(received.recv().expect("the upstream got the request"), request);
    let lines = log_lines(&log, 3);
    assert!(lines[0].ends_with("GET /bkt/a seen 0"), "{lines:?}");
    assert!(lines[1].ends_with("PUT /bkt/b seen 3"), "{lines:?}");
    assert!(lines[2].contains("stopped copying"), "{lines:?}");
    assert_eq!(counters.shed.load(Ordering::Relaxed), 0);
}

/// Negative — a judge that never returns cannot hold the traffic: the copies it has no room for
/// are shed and counted, and every exchange still completes.
#[test]
fn a_stalled_diff_never_slows_the_traffic() {
    const ANSWER: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";
    let (upstream, received) = upstream(ANSWER);
    let (release, stalled) = sync_channel::<()>(0);
    let stalled = Mutex::new(stalled);
    let stuck: Judge = Arc::new(move |_: &Captured| {
        let _ = stalled.lock().map(|receiver| receiver.recv());
        "released".to_owned()
    });
    let (address, counters, _log) = proxy(upstream, 1, stuck);
    for _ in 0..5 {
        assert_eq!(exchange(address, b"GET /bkt/k HTTP/1.1\r\n\r\n"), ANSWER);
        assert_eq!(received.recv().expect("forwarded"), b"GET /bkt/k HTTP/1.1\r\n\r\n");
    }
    assert!(counters.shed.load(Ordering::Relaxed) >= 3, "{counters:?}");
    drop(release);
}

/// Negative — what the diff cannot replay is removed or skipped: the signature, the presigned
/// query, chunked framing; a signed chunk framing is a skip.
#[test]
fn a_copied_request_loses_its_signature_and_framing() {
    let captured = Captured {
        method: "PUT".to_owned(),
        target: "/bkt/k?X-Amz-Signature=s&X-Amz-Credential=c&tagging".to_owned(),
        headers: vec![
            ("Authorization".to_owned(), b"AWS4-HMAC-SHA256 ...".to_vec()),
            ("Transfer-Encoding".to_owned(), b"chunked".to_vec()),
            ("Host".to_owned(), b"h".to_vec()),
        ],
        body: b"abc".to_vec(),
        chunked: true,
    };
    let request = request_of(&captured).expect("sendable");
    assert_eq!(request.target, "/bkt/k?tagging");
    let value = |wanted: &str| {
        request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
    };
    assert_eq!(value("content-length").as_deref(), Some("3"));
    assert_eq!(value("transfer-encoding"), None);
    assert!(
        value("authorization").is_some_and(|signature| signature.contains("Credential=AKIDDIFFTEST/")),
        "signed again"
    );
    assert!(
        request.headers.iter().all(|(_, value)| value != b"AWS4-HMAC-SHA256 ..."),
        "the client's signature is gone"
    );
    let signed = Captured {
        headers: vec![("x-amz-content-sha256".to_owned(), b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD".to_vec())],
        ..captured
    };
    assert!(judge(&signed).starts_with("skip: signed chunk framing"));
}

/// Negative — the verdict names agreement, registered differences, and unregistered ones.
#[test]
fn the_verdict_names_agreement_and_differences() {
    let copy = |target: &str| Captured {
        method: "GET".to_owned(),
        target: target.to_owned(),
        headers: vec![("host".to_owned(), b"h".to_vec())],
        body: Vec::new(),
        chunked: false,
    };
    assert_eq!(judge(&copy("/bkt/k")), "agree");
    assert!(judge(&copy("/bkt/k?x-id=GetObjectTagging")).starts_with("known kd-decode-0058,kd-decode-0059"));
    assert!(judge(&copy("/bkt/k?x-id=ListParts")).starts_with("DIFF "));
}
