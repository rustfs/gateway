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

//! Bounded recording peer for uploaded setup-part tests.
//!
//! Responsible for: observing request targets, declared lengths and actual payload bytes separately.
//! NOT responsible for: fixture behavior, request signing or saving authentication headers.
//! Upstream: `parts_tests`; downstream: real loopback sockets and temporary payload files.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::super::{Conn, PEERS};

#[derive(Clone)]
pub(super) struct Step {
    pub(super) line: String,
    pub(super) body: Vec<u8>,
    pub(super) response: Vec<u8>,
}

impl Step {
    pub(super) fn new(line: impl Into<String>, body: &[u8], response: Vec<u8>) -> Self {
        Self {
            line: line.into(),
            body: body.to_vec(),
            response,
        }
    }
}

#[derive(Debug)]
pub(super) struct Request {
    pub(super) line: String,
    declared_length: usize,
    body: Vec<u8>,
}

#[derive(Default)]
pub(super) struct Record {
    pub(super) requests: Vec<Request>,
    errors: Vec<String>,
}

impl Record {
    pub(super) fn require_request(&self, line: &str) {
        assert!(
            self.requests.iter().any(|request| request.line == line),
            "the intended part request must reach the peer before its response can prove a refusal: {line}"
        );
    }

    pub(super) fn verify(&self, expected: &[Step]) {
        assert!(self.errors.is_empty(), "request observation failed: {:?}", self.errors);
        assert_eq!(self.requests.len(), expected.len(), "remote control request count changed");
        for (request, step) in self.requests.iter().zip(expected) {
            assert_eq!(request.line, step.line, "remote control target or order changed");
            assert_eq!(
                request.body, step.body,
                "observed payload bytes changed (declared {} bytes)",
                request.declared_length
            );
        }
    }
}

pub(super) struct Peer {
    url: String,
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<Record>>,
    _lease: MutexGuard<'static, ()>,
}

impl Peer {
    pub(super) fn new(steps: Vec<Step>) -> Self {
        let lease = PEERS.lock().expect("previous multipart peer released its lease");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind part recording peer");
        listener.set_nonblocking(true).expect("bound part peer accepts");
        let url = format!("http://{}", listener.local_addr().expect("part peer address"));
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut record = Record::default();
            let mut steps = steps.into_iter();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stopping = false;
            loop {
                stopping |= stopped.try_recv().is_ok();
                if Instant::now() >= deadline {
                    record.errors.push("recording peer exceeded its total deadline".to_owned());
                    return record;
                }
                // Drain already queued connections even after stop. Exhausting the script is
                // not permission to stop observing requests the fixture still sends.
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && stopping => return record,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(_) => {
                        record.errors.push("recording peer could not accept a request".to_owned());
                        return record;
                    }
                };
                stream.set_nonblocking(false).expect("blocking part request");
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .expect("bound part peer write");
                let step = steps.next();
                match read_request(&mut stream, step.as_ref()) {
                    Ok(request) => record.requests.push(request),
                    Err(error) => record.errors.push(error),
                }
                let reply = step.map_or_else(|| super::super::response(500, ""), |step| step.response);
                if stream.write_all(&reply).is_err() {
                    record.errors.push("recording peer could not write its response".to_owned());
                }
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            _lease: lease,
        }
    }

    pub(super) fn target(&self, root: &Path) -> Conn {
        Conn::external_with_fixtures(root.to_path_buf(), &self.url, None).expect("opted-in part target")
    }

    pub(super) fn finish(mut self) -> Record {
        let _ = self.stop.send(());
        self.worker
            .take()
            .expect("part peer worker exists")
            .join()
            .expect("part peer exits")
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_request(stream: &mut TcpStream, expected: Option<&Step>) -> Result<Request, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "could not bound request read")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::new();
    let (head_end, line, declared_length) = loop {
        read_more(stream, &mut bytes, deadline)?;
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4) {
            let head = std::str::from_utf8(&bytes[..end]).map_err(|_| "request head is not UTF-8")?;
            let line = head.lines().next().ok_or("request line is missing")?.to_owned();
            let lengths = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "invalid declared request length")?;
            let [length] = lengths.as_slice() else {
                return Err("request must declare exactly one Content-Length".to_owned());
            };
            // Compare on head arrival, before a wrong length could turn into a read timeout.
            if let Some(expected) = expected
                && *length != expected.body.len()
            {
                return Err(format!("declared request length {length} differs from expected {}", expected.body.len()));
            }
            if expected.is_none() && *length > 64 * 1024 {
                return Err("unexpected request body exceeded the recording bound".to_owned());
            }
            break (end, line, *length);
        }
        if bytes.len() > 16 * 1024 {
            return Err("request head exceeded the recording bound".to_owned());
        }
    };
    while bytes.len() - head_end < declared_length {
        read_more(stream, &mut bytes, deadline).map_err(|error| {
            format!(
                "request body ended after {} observed bytes, expected {}: {error}",
                bytes.len() - head_end,
                declared_length
            )
        })?;
    }
    let body = bytes.split_off(head_end);
    if body.len() != declared_length {
        return Err(format!("observed request body has {} bytes, expected {}", body.len(), declared_length));
    }
    Ok(Request {
        line,
        declared_length,
        body,
    })
}

fn read_more(stream: &mut TcpStream, bytes: &mut Vec<u8>, deadline: Instant) -> Result<(), String> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("request read deadline expired")?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| "could not bound remaining request read")?;
    let mut block = [0_u8; 4096];
    let count = stream
        .read(&mut block)
        .map_err(|_| "request read failed or reached its deadline")?;
    if count == 0 {
        return Err("request ended before the expected bytes arrived".to_owned());
    }
    bytes.extend_from_slice(&block[..count]);
    Ok(())
}

pub(super) struct TestRoot(PathBuf);

impl TestRoot {
    pub(super) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "gateway-part-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create part payload root");
        Self(path)
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observe_reply(mut reader: impl Read, phase: &str) -> String {
        let mut bytes = Vec::new();
        if let Err(error) = reader.read_to_end(&mut bytes) {
            panic!("{phase}: received {} bytes before read error: {error:?}", bytes.len());
        }
        String::from_utf8(bytes).expect("calibration response is text")
    }

    struct ResetAfterHead(bool);

    impl Read for ResetAfterHead {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.0 {
                self.0 = true;
                buffer[..4].copy_from_slice(b"head");
                Ok(4)
            } else {
                Err(std::io::ErrorKind::ConnectionReset.into())
            }
        }
    }

    #[test]
    #[should_panic(expected = "extra response")]
    fn reply_diagnostic_reports_the_response_phase() {
        observe_reply(ResetAfterHead(false), "extra response");
    }

    #[test]
    #[should_panic(expected = "4 bytes")]
    fn reply_diagnostic_reports_the_partial_byte_count() {
        observe_reply(ResetAfterHead(false), "extra response");
    }

    #[test]
    #[should_panic(expected = "ConnectionReset")]
    fn reply_diagnostic_reports_the_read_error() {
        observe_reply(ResetAfterHead(false), "extra response");
    }

    #[test]
    fn reply_diagnostic_preserves_a_complete_response() {
        assert_eq!(observe_reply(&b"response"[..], "normal response"), "response");
    }

    fn send(peer: &Peer, line: &str) -> TcpStream {
        let mut stream =
            TcpStream::connect(peer.url.strip_prefix("http://").expect("plain peer URL")).expect("connect calibration client");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("bound calibration write");
        stream
            .write_all(format!("{line}\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())
            .expect("send calibration request");
        stream
    }

    fn reply(stream: TcpStream, phase: &str) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound calibration response");
        observe_reply(stream, phase)
    }

    fn expected() -> Vec<Step> {
        vec![Step::new(
            "GET /calibration HTTP/1.1",
            &[],
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        )]
    }

    #[test]
    fn observer_accepts_exact_script_without_extra_requests() {
        let steps = expected();
        let peer = Peer::new(steps.clone());
        let response = reply(send(&peer, "GET /calibration HTTP/1.1"), "expected response");
        let observed = peer.finish();
        assert!(
            response.starts_with("HTTP/1.1 200 "),
            "the expected request received its scripted response"
        );
        observed.verify(&steps);
    }

    #[test]
    fn observer_drains_and_rejects_an_extra_request_queued_before_stop() {
        let steps = expected();
        let peer = Peer::new(steps.clone());
        let _ = reply(send(&peer, "GET /calibration HTTP/1.1"), "expected response");
        let extra = send(&peer, "GET /unexpected-extra HTTP/1.1");
        // Do not await the extra response before stop: the queued request must still be drained.
        let observed = peer.finish();
        let response = reply(extra, "extra response");
        assert!(response.starts_with("HTTP/1.1 500 "), "the extra request received a controlled refusal");
        assert_eq!(observed.requests.len(), 2, "the queued extra request was observed");
        assert_eq!(observed.requests[1].line, "GET /unexpected-extra HTTP/1.1");
        assert!(
            std::panic::catch_unwind(|| observed.verify(&steps)).is_err(),
            "the ordinary sequence assertion must reject the observed extra request"
        );
    }
}
