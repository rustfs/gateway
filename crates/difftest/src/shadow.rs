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

//! The shadow proxy: live traffic forwarded byte for byte to an upstream S3 server, and a copy of
//! each request decoded by both stacks on the side.
//!
//! Responsible for: accepting connections, opening one upstream connection per client
//! connection, and pumping bytes both ways unchanged — the client-to-upstream pump writes each
//! read to the upstream before anything else sees it; handing a copy of the client bytes to a
//! [`Tee`], and each request it completes to the judging thread through a bounded queue that is
//! never waited on (a full queue sheds the copy, counted, so a slow diff can never slow the
//! traffic); and judging a request ([`judge`]): the decode diff of the request as the client sent
//! it, minus what the diff cannot replay — the signature (`Authorization`, the presigned query) is
//! removed, a `chunked` body is sent de-framed with its length, and a signed chunk framing is
//! skipped — judged by the register, one log line per request.
//! NOT responsible for: the answers (the upstream's go to the client untouched, and an encode diff
//! needs an s3s output a live upstream never shows), TLS (point it at a plaintext listener), or
//! deciding anything about the upstream: it never answers a client itself.
//! Upstream: a listener, an upstream address. Downstream: the `shadow-proxy` binary, the log.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::thread;

use crate::corpus::PRESIGN_PARAMETERS;
use crate::known::KnownDiffs;
use crate::request::RawRequest;
use crate::tee::{Captured, Event, Tee};

/// How a copied request is judged: the log line for it.
pub type Judge = Arc<dyn Fn(&Captured) -> String + Send + Sync>;

/// What the proxy counted.
#[derive(Debug, Default)]
pub struct Counters {
    /// Connections accepted.
    pub connections: AtomicU64,
    /// Requests copied to the judging thread.
    pub copied: AtomicU64,
    /// Requests not copied because the judging queue was full.
    pub shed: AtomicU64,
}

/// A running proxy's shared parts.
pub struct Proxy {
    upstream: SocketAddr,
    body_cap: usize,
    queue: SyncSender<(String, Event)>,
    counters: Arc<Counters>,
}

impl Proxy {
    /// A proxy to `upstream` that copies requests to `queue`, comparing bodies up to `body_cap`.
    #[must_use]
    pub fn new(upstream: SocketAddr, body_cap: usize, queue: SyncSender<(String, Event)>, counters: Arc<Counters>) -> Self {
        Self {
            upstream,
            body_cap,
            queue,
            counters,
        }
    }

    /// Serves `listener` until it fails; one thread pair per connection.
    ///
    /// # Errors
    ///
    /// The listener stopped accepting.
    pub fn serve(self: Arc<Self>, listener: &TcpListener) -> io::Result<()> {
        for client in listener.incoming() {
            let client = client?;
            let number = self.counters.connections.fetch_add(1, Ordering::Relaxed) + 1;
            let proxy = Arc::clone(&self);
            thread::spawn(move || proxy.connection(number, client));
        }
        Ok(())
    }

    fn connection(&self, number: u64, client: TcpStream) {
        let Ok(upstream) = TcpStream::connect(self.upstream) else {
            // The client sees the refusal it would see from the upstream itself: a closed socket.
            let _ = client.shutdown(Shutdown::Both);
            let _ = self
                .queue
                .try_send((format!("c{number}"), Event::Lost("the upstream refused the connection".to_owned())));
            return;
        };
        let (Ok(client_reader), Ok(upstream_writer)) = (client.try_clone(), upstream.try_clone()) else {
            return;
        };
        let back = thread::spawn(move || pump(upstream, client, |_| {}));
        let mut tee = Tee::new(self.body_cap);
        let mut sequence = 0_u64;
        pump(client_reader, upstream_writer, |bytes| {
            for event in tee.feed(bytes) {
                sequence += 1;
                match self.queue.try_send((format!("c{number}#{sequence}"), event)) {
                    Ok(()) => {
                        self.counters.copied.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                        self.counters.shed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        let _ = back.join();
    }
}

/// Copies `from` to `to` until `from` ends, showing each piece to `copy` after it was written.
fn pump(mut from: TcpStream, mut to: TcpStream, mut copy: impl FnMut(&[u8])) {
    let mut buffer = vec![0_u8; 64 << 10];
    loop {
        match from.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if to.write_all(&buffer[..read]).is_err() {
                    break;
                }
                copy(&buffer[..read]);
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

/// Judges queued copies with `judge`, writing one line each to `log`, until every sender is gone.
pub fn judge_all(queue: &Receiver<(String, Event)>, judge: &Judge, log: &mut dyn Write) {
    while let Ok((label, event)) = queue.recv() {
        let line = match event {
            Event::Request(captured) => format!("{label} {} {} {}", captured.method, captured.target, judge(&captured)),
            Event::Oversize { method, target } => format!("{label} {method} {target} skip: body over the comparison cap"),
            Event::Lost(why) => format!("{label} stopped copying: {why}"),
        };
        let _ = writeln!(log, "{line}");
        let _ = log.flush();
    }
}

/// A copied request as the decode diff sends it, or why it cannot be sent.
///
/// # Errors
///
/// The reason the request is skipped.
pub fn request_of(captured: &Captured) -> Result<RawRequest, String> {
    let method = http::Method::from_bytes(captured.method.as_bytes()).map_err(|_| "a method the diff cannot send".to_owned())?;
    let (path, query) = captured.target.split_once('?').unwrap_or((captured.target.as_str(), ""));
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter(|pair| !PRESIGN_PARAMETERS.contains(&pair.split_once('=').map_or(*pair, |(name, _)| name)))
        .collect();
    let target = if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    };
    let signed_by_client = kept.len() != query.split('&').filter(|pair| !pair.is_empty()).count()
        || captured
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization"));
    let mut request = RawRequest::new(method, &target);
    for (name, value) in &captured.headers {
        if name.eq_ignore_ascii_case("x-amz-content-sha256") && value.starts_with(b"STREAMING-AWS4-") {
            return Err("signed chunk framing: its chunk signatures cannot be replayed unsigned".to_owned());
        }
        let framing =
            captured.chunked && (name.eq_ignore_ascii_case("transfer-encoding") || name.eq_ignore_ascii_case("content-length"));
        if name.eq_ignore_ascii_case("authorization") || framing {
            continue;
        }
        request.headers.push((name.clone(), value.clone()));
    }
    if captured.chunked {
        request
            .headers
            .push(("content-length".to_owned(), captured.body.len().to_string().into_bytes()));
    }
    if !captured.body.is_empty() {
        request.body = vec![bytes::Bytes::copy_from_slice(&captured.body)];
    }
    // A request the client signed is signed again with the credential both stacks hold, so it
    // takes the authenticated path it took upstream; an anonymous one stays anonymous.
    if signed_by_client {
        request = crate::sign::signed(&request).map_err(|why| format!("cannot sign the replay: {why}"))?;
    }
    Ok(request)
}

fn register() -> Result<&'static KnownDiffs, String> {
    static REGISTER: OnceLock<Result<KnownDiffs, String>> = OnceLock::new();
    REGISTER
        .get_or_init(|| KnownDiffs::checked_in().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(Clone::clone)
}

/// The log verdict for one copied request: `agree`, `known <ids>`, `DIFF <findings>`,
/// `skip: <why>` or `harness: <why>`.
#[must_use]
pub fn judge(captured: &Captured) -> String {
    let request = match request_of(captured) {
        Ok(request) => request,
        Err(why) => return format!("skip: {why}"),
    };
    let diff = match crate::decode_diff(&request) {
        Ok(diff) => diff,
        Err(why) => return format!("harness: {why}"),
    };
    let register = match register() {
        Ok(register) => register,
        Err(why) => return format!("harness: the register: {why}"),
    };
    let verdict = register.verdict_for(&request, diff.findings());
    if !verdict.failures.is_empty() {
        let findings: Vec<String> = verdict.failures.iter().map(ToString::to_string).collect();
        return format!("DIFF {}", findings.join("; "));
    }
    if verdict.known.is_empty() {
        return "agree".to_owned();
    }
    let mut ids: Vec<&str> = verdict.known.iter().map(|(_, id)| id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    format!("known {}", ids.join(","))
}
