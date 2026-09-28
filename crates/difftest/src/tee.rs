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

//! The shadow proxy's copy of one connection's client bytes, read back as HTTP/1.1 requests.
//!
//! Responsible for: taking the bytes a client sent, in whatever pieces they arrived, and
//! producing each complete request (head and de-framed body: `Content-Length` or `chunked`,
//! pipelined requests in order); skipping the body of a request larger than the cap while still
//! finding the next request; and giving up on the connection — reporting why, once — when the
//! bytes stop being HTTP/1.1 (not a request, a head over 64 KiB, a protocol upgrade, a chunked
//! body over the cap).
//! NOT responsible for: forwarding (the proxy forwards every byte before this sees it, so nothing
//! here can delay or change what the upstream receives), or judging a request (`shadow.rs`).
//! Upstream: the proxy's client-to-upstream pump. Downstream: `shadow.rs`.

/// One request as the client sent it, its body de-framed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Captured {
    /// The method, as sent.
    pub method: String,
    /// The request target, as sent.
    pub target: String,
    /// The header lines, in order, as sent.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body with its transfer framing removed.
    pub body: Vec<u8>,
    /// The body arrived `chunked`: its `Transfer-Encoding` line describes framing that is gone.
    pub chunked: bool,
}

/// What the copy of a connection produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A complete request.
    Request(Captured),
    /// A request whose body is over the cap: forwarded, not compared.
    Oversize {
        /// The method.
        method: String,
        /// The target.
        target: String,
    },
    /// The connection stopped being readable as HTTP/1.1 requests; nothing more is copied from it.
    Lost(String),
}

/// The largest request head read before giving up.
const HEAD_CAP: usize = 64 << 10;

/// The most header lines one head may hold.
const HEADER_LINES: usize = 128;

enum State {
    Head,
    Body { request: Captured, remaining: usize },
    Chunked { request: Captured },
    Skip { remaining: usize },
    Lost,
}

/// The copy of one connection's client bytes.
pub struct Tee {
    buffer: Vec<u8>,
    state: State,
    body_cap: usize,
    /// The request being read upgrades the connection: nothing after it is HTTP.
    upgrading: bool,
}

enum Framing {
    Length(usize),
    Chunked,
}

impl Tee {
    /// A copy that compares bodies up to `body_cap` bytes.
    #[must_use]
    pub const fn new(body_cap: usize) -> Self {
        Self {
            buffer: Vec::new(),
            state: State::Head,
            body_cap,
            upgrading: false,
        }
    }

    /// The next bytes the client sent; returns what they completed.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        match &mut self.state {
            State::Lost => return events,
            State::Skip { remaining } => {
                let skipped = (*remaining).min(bytes.len());
                *remaining -= skipped;
                self.buffer.extend_from_slice(&bytes[skipped..]);
                if *remaining == 0 {
                    self.state = State::Head;
                }
            }
            _ => self.buffer.extend_from_slice(bytes),
        }
        while let Some(event) = self.step() {
            let lost = matches!(event, Event::Lost(_)) || self.upgrading;
            events.push(event);
            if lost {
                self.state = State::Lost;
                self.buffer = Vec::new();
                break;
            }
        }
        events
    }

    fn lose(&mut self, why: impl Into<String>) -> Option<Event> {
        Some(Event::Lost(why.into()))
    }

    /// Advances by at most one event; `None` when more bytes are needed.
    fn step(&mut self) -> Option<Event> {
        match std::mem::replace(&mut self.state, State::Head) {
            State::Lost => {
                self.state = State::Lost;
                None
            }
            State::Skip { remaining } => {
                let skipped = remaining.min(self.buffer.len());
                self.buffer.drain(..skipped);
                if remaining > skipped {
                    self.state = State::Skip {
                        remaining: remaining - skipped,
                    };
                    return None;
                }
                self.step()
            }
            State::Head => self.head(),
            State::Body { request, remaining } => {
                if self.buffer.len() < remaining {
                    self.state = State::Body { request, remaining };
                    return None;
                }
                let body = self.buffer.drain(..remaining).collect();
                Some(Event::Request(Captured { body, ..request }))
            }
            State::Chunked { request } => match dechunk(&self.buffer) {
                Ok(Some((body, used))) => {
                    self.buffer.drain(..used);
                    Some(Event::Request(Captured { body, ..request }))
                }
                Ok(None) if self.buffer.len() > self.body_cap => self.lose("a chunked body over the comparison cap"),
                Ok(None) => {
                    self.state = State::Chunked { request };
                    None
                }
                Err(why) => self.lose(why),
            },
        }
    }

    fn head(&mut self) -> Option<Event> {
        if self.buffer.is_empty() {
            return None;
        }
        let mut lines = [httparse::EMPTY_HEADER; HEADER_LINES];
        let mut parsed = httparse::Request::new(&mut lines);
        let used = match parsed.parse(&self.buffer) {
            Ok(httparse::Status::Complete(used)) => used,
            Ok(httparse::Status::Partial) if self.buffer.len() > HEAD_CAP => return self.lose("a request head over 64 KiB"),
            Ok(httparse::Status::Partial) => return None,
            Err(error) => return self.lose(format!("not an HTTP/1.1 request: {error}")),
        };
        let (Some(method), Some(target)) = (parsed.method, parsed.path) else {
            return self.lose("a request head without a method or target");
        };
        let request = Captured {
            method: method.to_owned(),
            target: target.to_owned(),
            headers: parsed
                .headers
                .iter()
                .map(|header| (header.name.to_owned(), header.value.to_vec()))
                .collect(),
            body: Vec::new(),
            chunked: false,
        };
        // The request itself is still HTTP; what follows it on the connection is not.
        self.upgrading = request.method.eq_ignore_ascii_case("CONNECT")
            || request.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("upgrade"));
        self.buffer.drain(..used);
        let framing = match framing(&request.headers) {
            Ok(framing) => framing,
            Err(why) => return self.lose(why),
        };
        match framing {
            Framing::Chunked => {
                self.state = State::Chunked {
                    request: Captured {
                        chunked: true,
                        ..request
                    },
                };
                self.step()
            }
            Framing::Length(length) if length > self.body_cap => {
                self.state = State::Skip { remaining: length };
                Some(Event::Oversize {
                    method: request.method,
                    target: request.target,
                })
            }
            Framing::Length(length) => {
                self.state = State::Body {
                    request,
                    remaining: length,
                };
                self.step()
            }
        }
    }
}

/// The request's body framing, as RFC 9112 section 6.3 reads it: `chunked` wins over a length.
fn framing(headers: &[(String, Vec<u8>)]) -> Result<Framing, String> {
    if values(headers, "transfer-encoding").any(|coding| {
        String::from_utf8_lossy(coding)
            .rsplit(',')
            .next()
            .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"))
    }) {
        return Ok(Framing::Chunked);
    }
    let lengths: Vec<&Vec<u8>> = values(headers, "content-length").collect();
    match lengths.as_slice() {
        [] => Ok(Framing::Length(0)),
        [length] => std::str::from_utf8(length)
            .ok()
            .and_then(|length| length.trim().parse().ok())
            .map(Framing::Length)
            .ok_or_else(|| "a Content-Length that is not a length".to_owned()),
        _ => Err("more than one Content-Length line".to_owned()),
    }
}

/// Every value of one header, by case-insensitive name.
fn values<'a>(headers: &'a [(String, Vec<u8>)], name: &'a str) -> impl Iterator<Item = &'a Vec<u8>> {
    headers
        .iter()
        .filter(move |(present, _)| present.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn line_end(bytes: &[u8], from: usize) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|at| from + at)
}

/// A complete chunked body at the start of `bytes`, de-framed, and the bytes it used; `None` while
/// it is incomplete.
fn dechunk(bytes: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    let mut body = Vec::new();
    let mut at = 0;
    loop {
        let Some(end) = line_end(bytes, at) else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&bytes[at..end]).map_err(|_| "a chunk size line that is not text".to_owned())?;
        let size = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| format!("a chunk size that is not hex: {size:?}"))?;
        at = end + 2;
        if size == 0 {
            // Trailer lines, then the empty line that ends the message.
            loop {
                let Some(end) = line_end(bytes, at) else {
                    return Ok(None);
                };
                let empty = end == at;
                at = end + 2;
                if empty {
                    return Ok(Some((body, at)));
                }
            }
        }
        let Some(data) = bytes.get(at..at + size) else {
            return Ok(None);
        };
        body.extend_from_slice(data);
        at += size;
        match bytes.get(at..at + 2) {
            None => return Ok(None),
            Some(b"\r\n") => at += 2,
            Some(_) => return Err("a chunk not followed by CRLF".to_owned()),
        }
    }
}
