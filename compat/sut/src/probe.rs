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

//! Wire observation for the client-compatibility matrix.
//!
//! Responsible for: recording, per request the system under test actually served, the payload mode
//! a client chose, whether it framed the body as `aws-chunked`, how many signed chunks crossed the
//! socket, whether a trailer section followed, and whether the socket was encrypted — written as
//! one JSON object per line.
//! NOT responsible for: deciding whether a scenario passed, storing anything, or reproducing any
//! signature material. The chunk signatures themselves are counted and discarded; nothing here
//! writes a signature, an `Authorization` header, or a credential into the log — including the
//! ones a presigned request carries in its query string, whose values are redacted.
//! Every record also names who answered: `service` (the launcher's own `S3Service`), `upstream`
//! (an external endpoint behind `--external`) or `observer` (the observer itself, when that
//! endpoint could not be reached), so an answer nobody measured can never pass for a measured one.
//! Upstream: `crate::main`, which wraps the assembled `S3Service`, or `crate::forward::Forward`
//! under `--external`, in [`ProbeService`].
//! Downstream: `ci/compat/report.py`, which reads the log to decide whether a client really
//! emitted `STREAMING-AWS4-HMAC-SHA256` framing rather than merely exiting zero.

use std::convert::Infallible;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::Write as _;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Buf as _;
use http::Request;
use rustfs_gateway::{S3Service, TransportSecurity};

use crate::forward::AnsweredBy;

/// The chunk-extension every signed `aws-chunked` frame carries.
///
/// Only its occurrences are counted. The 64 hex characters that follow it are a signature and are
/// never read, stored, or logged.
const CHUNK_SIGNATURE_EXTENSION: &[u8] = b";chunk-signature=";

/// The trailing-header signature line that closes a `-TRAILER` payload mode.
const TRAILER_SIGNATURE_LINE: &[u8] = b"x-amz-trailer-signature:";

/// Counts non-overlapping occurrences of one needle across a stream delivered in arbitrary frames.
///
/// The retained tail is one byte shorter than the needle, which is what makes the count exact: a
/// complete needle cannot fit inside the tail, so nothing is counted twice, and a needle split
/// across two frames still has its prefix in the window when its suffix arrives.
struct NeedleCounter {
    needle: &'static [u8],
    carry: Vec<u8>,
    count: u64,
}

impl NeedleCounter {
    fn new(needle: &'static [u8]) -> Self {
        Self {
            needle,
            carry: Vec::new(),
            count: 0,
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        let mut window = std::mem::take(&mut self.carry);
        window.extend_from_slice(chunk);
        self.count += count_occurrences(&window, self.needle);
        let keep = window.len().min(self.needle.len() - 1);
        self.carry = window.split_off(window.len() - keep);
    }
}

/// The `x-amz-content-sha256` values that name a payload mode rather than a digest.
///
/// A value outside this set is a hex digest of the body. It is not secret, but it is also not
/// information the matrix uses, so it is recorded as the constant `sha256-hex` instead: an
/// evidence file that never contains an unbounded client-supplied string cannot leak one.
const PAYLOAD_MODE_SENTINELS: &[&str] = &[
    "UNSIGNED-PAYLOAD",
    "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
    "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD",
    "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER",
];

/// The append-only evidence file, plus the count of records written to it.
pub(crate) struct ProbeLog {
    file: Mutex<File>,
    records: AtomicU64,
}

impl ProbeLog {
    /// Opens (creating or truncating) the evidence file at `path`.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the file cannot be created.
    pub(crate) fn create(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            records: AtomicU64::new(0),
        })
    }

    /// How many records have been written. Used by the readiness banner only.
    pub(crate) fn records(&self) -> u64 {
        self.records.load(Ordering::Relaxed)
    }

    fn append(&self, line: &str) {
        // A probe that cannot record is a probe that reports nothing while looking healthy, so the
        // failure is announced on stderr rather than swallowed. It does not abort the request:
        // the client under test is measuring the gateway, not the evidence file.
        let Ok(mut file) = self.file.lock() else {
            eprintln!("compat-sut: probe log mutex was poisoned; evidence is incomplete");
            return;
        };
        if let Err(error) = writeln!(file, "{line}").and_then(|()| file.flush()) {
            eprintln!("compat-sut: probe log write failed: {error}");
            return;
        }
        self.records.fetch_add(1, Ordering::Relaxed);
    }
}

/// What one request's body looked like on the wire, published to the record writer.
#[derive(Default)]
struct BodyFacts {
    /// Occurrences of `;chunk-signature=`: one per signed `aws-chunked` frame.
    signed_chunks: AtomicU64,
    /// Occurrences of a trailing-header signature line closing a `-TRAILER` payload mode.
    trailer_signature: AtomicU64,
    /// Bytes the transport handed over, framing included.
    wire_bytes: AtomicU64,
}

/// A request body that counts what crosses it and forwards every byte unchanged.
pub(crate) struct ProbeBody<B> {
    inner: B,
    facts: Arc<BodyFacts>,
    signed_chunks: NeedleCounter,
    trailer_signature: NeedleCounter,
}

impl<B> ProbeBody<B> {
    fn new(inner: B, facts: Arc<BodyFacts>) -> Self {
        Self {
            inner,
            facts,
            signed_chunks: NeedleCounter::new(CHUNK_SIGNATURE_EXTENSION),
            trailer_signature: NeedleCounter::new(TRAILER_SIGNATURE_LINE),
        }
    }

    fn observe(&mut self, chunk: &[u8]) {
        self.facts.wire_bytes.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        self.signed_chunks.feed(chunk);
        self.trailer_signature.feed(chunk);
        self.facts.signed_chunks.store(self.signed_chunks.count, Ordering::Relaxed);
        self.facts
            .trailer_signature
            .store(self.trailer_signature.count, Ordering::Relaxed);
    }
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> u64 {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    let mut found = 0;
    let mut index = 0;
    while index + needle.len() <= haystack.len() {
        if &haystack[index..index + needle.len()] == needle {
            found += 1;
            index += needle.len();
        } else {
            index += 1;
        }
    }
    found
}

impl<B> http_body::Body for ProbeBody<B>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin,
{
    type Data = bytes::Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    // `Bytes` is one contiguous region, so `chunk()` is the whole frame.
                    this.observe(data.chunk());
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// The served service, wrapped so that every request leaves one evidence record.
///
/// `S` is the launcher's own `S3Service`, or `crate::forward::Forward` when `--external` puts an
/// endpoint started elsewhere behind the same listeners; the record is the same either way, plus
/// who answered.
#[derive(Clone)]
pub(crate) struct ProbeService<S = S3Service> {
    inner: S,
    log: Option<Arc<ProbeLog>>,
}

impl<S> ProbeService<S> {
    /// Wraps `inner`, appending one record per served request to `log` when there is one.
    ///
    /// `None` records nothing, and is what a launch without `--probe-log` gets: the probe is
    /// opt-in so that a driver being debugged by hand does not overwrite a matrix run's evidence.
    /// It is one type either way so that the plaintext and the encrypted listener serve the same
    /// value.
    pub(crate) fn new(inner: S, log: Option<Arc<ProbeLog>>) -> Self {
        Self { inner, log }
    }
}

type ProbeFuture<R> = Pin<Box<dyn Future<Output = Result<R, Infallible>> + Send>>;

impl<S, B, R> tower::Service<Request<B>> for ProbeService<S>
where
    S: tower::Service<Request<ProbeBody<B>>, Response = http::Response<R>, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
    R: Send + 'static,
    B: http_body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = http::Response<R>;
    type Error = Infallible;
    type Future = ProbeFuture<Self::Response>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let facts = Arc::new(BodyFacts::default());
        let log = self.log.clone();
        let mut inner = self.inner.clone();
        let (parts, body) = request.into_parts();
        let record = RequestFacts::of(&parts);
        let request = Request::from_parts(parts, ProbeBody::new(body, Arc::clone(&facts)));
        let call = tower::Service::call(&mut inner, request);
        Box::pin(async move {
            let response: Result<Self::Response, Infallible> = call.await;
            let (status, answered_by) = match &response {
                Ok(answered) => (
                    answered.status().as_u16(),
                    // The launcher's own service marks nothing: it answered in-process.
                    answered
                        .extensions()
                        .get::<AnsweredBy>()
                        .map_or("service", |who| who.as_str()),
                ),
                // The inner service's error is `Infallible`, so this arm is unreachable in
                // practice; it is spelled out rather than unwrapped because the record must not
                // be the thing that panics.
                Err(_) => (0, "service"),
            };
            if let Some(log) = log {
                log.append(&record.render(status, answered_by, &facts));
            }
            response
        })
    }
}

/// The request-side fields of one evidence record, captured before the body is read.
struct RequestFacts {
    method: String,
    path: String,
    query: String,
    payload_mode: String,
    content_encoding: String,
    decoded_length: String,
    declared_trailer: String,
    client: String,
    /// What the gateway is about to be told about the socket: the `TransportSecurity` that
    /// `crate::transport::DeclareTransport` inserted, read back rather than recomputed, so the
    /// record shows the fact the customer-key gate acts on.
    transport: &'static str,
}

impl RequestFacts {
    fn of(parts: &http::request::Parts) -> Self {
        let header = |name: &str| -> String {
            parts
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        let raw_sha256 = header("x-amz-content-sha256");
        let payload_mode = if PAYLOAD_MODE_SENTINELS.contains(&raw_sha256.as_str()) {
            raw_sha256
        } else if raw_sha256.is_empty() {
            String::new()
        } else {
            "sha256-hex".to_owned()
        };
        Self {
            method: parts.method.as_str().to_owned(),
            path: parts.uri.path().to_owned(),
            query: redact_query(parts.uri.query().unwrap_or_default()),
            payload_mode,
            content_encoding: header("content-encoding"),
            decoded_length: header("x-amz-decoded-content-length"),
            declared_trailer: header("x-amz-trailer"),
            client: header("user-agent"),
            transport: match parts.extensions.get::<TransportSecurity>() {
                Some(TransportSecurity::Encrypted) => "encrypted",
                Some(TransportSecurity::Plaintext) | None => "plaintext",
            },
        }
    }

    fn render(&self, status: u16, answered_by: &str, facts: &BodyFacts) -> String {
        format!(
            concat!(
                "{{\"method\":{},\"path\":{},\"query\":{},\"status\":{},\"answered_by\":{},",
                "\"payload_mode\":{},\"content_encoding\":{},\"decoded_content_length\":{},",
                "\"declared_trailer\":{},\"signed_chunks\":{},\"trailer_signature\":{},",
                "\"request_wire_bytes\":{},\"user_agent\":{},\"transport\":{}}}"
            ),
            quote(&self.method),
            quote(&self.path),
            quote(&self.query),
            status,
            quote(answered_by),
            quote(&self.payload_mode),
            quote(&self.content_encoding),
            quote(&self.decoded_length),
            quote(&self.declared_trailer),
            facts.signed_chunks.load(Ordering::Relaxed),
            facts.trailer_signature.load(Ordering::Relaxed),
            facts.wire_bytes.load(Ordering::Relaxed),
            quote(&self.client),
            quote(self.transport),
        )
    }
}

/// The constant a redacted query value is replaced with.
const REDACTED: &str = "__REDACTED__";

/// Query parameters whose value is a signature, a credential or a session token.
///
/// A presigned request carries its authentication in the query string, so recording the query
/// verbatim would write a signature and an access key into the evidence file — which is uploaded
/// as a workflow artifact and read by the corpus converter. The names stay, because they are what
/// tells a presigned request from a plain one; only the values go (rustfs/gateway#911).
const SENSITIVE_QUERY_PARAMETERS: &[&str] = &[
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
    "signature",
    "awsaccesskeyid",
];

/// Replaces the value of every [`SENSITIVE_QUERY_PARAMETERS`] entry with [`REDACTED`].
///
/// Names are compared case-insensitively after percent-decoding, so `X%2DAmz%2DSignature` is
/// the same parameter a server would read. Everything else is kept byte for byte.
fn redact_query(query: &str) -> String {
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) if is_sensitive_name(name) => format!("{name}={REDACTED}"),
            _ => pair.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn is_sensitive_name(raw: &str) -> bool {
    let decoded = percent_decode_ascii(raw).to_ascii_lowercase();
    SENSITIVE_QUERY_PARAMETERS.contains(&decoded.as_str())
}

/// Decodes `%XX` escapes. An escape that is not two hex digits is kept literally: a malformed
/// name is not a sensitive one, and this function never fails.
fn percent_decode_ascii(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let escaped = (byte == b'%')
            .then(|| bytes.get(index + 1..index + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        if let Some(value) = escaped {
            decoded.push(value);
            index += 3;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Renders one JSON string, escaping what JSON requires and dropping the rest.
fn quote(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len() + 2);
    rendered.push('"');
    for character in value.chars() {
        match character {
            '"' => rendered.push_str("\\\""),
            '\\' => rendered.push_str("\\\\"),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            '\t' => rendered.push_str("\\t"),
            control if control.is_control() => rendered.push('.'),
            other => rendered.push(other),
        }
    }
    rendered.push('"');
    rendered
}

#[cfg(test)]
mod tests {
    use super::{
        CHUNK_SIGNATURE_EXTENSION, NeedleCounter, PAYLOAD_MODE_SENTINELS, REDACTED, RequestFacts, count_occurrences, quote,
        redact_query,
    };

    fn count_over_frames(frames: &[&[u8]]) -> u64 {
        let mut counter = NeedleCounter::new(CHUNK_SIGNATURE_EXTENSION);
        for frame in frames {
            counter.feed(frame);
        }
        counter.count
    }

    #[test]
    fn two_signed_frames_in_one_delivery_are_counted_twice() {
        assert_eq!(count_over_frames(&[b"5;chunk-signature=abc\r\ndata\r\n0;chunk-signature=def\r\n"]), 2);
    }

    #[test]
    fn a_needle_split_across_two_deliveries_is_still_counted() {
        assert_eq!(count_over_frames(&[b"5;chunk-sig", b"nature=abc\r\n"]), 1);
    }

    #[test]
    fn the_retained_tail_cannot_recount_a_needle_it_already_saw() {
        // The tail kept after the first delivery ends with a complete needle; a naive carry
        // window would count it again when the second delivery arrives.
        assert_eq!(count_over_frames(&[b"0;chunk-signature=", b"abc\r\n"]), 1);
    }

    #[test]
    fn an_unsigned_chunked_body_is_counted_as_zero_signed_frames() {
        assert_eq!(count_over_frames(&[b"5\r\ndata\r\n0\r\n\r\n"]), 0);
    }

    #[test]
    fn overlapping_prefixes_do_not_double_count() {
        assert_eq!(count_occurrences(b";chunk-signature=;chunk-signature=", b";chunk-signature="), 2);
        assert_eq!(count_occurrences(b";chunk-signatur", b";chunk-signature="), 0);
    }

    #[test]
    fn a_hex_digest_is_recorded_as_a_constant_rather_than_copied() {
        let request = http::Request::builder()
            .method(http::Method::PUT)
            .uri("/bucket/key")
            .header("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .body(())
            .expect("a valid fixture request");
        let (parts, ()) = request.into_parts();
        assert_eq!(RequestFacts::of(&parts).payload_mode, "sha256-hex");
    }

    #[test]
    fn a_streaming_sentinel_is_recorded_verbatim() {
        let request = http::Request::builder()
            .method(http::Method::PUT)
            .uri("/bucket/key")
            .header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
            .body(())
            .expect("a valid fixture request");
        let (parts, ()) = request.into_parts();
        let facts = RequestFacts::of(&parts);
        assert_eq!(facts.payload_mode, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
        assert!(PAYLOAD_MODE_SENTINELS.contains(&facts.payload_mode.as_str()));
    }

    fn recorded_query(uri: &str) -> String {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(())
            .expect("a valid fixture request");
        let (parts, ()) = request.into_parts();
        RequestFacts::of(&parts).query
    }

    #[test]
    fn a_sigv4_presigned_signature_and_credential_are_not_recorded() {
        let query = recorded_query(
            "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20260928%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20260928T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host\
             &X-Amz-Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        assert!(!query.contains("AKIDEXAMPLE"), "{query}");
        assert!(!query.contains("0123456789abcdef"), "{query}");
        assert!(query.contains(&format!("X-Amz-Credential={REDACTED}")), "{query}");
        assert!(query.contains(&format!("X-Amz-Signature={REDACTED}")), "{query}");
        // The parameters that say what kind of request it was survive.
        assert!(query.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"), "{query}");
        assert!(query.contains("X-Amz-Expires=300"), "{query}");
    }

    #[test]
    fn a_sigv2_presigned_signature_and_access_key_are_not_recorded() {
        let query = recorded_query("/b/k?AWSAccessKeyId=AKIDEXAMPLE&Expires=1790558621&Signature=v11ya5bUkQVr3yyFi8vM%3D");
        assert_eq!(query, format!("AWSAccessKeyId={REDACTED}&Expires=1790558621&Signature={REDACTED}"));
    }

    #[test]
    fn a_session_token_in_the_query_is_not_recorded() {
        let query = recorded_query("/b/k?X-Amz-Security-Token=FQoGZXIvYXdzEXAMPLE&x-amz-security-token=second");
        assert_eq!(query, format!("X-Amz-Security-Token={REDACTED}&x-amz-security-token={REDACTED}"));
    }

    #[test]
    fn a_sensitive_name_is_matched_regardless_of_case() {
        assert_eq!(
            redact_query("x-amz-signature=abc&SIGNATURE=def"),
            format!("x-amz-signature={REDACTED}&SIGNATURE={REDACTED}")
        );
    }

    #[test]
    fn a_percent_encoded_sensitive_name_is_still_matched() {
        assert_eq!(redact_query("X%2DAmz%2DSignature=abc"), format!("X%2DAmz%2DSignature={REDACTED}"));
    }

    #[test]
    fn a_name_that_only_contains_a_sensitive_word_is_kept() {
        assert_eq!(redact_query("prefix=Signature&SignatureDisplay=x"), "prefix=Signature&SignatureDisplay=x");
    }

    #[test]
    fn an_ordinary_query_is_recorded_unchanged() {
        assert_eq!(
            recorded_query("/b?list-type=2&prefix=page%2F&max-keys=7"),
            "list-type=2&prefix=page%2F&max-keys=7"
        );
        assert_eq!(recorded_query("/b/k?uploads"), "uploads");
        assert_eq!(recorded_query("/b/k?acl&versionId=3"), "acl&versionId=3");
    }

    #[test]
    fn quoting_escapes_what_would_otherwise_break_the_line() {
        assert_eq!(quote("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
    }
}
