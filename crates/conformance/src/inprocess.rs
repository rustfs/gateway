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

//! The in-process target: a service assembled from the facade, driven without a socket.
//!
//! Responsible for: turning one `[request]` block into signed bytes, handing them to
//! [`rustfs_gateway::S3Service::call_bytes`], and turning what comes back into an
//! [`Observation`] — the response head in wire order, the body, and the trailers.
//! NOT responsible for: judging anything (`crate::expect`), or storing anything
//! (`crate::fixture`).
//! Upstream: `rustfs-gateway`, `crate::fixture`, `crate::exec`. Downstream: `crate::cli`.
//!
//! # What this transport can see, and what it cannot
//!
//! There is no connection here, so three families of assertion have no honest answer and this
//! module reports what is true of an in-process call rather than guessing what a socket would have
//! done. Each is stated once, here, so a red case can be read against it:
//!
//! * **`connection_after`** — the service is a value, not a peer. A completed exchange leaves it
//!   reusable, which is reported as `open`. A case asserting `closed`, `reset` or `half_closed`
//!   cannot be judged by this transport and will be red for that reason alone.
//! * **`request_progress`** — the whole body is handed over before the call begins, so
//!   `body_bytes_sent_at_response` is the whole body and `body_fully_sent` is true. A case
//!   asserting that the server refused *before* reading the payload is measuring something only a
//!   socket can measure; it will be red here even against a server that gets it right.
//! * **`timing`** — `elapsed_ms` and `ttfb_ms` are real but meaningless: an in-memory call takes
//!   microseconds, so an upper bound always holds and a lower bound never does.
//!
//! Everything else — status, error code, header set, header order, body bytes, trailers, capture —
//! is measured exactly.
//!
//! # What `kind` is, and what it is not allowed to be
//!
//! `expect.kind` was reported as `response` unconditionally, and `body_bytes_before_error` was never
//! recorded at all. That is a worse defect than a missing feature: the four cases that assert a late
//! failure could not have failed those assertions no matter what the server did, so the assertions
//! read as satisfied while measuring nothing. A blind spot in the instrument is invisible in the
//! report, which is the one place a conformance suite has to be trusted.
//!
//! Two things are reported now, and each is read off the exchange rather than assumed:
//!
//! * A response that arrived intact but whose status line and body **disagree** — a success status
//!   over an `<Error>` document — is a `stream_error` terminating in an `error_document`, and
//!   `body_bytes_before_error` is where that document begins. The classification is
//!   [`crate::observation::late_error_offset`]'s, so a socket transport will make it identically.
//! * A body that could not be drained is a `stream_error` terminating in an `abrupt_close`, and no
//!   longer an environment failure that *skips* the case.
//!
//! What is still out of reach is the byte count on that second path: `collect` discards what it had
//! read when the stream failed, so `body_bytes_before_error` is left unrecorded there rather than
//! guessed, and a case pinning it stays red. `stream_termination = "reset"` and `"trailer_error"`
//! need a connection and are likewise never reported.
//!
//! # Why a request is built twice
//!
//! Signing needs the host in the byte-exact form the canonical request uses, and the only way to
//! obtain one through the facade is [`rustfs_gateway::WireRequest::accept`], which consumes the
//! request. So the head is assembled once to be accepted and read, and again to be sent. The two
//! are built from the same description, so they cannot disagree.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, Tamper, TamperComponent,
};
use rustfs_gateway::{
    Credentials, FixedClock, Limits, RegionSet, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials, WireRequest,
    allow_when, collect, dto,
};

use crate::exec::block_on;
use crate::fixture::{Fixture, StoredObject, Stub};
use crate::interpolate::Captures;
use crate::observation::{ConnectionState, Observation, Outcome, StreamTermination, late_error_offset};
use crate::sut::{ExchangePlan, Sut, SutError};
use crate::time;
use crate::value::Value;

/// The access key id every case names as `valid`.
pub const VALID_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
/// Its secret. The AWS documentation example key, which is what makes a hand-checked signature
/// comparable against the worked examples in the SigV4 documentation.
pub const VALID_SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
/// The access key id the target has never heard of.
pub const UNKNOWN_ACCESS_KEY: &str = "AKIAI44QH8DHBEXAMPLE";
/// The secret used when a case asks to sign with the wrong one.
pub const WRONG_SECRET: &[u8] = b"this-is-not-the-secret-the-target-knows--";
/// The host every request addresses. Path-style, because the corpus writes `/bucket/key` targets.
pub const HOST: &str = "s3.example.com";
/// The region every case signs for.
pub const REGION: &str = "us-east-1";

/// A service assembled from the facade, plus the fixtures the current case established.
pub struct InProcess {
    root: PathBuf,
    state: Arc<Mutex<Fixture>>,
    limits: Limits,
}

impl InProcess {
    /// Builds a target rooted at a corpus directory, which is where `body.file` payloads are read
    /// from.
    #[must_use]
    pub fn new(root: PathBuf) -> InProcess {
        InProcess {
            root,
            state: Arc::new(Mutex::new(Fixture::at(0))),
            limits: Limits::default(),
        }
    }

    /// Assembles the service for one exchange.
    ///
    /// Rebuilt per exchange rather than once, because the clock is fixed at assembly time and is a
    /// per-case declaration. Assembly is a few table inserts; a stale clock would be a wrong answer.
    fn assemble(&self, at_unix_seconds: i64, skew_ms: i64) -> Result<S3Service, SutError> {
        let backend = Arc::new(Stub::new(Arc::clone(&self.state)));
        let credentials = Credentials::new(VALID_ACCESS_KEY, VALID_SECRET)
            .map_err(|error| SutError::Environment(format!("the fixture credentials are not valid: {error}")))?;
        let provider = Arc::new(StaticCredentials::new().with(credentials));
        let regions =
            RegionSet::new([REGION]).map_err(|error| SutError::Environment(format!("`{REGION}` is not a region: {error}")))?;
        let clock = FixedClock::at_unix_seconds(at_unix_seconds).skewed_by_millis(skew_ms);
        ServiceBuilder::new()
            .register::<dto::AbortMultipartUpload, _>(Arc::clone(&backend))
            .register::<dto::CompleteMultipartUpload, _>(Arc::clone(&backend))
            .register::<dto::CopyObject, _>(Arc::clone(&backend))
            .register::<dto::CreateMultipartUpload, _>(Arc::clone(&backend))
            .register::<dto::DeleteObject, _>(Arc::clone(&backend))
            .register::<dto::DeleteObjects, _>(Arc::clone(&backend))
            .register::<dto::GetBucketLocation, _>(Arc::clone(&backend))
            .register::<dto::GetObject, _>(Arc::clone(&backend))
            .register::<dto::HeadObject, _>(Arc::clone(&backend))
            .register::<dto::ListBuckets, _>(Arc::clone(&backend))
            .register::<dto::ListMultipartUploads, _>(Arc::clone(&backend))
            .register::<dto::ListObjectVersions, _>(Arc::clone(&backend))
            .register::<dto::ListObjects, _>(Arc::clone(&backend))
            .register::<dto::ListObjectsV2, _>(Arc::clone(&backend))
            .register::<dto::ListParts, _>(Arc::clone(&backend))
            .register::<dto::PutObject, _>(Arc::clone(&backend))
            .register::<dto::UploadPart, _>(Arc::clone(&backend))
            .register::<dto::UploadPartCopy, _>(Arc::clone(&backend))
            .authenticator(SigV4Authenticator::new(provider, regions))
            // Authorisation is not what this corpus measures: every case that reaches a handler is
            // signed with the one identity the fixtures know, and a policy engine here would turn
            // protocol failures into authorisation failures.
            .authorizer(allow_when(|request| !request.is_anonymous()))
            .clock(clock)
            .limits(self.limits)
            .build()
            .map_err(|error| SutError::Environment(format!("the service could not be assembled: {error}")))
    }

    /// Reads a `payload` block into bytes.
    fn payload(&self, payload: &Value) -> Result<Vec<u8>, SutError> {
        if let Some(text) = payload.get("utf8").and_then(Value::as_str) {
            return Ok(text.as_bytes().to_vec());
        }
        if let Some(text) = payload.get("hex").and_then(Value::as_str) {
            return decode_hex(text).ok_or_else(|| SutError::Environment(format!("`{text}` is not valid hex")));
        }
        if let Some(relative) = payload.get("file").and_then(Value::as_str) {
            let path = self.root.join(relative);
            return std::fs::read(&path)
                .map_err(|error| SutError::Environment(format!("cannot read {}: {error}", path.display())));
        }
        if let Some(size) = payload.get("size").and_then(Value::as_integer) {
            let size = usize::try_from(size).unwrap_or(0);
            let fill = payload.get("fill").and_then(Value::as_str);
            return Ok(generate(size, fill));
        }
        Err(SutError::Environment("a payload names no source".to_owned()))
    }
}

/// Generates `size` bytes.
///
/// `fill` is read as hex when it is valid hex, because the corpus writes `fill = "ff"` meaning one
/// byte and not two. With no `fill` the pattern is `index % 251`, which is deterministic, has no
/// period that lines up with a power-of-two block size, and is therefore a payload whose corruption
/// a digest actually notices.
fn generate(size: usize, fill: Option<&str>) -> Vec<u8> {
    let pattern = fill
        .and_then(decode_hex)
        .or_else(|| fill.map(|text| text.as_bytes().to_vec()))
        .filter(|bytes| !bytes.is_empty());
    match pattern {
        Some(pattern) => (0..size)
            .map(|index| pattern.get(index % pattern.len()).copied().unwrap_or(0))
            .collect(),
        None => (0..size).map(|index| (index % 251) as u8).collect(),
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (*pair.first()? as char).to_digit(16)?;
        let low = (*pair.get(1)? as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

/// The clock a case declared, or the pinned default.
fn clock_of(clock: Option<&Value>) -> Result<(time::Instant, time::Instant, i64), SutError> {
    let read = |key: &str| -> Result<Option<time::Instant>, SutError> {
        match clock.and_then(|clock| clock.get(key)).and_then(Value::as_str) {
            None => Ok(None),
            Some(text) => time::parse_rfc3339(text).map(Some).map_err(SutError::Environment),
        }
    };
    let fixed = read("fixed")?.map_or_else(|| time::parse_rfc3339(time::DEFAULT_FIXED).map_err(SutError::Environment), Ok)?;
    let request_time = read("request_time")?.unwrap_or_else(|| fixed.clone());
    let skew_ms = clock
        .and_then(|clock| clock.get("skew_ms"))
        .and_then(Value::as_integer)
        .unwrap_or(0);
    Ok((fixed, request_time, skew_ms))
}

/// One request, read out of the case and ready to be signed.
#[derive(Debug)]
struct Wire {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    sign: Option<Value>,
}

impl InProcess {
    /// Reads a `[request]` block, refusing every shape a socketless transport cannot send.
    fn read_request(&self, request: &Value) -> Result<Wire, SutError> {
        for unsupported in ["raw_head_utf8", "raw_head_hex", "h2_frames"] {
            if request.get(unsupported).is_some() {
                return Err(SutError::Environment(format!(
                    "`request.{unsupported}` needs a transport that writes bytes on a socket; the \
                     in-process target hands a parsed `http::Request` to the service and cannot \
                     express a malformed head"
                )));
            }
        }
        if request.get("http_version").and_then(Value::as_str) == Some("h2") {
            return Err(SutError::Environment(
                "`request.http_version = \"h2\"` needs a real HTTP/2 framing layer".to_owned(),
            ));
        }
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| SutError::Environment("a request has no method".to_owned()))?
            .to_owned();
        let target = request
            .get("target")
            .and_then(Value::as_str)
            .ok_or_else(|| SutError::Environment("a request has no target".to_owned()))?
            .to_owned();

        let mut headers = Vec::new();
        if let Some(Value::Table(entries)) = request.get("headers") {
            for (name, value) in entries {
                match value {
                    Value::String(text) => headers.push((name.clone(), text.clone())),
                    Value::Array(items) => {
                        for item in items.iter().filter_map(Value::as_str) {
                            headers.push((name.clone(), item.to_owned()));
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(Value::Array(rows)) = request.get("raw_headers") {
            for row in rows {
                let pair: Vec<&str> = row.as_array().unwrap_or_default().iter().filter_map(Value::as_str).collect();
                if let (Some(name), Some(value)) = (pair.first(), pair.get(1)) {
                    headers.push(((*name).to_owned(), (*value).to_owned()));
                }
            }
        }

        let body = match (request.get("body"), request.get("chunks")) {
            (Some(payload), _) => self.payload(payload)?,
            (None, Some(Value::Array(chunks))) => self.chunks(chunks)?,
            _ => Vec::new(),
        };

        Ok(Wire {
            method,
            target,
            headers,
            body,
            sign: request.get("sign").cloned(),
        })
    }

    /// Flattens a chunk sequence into one body.
    ///
    /// `delay_ms` is dropped on purpose: it exists to make arrival timing observable, and nothing
    /// in an in-process call observes it. A control chunk is refused rather than dropped, because
    /// a case that half-closes the connection is asserting something about a socket and answering
    /// it from a complete body would be a false green.
    fn chunks(&self, chunks: &[Value]) -> Result<Vec<u8>, SutError> {
        let mut body = Vec::new();
        for chunk in chunks {
            if let Some(action) = chunk.get("action").and_then(Value::as_str) {
                return Err(SutError::Environment(format!(
                    "a `{action}` control chunk needs a transport that owns the connection; the \
                     in-process target hands over a complete body"
                )));
            }
            let repeat = usize::try_from(chunk.get("repeat").and_then(Value::as_integer).unwrap_or(1)).unwrap_or(1);
            let unit = if chunk.get("raw_utf8").is_some() || chunk.get("raw_hex").is_some() {
                let renamed = Value::Table(
                    chunk
                        .as_table()
                        .unwrap_or_default()
                        .iter()
                        .map(|(key, value)| (key.trim_start_matches("raw_").to_owned(), value.clone()))
                        .collect(),
                );
                self.payload(&renamed)?
            } else {
                self.payload(chunk)?
            };
            for _ in 0..repeat {
                body.extend_from_slice(&unit);
            }
        }
        Ok(body)
    }
}

/// Splits a request target into its path and its query, neither decoded.
fn split_target(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    }
}

/// Builds the `http::Request` the service is called with.
fn assemble_request(
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> Result<http::Request<bytes::Bytes>, SutError> {
    let mut builder = http::Request::builder().method(method).uri(target);
    for (name, value) in headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .body(bytes::Bytes::from(body))
        .map_err(|error| SutError::Environment(format!("the request could not be built: {error}")))
}

/// Reads `sign.tamper` into the signer's own description.
fn read_tamper(spec: &Value) -> Result<Tamper, SutError> {
    let component = spec
        .get("component")
        .and_then(Value::as_str)
        .ok_or_else(|| SutError::Environment("a tamper names no component".to_owned()))?;
    let component = match component {
        "signature" => TamperComponent::Signature,
        "access_key" => TamperComponent::AccessKey,
        "scope_date" => TamperComponent::ScopeDate,
        "scope_region" => TamperComponent::ScopeRegion,
        "scope_service" => TamperComponent::ScopeService,
        "signed_headers_list" => TamperComponent::SignedHeadersList,
        "canonical_query" => TamperComponent::CanonicalQuery,
        "canonical_path" => TamperComponent::CanonicalPath,
        "canonical_header_value" => TamperComponent::CanonicalHeaderValue,
        "payload_hash" => TamperComponent::PayloadHash,
        "date_header" => TamperComponent::DateHeader,
        other => return Err(SutError::Environment(format!("unknown tamper component `{other}`"))),
    };
    let mut tamper = Tamper::new(component);
    if let Some(target) = spec.get("target").and_then(Value::as_str) {
        tamper = tamper.with_target(target);
    }
    if let Some(value) = spec.get("new_value").and_then(Value::as_str) {
        tamper = tamper.with_new_value(value);
    }
    if let Some(index) = spec.get("flip_byte_at").and_then(Value::as_integer) {
        tamper = tamper.flip_byte_at(usize::try_from(index).unwrap_or(0));
    }
    Ok(tamper)
}

impl Sut for InProcess {
    fn describe(&self) -> String {
        "rustfs-gateway assembled in process from the facade, over a fixture backend".to_owned()
    }

    fn prepare(&mut self, _case_id: &str, setup: Option<&Value>) -> Result<Captures, SutError> {
        let mut captures = Captures::new();
        let mut fixture = Fixture::at(
            time::parse_rfc3339(time::DEFAULT_FIXED)
                .map_err(SutError::Environment)?
                .unix_seconds,
        );
        let Some(setup) = setup else {
            *self.state.lock().map_err(poisoned)? = fixture;
            return Ok(captures);
        };

        for bucket in setup.get("buckets").and_then(Value::as_array).unwrap_or_default() {
            let Some(name) = bucket.get("name").and_then(Value::as_str) else { continue };
            if bucket.get("absent").and_then(Value::as_bool).unwrap_or(false) {
                fixture.remove_bucket(name);
                continue;
            }
            let versioned = bucket.get("versioning").and_then(Value::as_str) == Some("enabled");
            fixture.declare_bucket(name, versioned);
        }

        for object in setup.get("objects").and_then(Value::as_array).unwrap_or_default() {
            let (Some(bucket), Some(key)) =
                (object.get("bucket").and_then(Value::as_str), object.get("key").and_then(Value::as_str))
            else {
                continue;
            };
            if object.get("absent").and_then(Value::as_bool).unwrap_or(false) {
                fixture.remove_object(bucket, key);
                continue;
            }
            let body = match object.get("body") {
                Some(payload) => self.payload(payload)?,
                None => Vec::new(),
            };
            let now = fixture.now;
            let mut stored =
                StoredObject::new(body, object.get("content_type").and_then(Value::as_str).map(ToOwned::to_owned), now);
            if let Some(class) = object.get("storage_class").and_then(Value::as_str) {
                stored.storage_class = class.to_owned();
            }
            if let Some(Value::Table(entries)) = object.get("metadata") {
                stored.metadata = entries
                    .iter()
                    .filter_map(|(name, value)| value.as_str().map(|text| (name.clone(), text.to_owned())))
                    .collect::<BTreeMap<_, _>>();
            }
            fixture.put_object(bucket, key, stored);
        }

        for upload in setup.get("multipart_uploads").and_then(Value::as_array).unwrap_or_default() {
            let (Some(bucket), Some(key)) =
                (upload.get("bucket").and_then(Value::as_str), upload.get("key").and_then(Value::as_str))
            else {
                continue;
            };
            let id = fixture.create_upload(bucket, key);
            if let Some(name) = upload.get("capture_upload_id_as").and_then(Value::as_str) {
                captures.insert(name.to_owned(), id.clone());
            }
            for part in upload.get("parts").and_then(Value::as_array).unwrap_or_default() {
                let Some(number) = part.get("part_number").and_then(Value::as_integer) else { continue };
                let body = match part.get("body") {
                    Some(payload) => self.payload(payload)?,
                    None => Vec::new(),
                };
                let etag = fixture.put_part(&id, i32::try_from(number).unwrap_or(0), body);
                if let Some(name) = part.get("capture_etag_as").and_then(Value::as_str) {
                    // Captured quoted, because that is the form a case interpolates into an XML
                    // `<ETag>` element and into an `If-Match` header alike.
                    captures.insert(name.to_owned(), format!("\"{etag}\""));
                }
            }
        }

        *self.state.lock().map_err(poisoned)? = fixture;
        Ok(captures)
    }

    fn exchange(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        let (fixed, request_time, skew_ms) = clock_of(plan.clock)?;
        if let Ok(mut fixture) = self.state.lock() {
            fixture.now = fixed.unix_seconds;
        }
        let service = self.assemble(fixed.unix_seconds, skew_ms)?;
        let wire = self.read_request(&plan.request)?;
        let (path, query) = split_target(&wire.target);

        let mut headers = wire.headers.clone();
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
            headers.push(("host".to_owned(), HOST.to_owned()));
        }
        if !wire.body.is_empty() && !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
            headers.push(("content-length".to_owned(), wire.body.len().to_string()));
        }

        let headers = match &wire.sign {
            None => headers,
            Some(sign) => sign_request(sign, &wire, path, query, &headers, &request_time, &self.limits)?,
        };

        let request = assemble_request(&wire.method, &wire.target, &headers, wire.body.clone())?;
        let started = std::time::Instant::now();
        let response = block_on(service.call_bytes(request));
        // The head is kept before the body is drained, so that a body which fails halfway can still
        // be reported *as a response that failed halfway* rather than as an environment problem. A
        // drain that consumed the head first would leave the transport with nothing to report but
        // the exception.
        let (parts, payload) = response.into_parts();
        let status = parts.status;
        let head: Vec<(http::HeaderName, http::HeaderValue)> = parts
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let drained = block_on(collect(http::Response::from_parts(parts, payload)));
        let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

        let render = |pairs: Vec<(http::HeaderName, http::HeaderValue)>| -> Vec<(String, String)> {
            pairs
                .into_iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        value
                            .to_str()
                            .map_or_else(|_| String::from_utf8_lossy(value.as_bytes()).into_owned(), ToOwned::to_owned),
                    )
                })
                .collect()
        };

        let (body, trailers, outcome, termination, before_error) = match drained {
            Ok(collected) => {
                let (_, _, body, trailers) = collected.into_parts();
                let body = body.to_vec();
                // The status line and the document can disagree, and when they do the disagreement
                // *is* the observation. Everything else about the exchange is unchanged: the head
                // arrived, the body arrived, and the connection is reusable — what differs is that
                // the request failed and only the body says so.
                match late_error_offset(status.as_u16(), &body) {
                    None => (body, trailers, Outcome::Response, None, None),
                    Some(offset) => (body, trailers, Outcome::StreamError, Some(StreamTermination::ErrorDocument), Some(offset)),
                }
            }
            // A body that could not be read to its end is a stream that stopped, which is a fact
            // about the response and not about this harness — reporting it as an environment error
            // would *skip* the case, and a skipped case asserts nothing. The byte count is left
            // unrecorded rather than guessed: `collect` discards what it had read when it failed, so
            // a case pinning `body_bytes_before_error` stays red here and says why.
            Err(_) => (Vec::new(), Vec::new(), Outcome::StreamError, Some(StreamTermination::AbruptClose), None),
        };

        Ok(Observation {
            outcome,
            stream_termination: termination,
            status: Some(status.as_u16()),
            http_version: None,
            headers: render(head),
            trailers: render(trailers),
            body,
            body_bytes_before_error: before_error,
            request_body_bytes_sent_at_response: Some(wire.body.len() as u64),
            request_body_fully_sent: Some(true),
            ttfb_ms: Some(elapsed_ms),
            elapsed_ms,
            connection_after: Some(ConnectionState::Open),
            events: Vec::new(),
        })
    }
}

fn poisoned<T>(_: T) -> SutError {
    SutError::Environment("the fixture state was left poisoned by an earlier case".to_owned())
}

/// Signs the request the way `sign.mode` asks for, returning the header list to send.
fn sign_request(
    sign: &Value,
    wire: &Wire,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    request_time: &time::Instant,
    limits: &Limits,
) -> Result<Vec<(String, String)>, SutError> {
    let mode = sign.get("mode").and_then(Value::as_str).unwrap_or("sigv4_header");
    match mode {
        "anonymous" | "none" => return Ok(headers.to_vec()),
        "sigv4_header" | "sigv4_unsigned_payload" => {}
        other => {
            return Err(SutError::Environment(format!(
                "`sign.mode = \"{other}\"` is not wired: the in-process target signs the header \
                 form and the unsigned-payload form, and a streaming or presigned mode needs the \
                 chunk framing a socket transport owns"
            )));
        }
    }

    // The host has to reach the canonical request in the byte-exact form the acceptance layer
    // settled on, and `WireRequest` is the only way to obtain one through the facade. The probe
    // carries the host and nothing else on purpose: a probe built from the real head would be
    // refused for exactly the requests a negative case exists to send — a duplicate `Range`, an
    // oversized query — and the case would be skipped instead of measured.
    let host = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map_or(HOST, |(_, value)| value.as_str());
    let probe = assemble_request("GET", "/", &[("host".to_owned(), host.to_owned())], Vec::new())?;
    let accepted = WireRequest::accept(probe, limits)
        .map_err(|error| SutError::Environment(format!("`{host}` is not an acceptable host: {error:?}")))?;

    let mut map = http::HeaderMap::new();
    for (name, value) in headers {
        let name: http::HeaderName = name
            .parse()
            .map_err(|_| SutError::Environment(format!("`{name}` is not a header name")))?;
        let value =
            http::HeaderValue::from_str(value).map_err(|_| SutError::Environment(format!("`{value}` is not a header value")))?;
        map.append(name, value);
    }

    let credential = sign.get("credential").and_then(Value::as_str).unwrap_or("valid");
    let (access_key, secret) = match credential {
        "unknown_access_key" => (UNKNOWN_ACCESS_KEY, VALID_SECRET),
        "wrong_secret" => (VALID_ACCESS_KEY, WRONG_SECRET),
        "expired_session" => (VALID_ACCESS_KEY, VALID_SECRET),
        _ => (VALID_ACCESS_KEY, VALID_SECRET),
    };
    let credentials = SigningCredentials::new(access_key, secret)
        .map_err(|error| SutError::Environment(format!("the signing credentials are not valid: {error}")))?;
    let stamp = AmzDate::parse(&request_time.amz_stamp)
        .map_err(|error| SutError::Environment(format!("`{}` is not a SigV4 stamp: {error}", request_time.amz_stamp)))?;
    let region = sign.get("region").and_then(Value::as_str).unwrap_or(REGION);
    let scope = SigningScope::new(stamp.day(), region, SigService::S3)
        .map_err(|error| SutError::Environment(format!("the credential scope is not well formed: {error}")))?;

    let payload = match (mode, sign.get("payload_hash").and_then(Value::as_str)) {
        ("sigv4_unsigned_payload", _) | (_, Some("unsigned")) => PayloadMode::Unsigned,
        (_, Some("empty")) => PayloadMode::Empty,
        _ if wire.body.is_empty() => PayloadMode::Empty,
        _ => PayloadMode::ExactSha256(crate::sha256::digest(&wire.body)),
    };

    let mut signer = SigV4Signer::new(credentials, scope);
    let method = http::Method::from_bytes(wire.method.as_bytes())
        .map_err(|_| SutError::Environment(format!("`{}` is not a method", wire.method)))?;
    let mut signing = SigningRequest::new(&method, path, query, &map, accepted.host().raw_for_signing(), payload, stamp);
    // Always declared, including for the empty body: the signed-header rules cross-check
    // `content-length` against the length the wire layer settled on, and omitting it makes a
    // request that declares `content-length: 0` unsignable.
    signing = signing.with_wire_content_length(wire.body.len() as u64);
    let signed = signer
        .sign_headers(&signing)
        .map_err(|error| SutError::Environment(format!("the request could not be signed: {error}")))?;
    let signed = match sign.get("tamper") {
        None => signed,
        Some(spec) => signed
            .tampered(&read_tamper(spec)?)
            .map_err(|error| SutError::Environment(format!("the request could not be tampered with: {error}")))?,
    };

    Ok(signed
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap_or_default().to_owned()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_split_into_a_path_and_a_raw_query() {
        assert_eq!(split_target("/b/k?list-type=2&x=1"), ("/b/k", "list-type=2&x=1"));
        assert_eq!(split_target("/b/k"), ("/b/k", ""));
    }

    #[test]
    fn a_generated_payload_is_deterministic_and_honours_a_hex_fill() {
        assert_eq!(generate(4, Some("ff")), vec![0xff, 0xff, 0xff, 0xff]);
        assert_eq!(generate(3, None), vec![0, 1, 2]);
        assert_eq!(generate(3, None), generate(3, None));
    }

    /// Negative — every request shape that needs a socket is refused by name, so the report says
    /// which capability was missing rather than reporting a wrong answer.
    #[test]
    fn a_raw_head_is_refused_rather_than_approximated() {
        let target = InProcess::new(PathBuf::from("."));
        let request = Value::Table(vec![("raw_head_utf8".to_owned(), Value::String("GET / HTTP/1.1".to_owned()))]);
        let error = target.read_request(&request).expect_err("must be refused");
        assert!(format!("{error}").contains("raw_head_utf8"), "{error}");
    }

    /// Negative — a control chunk is refused, because answering it from a complete body would turn
    /// an abnormal-termination case into a false green.
    #[test]
    fn a_control_chunk_is_refused() {
        let target = InProcess::new(PathBuf::from("."));
        let chunks = vec![Value::Table(vec![(
            "action".to_owned(),
            Value::String("half_close".to_owned()),
        )])];
        let error = target.chunks(&chunks).expect_err("must be refused");
        assert!(format!("{error}").contains("half_close"), "{error}");
    }

    #[test]
    fn a_case_without_a_clock_still_runs_at_a_pinned_instant() {
        let (fixed, request_time, skew) = clock_of(None).expect("a default clock");
        assert_eq!(fixed.amz_stamp, "20260102T030405Z");
        assert_eq!(request_time.amz_stamp, fixed.amz_stamp);
        assert_eq!(skew, 0);
    }
}
