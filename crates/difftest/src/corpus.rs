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

//! Recorded requests as decode-diff inputs, with every change made to them said out loud.
//!
//! Responsible for: reading `corpus/` (its bucket files, entry by entry, with a stable id
//! `<file>:<n>` for its n-th entry), and turning one entry into a [`RawRequest`] — or into a skip with its reason —
//! listing each [`Adjustment`] made on the way: the redacted signature removed (the diff compares
//! route and codec; a recording's signature cannot be replayed, rustfs/backlog#1762 decision 2), an
//! unrecorded payload hash removed, the `Content-Length` a partial head capture did not observe
//! synthesised from the recorded body, timing controls ignored. An entry whose body ends
//! abnormally, that claims a signed chunk framing whose signatures were redacted, or that arrived
//! with chunked transfer framing (which only a transport de-frames), is skipped
//! with that reason — never silently dropped and never counted as a pass.
//! NOT responsible for: judging (`runner.rs`), or the corpus format itself
//! (`rustfs-gateway-corpus`).
//! Upstream: `rustfs-gateway-corpus`. Downstream: `runner.rs`.

use std::fmt;
use std::path::Path;

use bytes::Bytes;
use http::Method;
use rustfs_gateway_corpus::schema::{Capture, Chunk, Entry};

use crate::request::RawRequest;

/// One change made to a recorded request before both stacks see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Adjustment {
    /// A redacted `Authorization` header or presigned query was removed: the request is sent
    /// unsigned.
    SignatureRemoved,
    /// A header recorded as `__UNRECORDED__` or `__REDACTED__` was removed.
    PlaceholderHeaderRemoved,
    /// A partial head capture did not observe `Content-Length`; it was set to the recorded body.
    ContentLengthSynthesised,
    /// A `flush` or `stall` timing control was ignored: the diff has no clock.
    TimingIgnored,
}

impl fmt::Display for Adjustment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SignatureRemoved => "redacted signature removed",
            Self::PlaceholderHeaderRemoved => "placeholder header removed",
            Self::ContentLengthSynthesised => "content-length synthesised",
            Self::TimingIgnored => "timing control ignored",
        })
    }
}

/// Why an entry could not be sent.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Skip {
    /// The body ends in an abnormal termination, which a pure decode cannot express.
    AbnormalBody(String),
    /// The body claims a signed chunk framing whose chunk signatures were redacted.
    SignedFramingRedacted,
    /// The body arrived with `Transfer-Encoding: chunked`. The in-process stacks have no transport:
    /// the gateway refuses such a request for its missing length, and replacing the framing with a
    /// length is not what the recorded server saw either.
    TransferFraming,
    /// The method, target, a header or a body chunk is not valid as recorded.
    Malformed(String),
}

impl fmt::Display for Skip {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AbnormalBody(action) => write!(formatter, "abnormal body termination ({action})"),
            Self::SignedFramingRedacted => formatter.write_str("signed chunk framing with its signatures redacted"),
            Self::TransferFraming => formatter.write_str("chunked transfer framing, which only a transport de-frames"),
            Self::Malformed(why) => write!(formatter, "malformed recording: {why}"),
        }
    }
}

/// One corpus entry, read.
#[derive(Clone, Debug)]
pub struct CorpusEntry {
    /// `<bucket file>:<n>` for the n-th entry of that file, stable across runs.
    pub id: String,
    /// The operation the corpus files it under.
    pub operation: String,
    /// The recorder saw only part of the head: a header it did not see can change the route.
    pub partial: bool,
    /// The request, or why it cannot be sent.
    pub request: Result<(RawRequest, Vec<Adjustment>), Skip>,
}

/// The presigned query parameters a redacted recording cannot replay.
pub(crate) const PRESIGN_PARAMETERS: [&str; 7] = [
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Signature",
    "X-Amz-Security-Token",
];

fn is_placeholder(value: &str) -> bool {
    value == "__UNRECORDED__" || value == "__REDACTED__"
}

/// One entry as the request both stacks receive.
///
/// # Errors
///
/// The [`Skip`] that says why this entry cannot be sent.
pub fn request_of(entry: &Entry) -> Result<(RawRequest, Vec<Adjustment>), Skip> {
    let mut adjustments = Vec::new();
    let method = Method::from_bytes(entry.method.as_bytes()).map_err(|error| Skip::Malformed(format!("method: {error}")))?;
    let (path, query) = entry.target.split_once('?').unwrap_or((entry.target.as_str(), ""));
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter(|pair| {
            let name = pair.split_once('=').map_or(*pair, |(name, _)| name);
            // Query parameter names are case-sensitive; only the spelling SigV4 defines is a signature.
            !PRESIGN_PARAMETERS.contains(&name)
        })
        .collect();
    if kept.len() != query.split('&').filter(|pair| !pair.is_empty()).count() {
        adjustments.push(Adjustment::SignatureRemoved);
    }
    let target = if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    };
    let mut request = RawRequest::new(method.clone(), &target);
    for (name, value) in &entry.headers {
        if name.eq_ignore_ascii_case("authorization") {
            adjustments.push(Adjustment::SignatureRemoved);
            continue;
        }
        if is_placeholder(value) {
            adjustments.push(Adjustment::PlaceholderHeaderRemoved);
            continue;
        }
        if name.eq_ignore_ascii_case("x-amz-content-sha256") && value.starts_with("STREAMING-AWS4-") {
            return Err(Skip::SignedFramingRedacted);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked") {
            return Err(Skip::TransferFraming);
        }
        request = request.header(name, value);
    }
    let mut pieces = Vec::new();
    for chunk in entry.chunks.iter().flatten() {
        match chunk {
            Chunk::Data { bytes_b64, .. } => {
                let bytes = rustfs_gateway_corpus::base64::decode(bytes_b64)
                    .map_err(|error| Skip::Malformed(format!("body: {error}")))?;
                pieces.push(Bytes::from(bytes));
            }
            Chunk::Control { action, .. } if matches!(action.as_str(), "flush" | "stall") => {
                adjustments.push(Adjustment::TimingIgnored);
            }
            Chunk::Control { action, .. } => return Err(Skip::AbnormalBody(action.clone())),
        }
    }
    let length: usize = pieces.iter().map(Bytes::len).sum();
    if !pieces.is_empty()
        && let Some((_, declared)) = entry
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        && declared.parse::<usize>().ok() != Some(length)
        && !entry.has_chunk_framing()
    {
        return Err(Skip::Malformed(format!("content-length {declared} but {length} body bytes recorded")));
    }
    request.body = pieces;
    let declared = entry
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding"));
    if entry.capture == Capture::HeadPartial && !declared && matches!(method, Method::PUT | Method::POST) {
        request = request.header("content-length", &length.to_string());
        adjustments.push(Adjustment::ContentLengthSynthesised);
    }
    adjustments.sort_unstable();
    adjustments.dedup();
    Ok((request, adjustments))
}

/// Every entry under `root`, in bucket-file and line order.
///
/// # Errors
///
/// The corpus cannot be enumerated or a bucket file cannot be read or parsed.
pub fn load(root: &Path) -> Result<Vec<CorpusEntry>, String> {
    let files = rustfs_gateway_corpus::store::bucket_files(root).map_err(|error| format!("{}: {error}", root.display()))?;
    let mut entries = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).map_err(|error| format!("{}: {error}", file.display()))?;
        let relative = file.strip_prefix(root).unwrap_or(&file).display().to_string();
        let parsed = rustfs_gateway_corpus::schema::load_jsonl(&text).map_err(|error| format!("{relative}:{error}"))?;
        for (index, entry) in parsed.iter().enumerate() {
            entries.push(CorpusEntry {
                id: format!("{relative}:{}", index + 1),
                operation: entry.op.clone(),
                partial: entry.capture == Capture::HeadPartial,
                request: request_of(entry),
            });
        }
    }
    Ok(entries)
}
