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

//! Responsible for: the versioned corpus entry shape, its JSONL codec, and the
//! explicit refusal of a schema version this build does not know.
//! Not responsible for: deciding whether an entry is safe to store (`redact`), how many
//! copies of it to keep (`dedup`), or how it becomes a conformance case (`case`).
//! Upstream: JSONL written by the recorder layer in the RustFS main repository, or by an
//! adapter over an external suite's capture.
//! Downstream: `redact`, `dedup`, `store`, `case`, and the `corpus` binary.

use serde::{Deserialize, Serialize};

/// The corpus schema version this build reads and writes.
///
/// A file declaring a higher version is refused with an explicit "update the tooling"
/// error rather than loaded with its unknown fields ignored: silently dropping a field
/// this build does not understand is how a corpus stops meaning what it says.
pub const CORPUS_SCHEMA_VERSION: u32 = 1;

/// How much of the original request the recording actually observed.
///
/// The distinction is load-bearing rather than cosmetic. A capture that saw the whole
/// request head can be replayed; one that saw a named subset of headers cannot, and a
/// partial capture rendered as if it were complete is a measurement claim nobody made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capture {
    /// Every request header, in the order sent, reached the recorder.
    HeadFull,
    /// Only the headers named in `headers` were observed. Absence proves nothing.
    HeadPartial,
}

/// The wire form of a chunk: every field optional, unknown fields refused.
///
/// [`Chunk`] is the shape the rest of the crate works with; this is the shape on disk.
/// Deserializing through it is what makes an unknown chunk key an error, which an
/// untagged enum cannot express.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChunk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bytes_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delay_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
}

/// What the client was actually talking to when the entry was recorded.
///
/// A closed vocabulary, and the deserializer is what closes it: an unrecognised spelling is
/// a load error rather than a value nobody checked. It is a separate axis from `src`, which
/// says which suite drove the traffic, because the same suite pointed at two different
/// endpoints produces two different things — and rustfs/gateway#624 measured that this
/// repository has no runnable production server binary at all, so "a real client spoke S3"
/// and "a real client spoke to the production server" are not the same claim and must not
/// be readable as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sut {
    /// The `rustfs-gateway-fs` reference backend behind a real listener: real sockets, real
    /// SigV4, real wire bytes — and none of the production storage stack behind it.
    GatewayFsReference,
    /// The production RustFS server. No entry carries this yet; rustfs/gateway#624 records
    /// that no such binary exists to point a client at.
    RustfsServer,
    /// No server was involved: the entry was hand-authored as input bytes.
    None,
}

/// One unit of request body, aligned field for field with the conformance case schema's
/// `[[request.chunks]]` entry so that conversion loses nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawChunk", into = "RawChunk")]
pub enum Chunk {
    /// Body bytes, base64-encoded, with the wall-clock pause that preceded them.
    Data {
        /// Standard-alphabet base64 of the logical payload for this chunk.
        bytes_b64: String,
        /// Pause before the chunk was written, in milliseconds.
        delay_ms: Option<u64>,
    },
    /// An abnormal or deliberate termination of the request body.
    Control {
        /// The control action, using the conformance case schema's vocabulary.
        action: String,
        /// Pause before the action, in milliseconds.
        delay_ms: Option<u64>,
        /// Duration of a `stall` or `stop_reading`, in milliseconds.
        duration_ms: Option<u64>,
    },
}

impl TryFrom<RawChunk> for Chunk {
    type Error = String;

    fn try_from(raw: RawChunk) -> Result<Self, Self::Error> {
        match (raw.bytes_b64, raw.action) {
            (Some(_), Some(_)) => Err("a chunk carries both `bytes_b64` and `action`".to_owned()),
            (None, None) => Err("a chunk carries neither `bytes_b64` nor `action`".to_owned()),
            (Some(bytes_b64), None) => {
                if raw.duration_ms.is_some() {
                    return Err("`duration_ms` belongs to a control chunk, not a data chunk".to_owned());
                }
                Ok(Self::Data {
                    bytes_b64,
                    delay_ms: raw.delay_ms,
                })
            }
            (None, Some(action)) => Ok(Self::Control {
                action,
                delay_ms: raw.delay_ms,
                duration_ms: raw.duration_ms,
            }),
        }
    }
}

impl From<Chunk> for RawChunk {
    fn from(chunk: Chunk) -> Self {
        match chunk {
            Chunk::Data { bytes_b64, delay_ms } => Self {
                bytes_b64: Some(bytes_b64),
                action: None,
                delay_ms,
                duration_ms: None,
            },
            Chunk::Control {
                action,
                delay_ms,
                duration_ms,
            } => Self {
                bytes_b64: None,
                action: Some(action),
                delay_ms,
                duration_ms,
            },
        }
    }
}

/// The recorded response, when the recorder saw one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response headers, lowercased names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    /// Response body, base64-encoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_b64: Option<String>,
}

/// One recorded request, plus whatever of its response was observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Schema version. Always [`CORPUS_SCHEMA_VERSION`] on write.
    pub v: u32,
    /// AWS operation name, used as the bucket key.
    pub op: String,
    /// Provenance: which test suite produced this entry, at which pinned revision.
    /// Checked against a closed allowlist; production traffic has no spelling here.
    pub src: String,
    /// Recording date, `YYYY-MM-DD`.
    pub recorded: String,
    /// How much of the request head the recorder saw.
    pub capture: Capture,
    /// What the client was talking to. See [`Sut`]: this is not implied by `src`.
    pub sut: Sut,
    /// Request method, verbatim.
    pub method: String,
    /// Raw request target, verbatim, including the query string.
    pub target: String,
    /// Observed request headers as ordered, duplicate-preserving pairs. Names are
    /// lowercased; the order is the order recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    /// Body as a timed sequence. Absent when no body was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunks: Option<Vec<Chunk>>,
    /// The recorded response, when there was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp: Option<Response>,
    /// Field names a sanitizing pass rewrote. Redaction must be visible: an entry that
    /// was altered and does not say so is indistinguishable from one that was not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted: Vec<String>,
}

impl Entry {
    /// Every request header value whose name matches `name`, case-insensitively.
    pub fn header_values<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> {
        let lowered = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(&lowered))
            .map(|(_, value)| value.as_str())
    }

    /// The query string of `target`, without the leading `?`.
    pub fn query(&self) -> &str {
        match self.target.split_once('?') {
            Some((_, query)) => query,
            None => "",
        }
    }

    /// The path component of `target`.
    pub fn path(&self) -> &str {
        match self.target.split_once('?') {
            Some((path, _)) => path,
            None => self.target.as_str(),
        }
    }

    /// Whether the request carries aws-chunked framing: a streaming payload mode, a
    /// declared trailer, or the `aws-chunked` content coding.
    ///
    /// This is the field the corpus exists to make visible. Client diversity does not
    /// imply signing diversity, and only a per-entry answer distinguishes the two.
    pub fn has_chunk_framing(&self) -> bool {
        self.header_values("x-amz-content-sha256")
            .any(|value| value.starts_with("STREAMING-"))
            || self.header_values("x-amz-trailer").next().is_some()
            || self
                .header_values("content-encoding")
                .any(|value| value.to_ascii_lowercase().contains("aws-chunked"))
    }

    /// Whether the request declares a trailing-header set.
    pub fn has_trailer(&self) -> bool {
        self.header_values("x-amz-trailer").next().is_some()
    }
}

/// Why a JSONL line could not become an [`Entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The line declares a schema version this build does not know.
    UnsupportedVersion {
        /// 1-based line number within the source file.
        line: usize,
        /// The version the line declared.
        found: u32,
        /// The highest version this build understands.
        supported: u32,
    },
    /// The line is not valid JSON, or not a valid entry of a known version.
    Malformed {
        /// 1-based line number within the source file.
        line: usize,
        /// The decoder's own message.
        message: String,
    },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { line, found, supported } => write!(
                f,
                "line {line}: corpus schema v{found} is newer than v{supported}; update the tooling \
                 (this build will not load it by ignoring unknown fields)"
            ),
            Self::Malformed { line, message } => write!(f, "line {line}: {message}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Parse a JSONL document into entries, refusing an unknown schema version outright.
///
/// Blank lines are skipped so that a hand-edited file stays loadable; every other line
/// must be a complete entry. Line numbers in errors are 1-based over the original text.
pub fn load_jsonl(text: &str) -> Result<Vec<Entry>, LoadError> {
    let mut entries = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        if raw.trim().is_empty() {
            continue;
        }
        // The version is read before the entry so that a v2 file fails with "update the
        // tooling" rather than with whichever field v2 happened to add.
        let probe: serde_json::Value = serde_json::from_str(raw).map_err(|error| LoadError::Malformed {
            line,
            message: error.to_string(),
        })?;
        let version = probe
            .get("v")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| LoadError::Malformed {
                line,
                message: "entry has no numeric `v` schema version".to_owned(),
            })?;
        if version > u64::from(CORPUS_SCHEMA_VERSION) {
            return Err(LoadError::UnsupportedVersion {
                line,
                found: u32::try_from(version).unwrap_or(u32::MAX),
                supported: CORPUS_SCHEMA_VERSION,
            });
        }
        let entry: Entry = serde_json::from_str(raw).map_err(|error| LoadError::Malformed {
            line,
            message: error.to_string(),
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Render entries as JSONL, one compact object per line, newline-terminated.
pub fn render_jsonl(entries: &[Entry]) -> String {
    let mut out = String::new();
    for entry in entries {
        match serde_json::to_string(entry) {
            Ok(line) => {
                out.push_str(&line);
                out.push('\n');
            }
            // `Entry` contains only strings, integers and vectors of them, so this arm is
            // unreachable in practice; it is written out rather than unwrapped because a
            // serializer failure must not abort a corpus write.
            Err(_) => continue,
        }
    }
    out
}
