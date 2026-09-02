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

//! Responsible for: turning one corpus entry into a conformance case **draft**, and
//! proving that the chunk timing and termination vocabulary survives the trip.
//! Not responsible for: writing a finished case. A draft carries no rationale and no
//! evidence, so `conformance/case.schema.json` refuses it — deliberately. Supplying those
//! two fields is a human judgement that belongs to whoever adopts the draft.
//! Upstream: `schema::Entry` values that passed `redact::admit`.
//! Downstream: the `corpus` binary's `to-case` subcommand.

use crate::base64;
use crate::schema::{Capture, Chunk, Entry};

/// One chunk in the conformance case schema's spelling.
///
/// The case schema carries payload bytes as `hex` and control chunks as an `action` with
/// optional `delay_ms`/`duration_ms`. Both spellings exist here so the conversion is a
/// real re-encoding rather than a relabelled copy — a round trip that changes nothing
/// proves nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseChunk {
    /// A data chunk: lowercase hex payload plus its arrival delay.
    Data {
        /// Lowercase hexadecimal payload.
        hex: String,
        /// Wall-clock pause before the chunk is written, in milliseconds.
        delay_ms: Option<u64>,
    },
    /// A control chunk from the case schema's action vocabulary.
    Control {
        /// The action name.
        action: String,
        /// Pause before the action, in milliseconds.
        delay_ms: Option<u64>,
        /// Duration of a `stall` or `stop_reading`, in milliseconds.
        duration_ms: Option<u64>,
    },
}

/// Actions the conformance case schema accepts for a control chunk.
pub const CASE_CONTROL_ACTIONS: &[&str] = &[
    "close",
    "flush",
    "half_close",
    "resume_reading",
    "rst",
    "stall",
    "stop_reading",
    "tls_close_without_notify",
];

/// A conformance case draft: everything a corpus entry can supply, and nothing it cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseDraft {
    /// Proposed case id, `c-<domain>-<NNNN>`.
    pub id: String,
    /// Request method.
    pub method: String,
    /// Raw request target.
    pub target: String,
    /// Ordered, duplicate-preserving header pairs.
    pub raw_headers: Vec<(String, String)>,
    /// Body as a timed chunk sequence, when there was one.
    pub chunks: Option<Vec<CaseChunk>>,
    /// Expected status, when the recording observed a response.
    pub status: Option<u16>,
    /// Provenance of the entry this draft came from.
    pub src: String,
}

/// Why an entry cannot become a case draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversionError {
    /// The recording did not observe the whole request head, so the draft would assert a
    /// head nobody measured.
    PartialCapture,
    /// A chunk payload is not decodable base64.
    UndecodablePayload {
        /// Index of the offending chunk.
        index: usize,
        /// The decoder's message.
        message: String,
    },
    /// A control chunk names an action the case schema does not define.
    UnknownAction {
        /// Index of the offending chunk.
        index: usize,
        /// The action that was named.
        action: String,
    },
}

impl std::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PartialCapture => f.write_str(
                "the recording captured only part of the request head; a case built from it would assert a head that was never observed",
            ),
            Self::UndecodablePayload { index, message } => write!(f, "chunk {index}: {message}"),
            Self::UnknownAction { index, action } => {
                write!(f, "chunk {index}: `{action}` is not a conformance control action")
            }
        }
    }
}

impl std::error::Error for ConversionError {}

/// Convert one entry into a case draft.
pub fn to_case(entry: &Entry, id: &str) -> Result<CaseDraft, ConversionError> {
    if entry.capture == Capture::HeadPartial {
        return Err(ConversionError::PartialCapture);
    }
    let chunks = match &entry.chunks {
        None => None,
        Some(chunks) => {
            let mut converted = Vec::with_capacity(chunks.len());
            for (index, chunk) in chunks.iter().enumerate() {
                converted.push(match chunk {
                    Chunk::Data { bytes_b64, delay_ms } => {
                        let bytes = base64::decode(bytes_b64)
                            .map_err(|message| ConversionError::UndecodablePayload { index, message })?;
                        CaseChunk::Data {
                            hex: base64::to_hex(&bytes),
                            delay_ms: *delay_ms,
                        }
                    }
                    Chunk::Control {
                        action,
                        delay_ms,
                        duration_ms,
                    } => {
                        if !CASE_CONTROL_ACTIONS.contains(&action.as_str()) {
                            return Err(ConversionError::UnknownAction {
                                index,
                                action: action.clone(),
                            });
                        }
                        CaseChunk::Control {
                            action: action.clone(),
                            delay_ms: *delay_ms,
                            duration_ms: *duration_ms,
                        }
                    }
                });
            }
            Some(converted)
        }
    };
    Ok(CaseDraft {
        id: id.to_owned(),
        method: entry.method.clone(),
        target: entry.target.clone(),
        raw_headers: entry.headers.clone(),
        chunks,
        status: entry.resp.as_ref().map(|response| response.status),
        src: entry.src.clone(),
    })
}

/// Convert a draft back into the corpus chunk vocabulary.
///
/// This exists for the round-trip assertion, not for production use: it is the half that
/// makes "lossless" a measurement rather than a claim.
pub fn from_case_chunks(chunks: &[CaseChunk]) -> Result<Vec<Chunk>, ConversionError> {
    let mut out = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        out.push(match chunk {
            CaseChunk::Data { hex, delay_ms } => {
                let bytes = base64::from_hex(hex).map_err(|message| ConversionError::UndecodablePayload { index, message })?;
                Chunk::Data {
                    bytes_b64: base64::encode(&bytes),
                    delay_ms: *delay_ms,
                }
            }
            CaseChunk::Control {
                action,
                delay_ms,
                duration_ms,
            } => Chunk::Control {
                action: action.clone(),
                delay_ms: *delay_ms,
                duration_ms: *duration_ms,
            },
        });
    }
    Ok(out)
}

/// Whether the entry survives a conversion to a draft and back with its chunk sequence
/// byte-identical, including every `delay_ms`, `duration_ms` and `action`.
pub fn roundtrips(entry: &Entry) -> Result<bool, ConversionError> {
    let draft = to_case(entry, "c-draft-0000")?;
    let restored = match &draft.chunks {
        None => None,
        Some(chunks) => Some(from_case_chunks(chunks)?),
    };
    Ok(restored == entry.chunks)
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

impl CaseDraft {
    /// Render the draft as a conformance case TOML document.
    ///
    /// `rationale` and `evidence` are left empty on purpose: the runner refuses a case
    /// without them, which is what stops a draft from being merged as if it were a
    /// reviewed case.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# DRAFT generated by `corpus to-case`. Not loadable as a conformance case:\n");
        out.push_str("# `rationale` and `evidence` are empty and the runner refuses a case without them.\n");
        out.push_str(&format!("# Recorded from: {}\n\n", escape(&self.src)));
        out.push_str("[case]\n");
        out.push_str(&format!("id = \"{}\"\n", escape(&self.id)));
        out.push_str("schema_version = 1\n");
        out.push_str("rationale = \"\"\n");
        out.push_str("evidence = []\n");
        out.push_str("quirks = []\n");
        out.push_str("polarity = \"positive\"\n\n");
        out.push_str("[request]\n");
        out.push_str(&format!("method = \"{}\"\n", escape(&self.method)));
        out.push_str(&format!("target = \"{}\"\n", escape(&self.target)));
        out.push_str("raw_headers = [\n");
        for (name, value) in &self.raw_headers {
            out.push_str(&format!("  [\"{}\", \"{}\"],\n", escape(name), escape(value)));
        }
        out.push_str("]\n");
        if let Some(chunks) = &self.chunks {
            for chunk in chunks {
                out.push_str("\n[[request.chunks]]\n");
                match chunk {
                    CaseChunk::Data { hex, delay_ms } => {
                        out.push_str(&format!("hex = \"{hex}\"\n"));
                        if let Some(delay) = delay_ms {
                            out.push_str(&format!("delay_ms = {delay}\n"));
                        }
                    }
                    CaseChunk::Control {
                        action,
                        delay_ms,
                        duration_ms,
                    } => {
                        out.push_str(&format!("action = \"{}\"\n", escape(action)));
                        if let Some(delay) = delay_ms {
                            out.push_str(&format!("delay_ms = {delay}\n"));
                        }
                        if let Some(duration) = duration_ms {
                            out.push_str(&format!("duration_ms = {duration}\n"));
                        }
                    }
                }
            }
        }
        if let Some(status) = self.status {
            out.push_str(&format!("\n[[expect]]\nkind = \"response\"\nstatus = {status}\n"));
        }
        out
    }
}
