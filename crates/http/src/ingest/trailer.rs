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

//! The bounded trailer section after an `aws-chunked` terminal chunk.
//!
//! Responsible for: parsing strict CRLF-delimited fields, enforcing the trailer name/count/size
//! allowlist, and requiring the received field set to equal the declaration from the request
//! head. NOT responsible for: digest or trailer-signature comparison.
//! Upstream: the request-head declaration and the ingest decoder cursor. Downstream: the ingest
//! pipeline, which can emit these fields only with EOF.

use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};
use rustfs_gateway_stream::TrailingHeaders;
use rustfs_gateway_types::ChecksumAlgorithm;
use smallvec::SmallVec;

use crate::ingest::ChunkReject;

/// The largest complete trailer section, including its final CRLF.
pub const MAX_TRAILER_SECTION_BYTES: usize = 1024;

const MAX_TRAILER_FIELDS: usize = 2;
const TRAILER_SIGNATURE: &str = "x-amz-trailer-signature";

/// The trailer names declared in the authenticated request head.
#[derive(Clone, Debug)]
pub struct TrailerDeclaration {
    names: SmallVec<[HeaderName; 2]>,
    signed: bool,
}

impl TrailerDeclaration {
    /// Parses `x-amz-trailer` before a body byte is read.
    ///
    /// Signed trailer framing adds `x-amz-trailer-signature` implicitly on the wire; clients do
    /// not list that protocol field in `x-amz-trailer`.
    ///
    /// # Errors
    ///
    /// [`ChunkReject::MalformedTrailer`] for an empty or malformed list,
    /// [`ChunkReject::TrailerNotAllowed`] for a non-checksum name, and
    /// [`ChunkReject::TrailerCountExceeded`] when the declaration cannot fit the two-field wire
    /// ceiling after the implicit signature is included.
    pub fn parse(value: &HeaderValue, signed: bool) -> Result<Self, ChunkReject> {
        let value = value.to_str().map_err(|_| ChunkReject::MalformedTrailer)?;
        let mut names = SmallVec::new();
        for raw in value.split(',') {
            let raw = raw.trim_matches([' ', '\t']);
            if raw.is_empty() {
                return Err(ChunkReject::MalformedTrailer);
            }
            let name = HeaderName::from_bytes(raw.as_bytes()).map_err(|_| ChunkReject::MalformedTrailer)?;
            if !is_checksum(&name) {
                return Err(ChunkReject::TrailerNotAllowed);
            }
            if names.contains(&name) {
                return Err(ChunkReject::DeclaredTrailerMismatch);
            }
            names.push(name);
        }
        if names.is_empty() {
            return Err(ChunkReject::MalformedTrailer);
        }
        let actual_count = names.len().saturating_add(usize::from(signed));
        if actual_count > MAX_TRAILER_FIELDS {
            return Err(ChunkReject::TrailerCountExceeded);
        }
        Ok(Self { names, signed })
    }

    pub(crate) fn signed(&self) -> bool {
        self.signed
    }

    fn validate_fields(&self, fields: &HeaderMap) -> Result<(), ChunkReject> {
        if self.signed && !fields.contains_key(TRAILER_SIGNATURE) {
            return Err(ChunkReject::TrailerSignatureMissing);
        }
        let expected = self.names.len().saturating_add(usize::from(self.signed));
        if fields.len() == expected
            && self.names.iter().all(|name| fields.contains_key(name))
            && (!self.signed || fields.contains_key(TRAILER_SIGNATURE))
        {
            Ok(())
        } else {
            Err(ChunkReject::DeclaredTrailerMismatch)
        }
    }
}

/// A partial or complete parse of the bytes after the terminal chunk line.
pub(crate) enum TrailerProgress {
    NeedMore,
    Complete { trailers: TrailingHeaders, consumed: usize },
}

/// Parses one complete trailer section without retaining a second buffer.
pub(crate) fn parse_trailer_section(input: &[u8], declaration: &TrailerDeclaration) -> Result<TrailerProgress, ChunkReject> {
    let mut cursor = 0usize;
    let mut fields = HeaderMap::new();

    loop {
        let rest = input.get(cursor..).ok_or(ChunkReject::MalformedTrailer)?;
        let Some((line_len, consumed)) = find_line(rest)? else {
            if input.len() >= MAX_TRAILER_SECTION_BYTES {
                return Err(ChunkReject::TrailerSizeExceeded);
            }
            return Ok(TrailerProgress::NeedMore);
        };
        cursor = cursor.saturating_add(consumed);
        if cursor > MAX_TRAILER_SECTION_BYTES {
            return Err(ChunkReject::TrailerSizeExceeded);
        }
        if line_len == 0 {
            declaration.validate_fields(&fields)?;
            return Ok(TrailerProgress::Complete {
                trailers: TrailingHeaders::from_header_map(fields),
                consumed: cursor,
            });
        }

        let line = rest.get(..line_len).ok_or(ChunkReject::MalformedTrailer)?;
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(ChunkReject::MalformedTrailer);
        };
        let name = HeaderName::from_bytes(line.get(..colon).ok_or(ChunkReject::MalformedTrailer)?)
            .map_err(|_| ChunkReject::MalformedTrailer)?;
        if !is_allowed(&name) {
            return Err(ChunkReject::TrailerNotAllowed);
        }
        if fields.contains_key(&name) {
            return Err(ChunkReject::DeclaredTrailerMismatch);
        }
        if fields.len() >= MAX_TRAILER_FIELDS {
            return Err(ChunkReject::TrailerCountExceeded);
        }
        let value = line
            .get(colon.saturating_add(1)..)
            .map(trim_ows)
            .ok_or(ChunkReject::MalformedTrailer)
            .and_then(|value| HeaderValue::from_bytes(value).map_err(|_| ChunkReject::MalformedTrailer))?;
        fields.insert(name, value);
    }
}

fn find_line(rest: &[u8]) -> Result<Option<(usize, usize)>, ChunkReject> {
    let searchable = rest.get(..rest.len().min(MAX_TRAILER_SECTION_BYTES)).unwrap_or(rest);
    match searchable.iter().position(|byte| matches!(byte, b'\r' | b'\n')) {
        Some(at) if searchable.get(at) == Some(&b'\n') => Err(ChunkReject::BadLineTerminator),
        Some(at) => match rest.get(at.saturating_add(1)) {
            Some(b'\n') => Ok(Some((at, at.saturating_add(2)))),
            Some(_) => Err(ChunkReject::BadLineTerminator),
            None => Ok(None),
        },
        None => Ok(None),
    }
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while let Some(rest) = value.strip_prefix(b" ").or_else(|| value.strip_prefix(b"\t")) {
        value = rest;
    }
    while let Some(rest) = value.strip_suffix(b" ").or_else(|| value.strip_suffix(b"\t")) {
        value = rest;
    }
    value
}

fn is_checksum(name: &HeaderName) -> bool {
    ChecksumAlgorithm::from_header_name(name.as_str()).is_some()
}

fn is_allowed(name: &HeaderName) -> bool {
    is_checksum(name) || name == TRAILER_SIGNATURE
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_declaration_without_its_final_hmac_has_a_distinct_refusal() {
        let declaration = TrailerDeclaration::parse(&HeaderValue::from_static("x-amz-checksum-crc32"), true)
            .expect("one checksum plus its implicit signature");
        let result = parse_trailer_section(b"x-amz-checksum-crc32:AAAAAA==\r\n\r\n", &declaration);

        assert!(matches!(result, Err(ChunkReject::TrailerSignatureMissing)));
    }
}
