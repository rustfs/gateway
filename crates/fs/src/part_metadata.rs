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

//! Original completed part numbers and verified part checksums in persisted records.
//!
//! Responsible for: the bounded part-meta/1 grammar and consistency with stored lengths/checksums.
//! NOT responsible for: byte windows, multipart completion or HTTP attribute pagination.
//! Upstream: completion and version records. Downstream: future part-attribute projection.

use rustfs_gateway::{ChecksumAlgorithm, ChecksumSpec, ChecksumType, HandlerError};

use super::checksums::StoredChecksum;

#[derive(Clone, Copy, Debug)]
pub(super) struct PartMetadata {
    pub(super) number: u32,
    pub(super) checksum: Option<ChecksumSpec>,
}

fn malformed() -> HandlerError {
    HandlerError::internal_error("the persisted part metadata is missing, malformed or inconsistent")
}

pub(super) fn encode(parts: Option<&[PartMetadata]>) -> String {
    let Some(parts) = parts else { return String::new() };
    let mut section = format!("part-meta/1 {}\n", parts.len());
    for part in parts {
        let (algorithm, value) = part
            .checksum
            .as_ref()
            .map_or(("-", "-"), |checksum| (checksum.algorithm().wire_name(), checksum.render_base64()));
        section.push_str(&format!("{} {algorithm} {value}\n", part.number));
    }
    section
}

pub(super) fn decode(lines: &mut std::str::Lines<'_>, count: &str) -> Result<Vec<PartMetadata>, HandlerError> {
    let count = count
        .parse::<usize>()
        .ok()
        .filter(|count| (1..=10000).contains(count))
        .ok_or_else(malformed)?;
    let mut parts = Vec::with_capacity(count);
    let mut previous = 0;
    for _ in 0..count {
        let mut fields = lines.next().ok_or_else(malformed)?.split(' ');
        let encoded_number = fields.next().ok_or_else(malformed)?;
        let number = encoded_number.parse::<u32>().map_err(|_| malformed())?;
        if number <= previous || number > 10000 || encoded_number != number.to_string() {
            return Err(malformed());
        }
        previous = number;
        let algorithm = fields.next().ok_or_else(malformed)?;
        let value = fields.next().ok_or_else(malformed)?;
        if fields.next().is_some() {
            return Err(malformed());
        }
        let checksum = if algorithm == "-" && value == "-" {
            None
        } else {
            let algorithm = ChecksumAlgorithm::from_wire_name(algorithm).ok_or_else(malformed)?;
            let checksum = ChecksumSpec::parse_header(algorithm.header_name(), value).map_err(|_| malformed())?;
            if checksum.checksum_type() != ChecksumType::FullObject {
                return Err(malformed());
            }
            Some(checksum)
        };
        parts.push(PartMetadata { number, checksum });
    }
    Ok(parts)
}

pub(super) fn validate(
    parts: &[PartMetadata],
    lengths: Option<&[u64]>,
    checksum: Option<StoredChecksum>,
) -> Result<(), HandlerError> {
    if lengths.is_none_or(|lengths| lengths.len() != parts.len()) {
        return Err(malformed());
    }
    let algorithm = checksum.map(|checksum| checksum.value.algorithm());
    if parts
        .iter()
        .any(|part| part.checksum.map(|checksum| checksum.algorithm()) != algorithm)
    {
        return Err(malformed());
    }
    Ok(())
}
