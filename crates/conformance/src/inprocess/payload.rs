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

//! Responsible for: deterministic payload generation and hexadecimal decoding for authored bytes.
//! NOT responsible for: request parsing, signing, or transport execution.
//! Upstream: the in-process request and HTTP/2 frame readers; downstream: byte buffers.

/// Generates `size` bytes.
///
/// `fill` is read as hex when it is valid hex, because the corpus writes `fill = "ff"` meaning one
/// byte and not two. With no `fill` the pattern is `index % 251`, which is deterministic, has no
/// period that lines up with a power-of-two block size, and is therefore a payload whose corruption
/// a digest actually notices.
pub(super) fn generate(size: usize, fill: Option<&str>) -> Vec<u8> {
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

pub(super) fn decode_hex(text: &str) -> Option<Vec<u8>> {
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
