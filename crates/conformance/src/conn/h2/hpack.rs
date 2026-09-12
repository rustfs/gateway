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

//! An HPACK decoder for the header blocks a peer sends back.
//! Responsible for: turning one response header block into its ordered `(name, value)` fields,
//! keeping the connection's dynamic table in step with the peer's encoder (RFC 7541 sections 2–6).
//! NOT responsible for: encoding — the request header block is octets the case authored, and no
//! code here produces one — or frame boundaries (`super`), or Huffman codes (`super::huffman`).
//! Upstream: `super::read_response`. Downstream: `super::huffman`.

use std::collections::VecDeque;

use super::huffman;

/// RFC 7541 Appendix A, indices 1..=61.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// What RFC 7541 section 4.1 charges an entry beyond its octets.
const ENTRY_OVERHEAD: usize = 32;

/// An integer no header block from a sane peer needs; bounds the continuation loop.
const LARGEST_INTEGER: usize = 1 << 28;

/// One connection's decoding state.
#[derive(Debug)]
pub(super) struct Decoder {
    /// Newest entry first, so index 62 is `dynamic[0]`.
    dynamic: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    capacity: usize,
    /// The ceiling a size update may raise the capacity to: what this client advertised.
    limit: usize,
}

impl Decoder {
    /// A decoder whose dynamic table may grow to `limit` octets.
    pub(super) fn new(limit: usize) -> Decoder {
        Decoder {
            dynamic: VecDeque::new(),
            size: 0,
            capacity: limit,
            limit,
        }
    }

    /// Decodes one complete header block.
    ///
    /// # Errors
    ///
    /// Returns a description of the first representation that cannot be decoded: an index outside
    /// both tables, a truncated integer or string, a malformed Huffman string, or a table size
    /// update that exceeds the advertised limit or follows a field.
    pub(super) fn decode(&mut self, block: &[u8]) -> Result<Vec<(String, String)>, String> {
        let mut input = Input { bytes: block, at: 0 };
        let mut fields = Vec::new();
        while let Some(first) = input.peek() {
            if first & 0x80 != 0 {
                let index = input.integer(7)?;
                let (name, value) = self.entry(index)?;
                fields.push((name, value));
            } else if first & 0xc0 == 0x40 {
                let (name, value) = self.literal(&mut input, 6)?;
                self.insert(name.clone(), value.clone());
                fields.push((name, value));
            } else if first & 0xe0 == 0x20 {
                if !fields.is_empty() {
                    return Err("a dynamic table size update follows a header field".to_owned());
                }
                let capacity = input.integer(5)?;
                if capacity > self.limit {
                    return Err(format!("a dynamic table size update to {capacity} exceeds the advertised {}", self.limit));
                }
                self.capacity = capacity;
                self.evict(0);
            } else {
                // Literal without indexing (0000) and never indexed (0001): both leave the table alone.
                let (name, value) = self.literal(&mut input, 4)?;
                fields.push((name, value));
            }
        }
        Ok(fields
            .into_iter()
            .map(|(name, value)| (String::from_utf8_lossy(&name).into_owned(), String::from_utf8_lossy(&value).into_owned()))
            .collect())
    }

    fn literal(&self, input: &mut Input<'_>, prefix: u32) -> Result<(Vec<u8>, Vec<u8>), String> {
        let index = input.integer(prefix)?;
        let name = if index == 0 { input.string()? } else { self.entry(index)?.0 };
        let value = input.string()?;
        Ok((name, value))
    }

    fn entry(&self, index: usize) -> Result<(Vec<u8>, Vec<u8>), String> {
        if index == 0 {
            return Err("a header field refers to index 0".to_owned());
        }
        if let Some((name, value)) = STATIC.get(index - 1) {
            return Ok((name.as_bytes().to_vec(), value.as_bytes().to_vec()));
        }
        self.dynamic
            .get(index - STATIC.len() - 1)
            .cloned()
            .ok_or_else(|| format!("a header field refers to index {index}, beyond both tables"))
    }

    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let size = name.len() + value.len() + ENTRY_OVERHEAD;
        self.evict(size);
        // An entry larger than the whole table empties it and is not added (section 4.4).
        if size <= self.capacity {
            self.size += size;
            self.dynamic.push_front((name, value));
        }
    }

    /// Evicts oldest entries until `incoming` more octets fit.
    fn evict(&mut self, incoming: usize) {
        while self.size + incoming > self.capacity {
            let Some((name, value)) = self.dynamic.pop_back() else {
                self.size = 0;
                return;
            };
            self.size -= name.len() + value.len() + ENTRY_OVERHEAD;
        }
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Input<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn next(&mut self) -> Result<u8, String> {
        let byte = self
            .peek()
            .ok_or_else(|| "a header block ends inside a representation".to_owned())?;
        self.at += 1;
        Ok(byte)
    }

    /// An integer with an `prefix`-bit prefix (RFC 7541 section 5.1).
    fn integer(&mut self, prefix: u32) -> Result<usize, String> {
        let mask = (1_usize << prefix) - 1;
        let mut value = usize::from(self.next()?) & mask;
        if value < mask {
            return Ok(value);
        }
        let mut shift = 0_u32;
        loop {
            let byte = self.next()?;
            value += usize::from(byte & 0x7f) << shift;
            if value > LARGEST_INTEGER {
                return Err("a header block integer exceeds any size this reader accepts".to_owned());
            }
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    /// A string literal, Huffman-decoded when its H bit says so (RFC 7541 section 5.2).
    fn string(&mut self) -> Result<Vec<u8>, String> {
        let huffman = self.peek().is_some_and(|byte| byte & 0x80 != 0);
        let length = self.integer(7)?;
        let end = self
            .at
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "a header block ends inside a string literal".to_owned())?;
        let raw = self.bytes.get(self.at..end).unwrap_or_default();
        self.at = end;
        if huffman { huffman::decode(raw) } else { Ok(raw.to_vec()) }
    }
}
