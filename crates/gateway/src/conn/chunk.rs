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

//! HTTP/1.1 response chunk-size encoding.
//!
//! Responsible for: formatting the full `u64` protocol length range without allocation.
//! NOT responsible for: choosing response framing or writing payload bytes.
//! Upstream: the response writer's decided chunk length. Downstream: socket progress writes.

use std::io;

pub(super) fn encode_chunk_prefix(length: u64, output: &mut [u8; 18]) -> io::Result<&[u8]> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut value = length;
    let mut cursor: usize = 16;
    loop {
        cursor = cursor
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("chunk size exceeds encoder capacity"))?;
        let digit = HEX
            .get(usize::try_from(value & 0x0f).map_err(io::Error::other)?)
            .copied()
            .ok_or_else(|| io::Error::other("chunk size produced an invalid hexadecimal digit"))?;
        let slot = output
            .get_mut(cursor)
            .ok_or_else(|| io::Error::other("chunk prefix cursor exceeds encoder capacity"))?;
        *slot = digit;
        value >>= 4;
        if value == 0 {
            break;
        }
    }
    let suffix = output
        .get_mut(16..)
        .ok_or_else(|| io::Error::other("chunk prefix suffix exceeds encoder capacity"))?;
    if suffix.len() != 2 {
        return Err(io::Error::other("chunk prefix suffix has an impossible length"));
    }
    suffix.copy_from_slice(b"\r\n");
    output
        .get(cursor..)
        .ok_or_else(|| io::Error::other("chunk prefix result exceeds encoder capacity"))
}
