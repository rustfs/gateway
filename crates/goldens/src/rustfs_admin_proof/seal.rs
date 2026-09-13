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

//! The proof's keyed stand-in for the madmin body seal (rustfs/backlog#1744).
//!
//! Responsible for: sealing and opening an admin body under a caller's secret, and a comparison
//! that reads every byte of a tag.
//! NOT responsible for: the madmin format — the claim under test is who holds the key, not the
//! cipher — or anything outside the proof.
//! Upstream: `sha2`. Downstream: the parent proof module and its tests.

use sha2::{Digest, Sha256};
const TAG_LENGTH: usize = 32;

fn keystream(secret: &[u8], length: usize) -> Vec<u8> {
    let mut stream = Vec::with_capacity(length + TAG_LENGTH);
    let mut counter = 0_u64;
    while stream.len() < length {
        let mut block = Sha256::new();
        block.update(b"rustfs-admin-proof keystream");
        block.update(secret);
        block.update(counter.to_be_bytes());
        stream.extend_from_slice(&block.finalize());
        counter += 1;
    }
    stream.truncate(length);
    stream
}

fn tag(secret: &[u8], plain: &[u8]) -> [u8; TAG_LENGTH] {
    let mut tag = Sha256::new();
    tag.update(b"rustfs-admin-proof tag");
    tag.update(secret);
    tag.update(plain);
    tag.finalize().into()
}

/// Seals `plain` under `secret`, the way a madmin client seals an admin body (a stand-in cipher).
pub(crate) fn seal(secret: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut sealed = tag(secret, plain).to_vec();
    sealed.extend(plain.iter().zip(keystream(secret, plain.len())).map(|(byte, key)| byte ^ key));
    sealed
}

/// Opens a body sealed under `secret`, or `None` when it was sealed under another key.
pub(crate) fn open(secret: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let (expected, cipher) = sealed.split_at_checked(TAG_LENGTH)?;
    let plain = cipher
        .iter()
        .zip(keystream(secret, cipher.len()))
        .map(|(byte, key)| byte ^ key)
        .collect::<Vec<_>>();
    same_bytes(&tag(secret, &plain), expected).then_some(plain)
}

/// A comparison that reads every byte, for key material and tags.
pub(crate) fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).fold(0_u8, |acc, (a, b)| acc | (a ^ b)) == 0
}
