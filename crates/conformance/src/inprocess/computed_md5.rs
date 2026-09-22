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

//! Responsible for: deriving a requested Content-MD5 from the resolved request payload.
//! NOT responsible for: payload interpolation, signing, or raw frame rewriting.
//! Upstream: shared wire preparation. Downstream: headers passed to every transport signer.

use super::Wire;
use crate::sut::SutError;
use crate::value::Value;

pub(super) fn prepare(request: &Value, mut wire: Wire) -> Result<Wire, SutError> {
    let Some(mode) = request.read("requestSpec.content_md5") else { return Ok(wire) };
    if mode.as_str() != Some("computed") {
        return Err(SutError::Environment("content_md5 must be computed".to_owned()));
    }
    let raw_chunks = matches!(request.get("chunks"), Some(Value::Array(chunks)) if chunks.iter().any(|chunk| {
        chunk.get("raw_utf8").is_some() || chunk.get("raw_hex").is_some()
    }));
    if wire.raw_head.is_some() || request.get("h2_frames").is_some() || raw_chunks {
        return Err(SutError::Environment("content_md5 cannot be combined with raw framing".to_owned()));
    }
    if wire.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-md5")) {
        return Err(SutError::Environment(
            "content_md5 conflicts with an explicit Content-MD5 header".to_owned(),
        ));
    }
    wire.headers
        .push(("content-md5".to_owned(), crate::fixture::encode_base64(&crate::md5::digest(&wire.body))));
    Ok(wire)
}

#[cfg(test)]
#[path = "computed_md5_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "computed_md5_transport_tests.rs"]
mod transport_tests;
