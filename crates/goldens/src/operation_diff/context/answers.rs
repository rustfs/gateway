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

//! What each stack answers on the wire, refusals included, for the named divergences that are
//! about the response rather than the handler context (rd-loc).
//!
//! Responsible for: sending one signed request through both stacks, as the parent harness
//! assembles them, and returning each status and body with the `<Code>` and `<Message>` readable.
//! NOT responsible for: the context comparison (the parent), or any assertion.
//! Upstream: `super` (request, gateway assembly, s3s service). Downstream: the rd-loc pins in
//! `super::get_bucket_location`.

use std::sync::{Arc, Mutex};

use rustfs_gateway_sig::RequestNow;

use super::{ContextRequest, block_on, gateway_service, s3s_answer};

/// What one stack answered, whether or not its handler ran.
#[derive(Debug)]
pub(crate) struct StackAnswer {
    pub(crate) status: u16,
    pub(crate) body: String,
}

impl StackAnswer {
    /// The `<Code>` of an error body.
    pub(crate) fn code(&self) -> Option<&str> {
        element(&self.body, "Code")
    }

    /// The `<Message>` of an error body.
    pub(crate) fn message(&self) -> Option<&str> {
        element(&self.body, "Message")
    }
}

fn element<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body.get(start..)?.find(&format!("</{name}>"))? + start;
    body.get(start..end)
}

/// Signs `request` once and returns what `(gateway, s3s)` answered, refusals included.
///
/// # Errors
///
/// A harness failure; a refusal is a [`StackAnswer`].
pub(crate) fn answers(request: &ContextRequest) -> Result<(StackAnswer, StackAnswer), String> {
    let headers = request.wire_headers(RequestNow::capture())?;
    let recorded = Arc::new(Mutex::new(None));
    let service = gateway_service(request, &recorded)?;
    let http_request = request
        .http_head(&headers)
        .body(request.body.clone())
        .map_err(|error| format!("fixture head: {error}"))?;
    let response = block_on(service.call_bytes(http_request));
    let status = response.status().as_u16();
    let body = block_on(http_body_util::BodyExt::collect(response.into_body()))
        .map_err(|error| format!("gateway body: {error:?}"))?
        .to_bytes();
    let gateway = StackAnswer {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    let (status, body, _) = s3s_answer(request, &headers)?;
    let oracle = StackAnswer {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    Ok((gateway, oracle))
}
