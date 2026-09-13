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

//! Filesystem-backed browser `POST` Object uploads.
//!
//! Responsible for: storing the file part of an accepted browser form, with its media type and
//! `x-amz-meta-*` fields, through the same publication `PutObject` uses, and reporting the stored
//! entity tag and version for the framework's success action.
//! NOT responsible for: the multipart form grammar, POST-policy signature and condition checks,
//! the `success_action_*` response, or the policy's content-length range — all of those are the
//! gateway's form pipeline, which hands this handler a live, policy-bounded stream.
//! Upstream: the authenticated gateway form pipeline. Downstream: the CRUD registry.

use std::collections::BTreeMap;

use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp};

use super::content_headers::ContentHeaders;
use super::records::ObjectAttributes;
use super::{FsBackend, drain, etag};

/// Collects the form's metadata fields, refusing a field the form repeats.
///
/// A repeated field is refused rather than resolved by first- or last-write-wins: the form carried
/// two values for one stored key, and choosing one of them is a decision the uploader did not make.
///
/// Today the gateway's form pipeline already refuses a repeated field before this handler runs,
/// so over the wire this refusal is defense in depth. It stays because the input type is a list,
/// not a map: nothing in the handler contract promises uniqueness, and a silent merge here would
/// be the first thing to break if the pipeline ever relaxed that rule.
fn form_metadata(fields: Vec<(String, String)>) -> Result<BTreeMap<String, String>, HandlerError> {
    let mut metadata = BTreeMap::new();
    for (key, value) in fields {
        if metadata.insert(key, value).is_some() {
            return Err(HandlerError::new(ErrorCode::INVALID_ARGUMENT, "the form repeats an x-amz-meta-* field"));
        }
    }
    Ok(metadata)
}

impl Handler<PostObject> for FsBackend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let input = request.into_input();
        // Drained first: a refusal returned with the file unread would be reported as an abandoned
        // body rather than as itself. Nothing is published until every refusal has had its turn.
        let bytes = drain(Some(input.body)).await?;
        let attributes = ObjectAttributes {
            metadata: form_metadata(input.metadata)?,
            headers: ContentHeaders::from_request(None, None, None, None, input.content_type, None),
            ..ObjectAttributes::default()
        };
        let e_tag = etag(&bytes)?;
        let published = self
            .publish_object(input.bucket.as_str(), input.key.as_str(), &bytes, &e_tag, &attributes)
            .await?;
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(e_tag),
            version_id: published.version_id,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(key: &str, value: &str) -> (String, String) {
        (key.to_owned(), value.to_owned())
    }

    /// Negative — a repeated field is refused rather than resolved by picking one value.
    #[test]
    fn a_repeated_form_field_is_refused() {
        let error =
            form_metadata(vec![field("origin", "first"), field("origin", "second")]).expect_err("a repeated field is refused");
        assert_eq!(error.code(), &ErrorCode::INVALID_ARGUMENT);
        assert_eq!(error.message(), "the form repeats an x-amz-meta-* field");
    }

    /// Positive — distinct fields are all kept.
    #[test]
    fn distinct_form_fields_are_kept() {
        let metadata = form_metadata(vec![field("origin", "browser"), field("owner", "ops")]).expect("distinct fields");
        assert_eq!(metadata.len(), 2);
        assert_eq!(metadata.get("origin").map(String::as_str), Some("browser"));
    }
}
