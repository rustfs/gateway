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

//! Browser `POST` Object uploads for the conformance fixture.
//!
//! Responsible for: storing an authorized POST Object's file under its resolved key, with its
//! content type and user metadata, the way `PutObject` stores a body, and reporting the stored
//! entity tag and version for the framework's success action.
//! NOT responsible for: the form grammar, the POST policy, or the success action — the gateway's
//! form pipeline decides all three before this handler is reached.
//! Upstream: `super::Stub` and the gateway's POST Object bridge. Downstream: the fixture state.

use super::*;

impl Handler<dto::PostObject> for Stub {
    fn call(&self, request: Req<dto::PostObject>) -> impl core::future::Future<Output = HandlerResult<dto::PostObject>> + Send {
        let state = Arc::clone(&self.state);
        let input = request.into_input();
        async move { post_object(&state, input).await }
    }
}

/// Drains the file, then stores it; nothing is stored until the whole file has arrived.
async fn post_object(state: &Arc<Mutex<Fixture>>, input: dto::PostObjectInput) -> HandlerResult<dto::PostObject> {
    let bytes = drain(Some(input.body)).await?;
    // The fixture stores a form's key, media type and metadata only. The gateway grammar these
    // cases run under hands it no other member; one it did would be refused, never dropped.
    if !input.fields.is_empty() {
        return Err(HandlerError::not_implemented(
            "the fixture does not store a form's other PutObject members",
        ));
    }
    let mut fixture = state
        .lock()
        .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
    require_bucket(&fixture, &input.bucket)?;
    let mut object = StoredObject::new(bytes, input.content_type, fixture.now);
    for (name, value) in input.metadata {
        if object.metadata.insert(name, value).is_some() {
            return Err(HandlerError::new(ErrorCode::INVALID_ARGUMENT, "the form repeats an x-amz-meta-* field"));
        }
    }
    let etag = object.etag.clone();
    let written = fixture.put_object(input.bucket.as_str(), input.key.as_str(), object);
    Ok(Resp::new(dto::PostObjectOutput {
        e_tag: Some(entity_tag(&etag)?),
        version_id: (written != UNVERSIONED).then_some(written),
    }))
}
