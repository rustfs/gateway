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
//! content type, user metadata and the retention and legal hold its Object Lock fields set, the
//! way `PutObject` stores a body and its lock headers, and reporting the stored entity tag and
//! version for the framework's success action.
//! NOT responsible for: the form grammar, the POST policy, the success action, or the customer
//! key's transport and digest rules — the gateway's form pipeline decides all of those before
//! this handler is reached (`Req::sse` is the proof).
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
///
/// The three Object Lock fields are held to the rules the `PutObject` headers are held to
/// (`conditional_write::put_object`): the bucket must have object lock on, and the values must
/// pass `validate_object_write_lock` against this case's clock, both before anything is stored.
/// The customer-key fields were judged by the gateway's gate before this handler ran; the fixture
/// encrypts nothing for a `PutObject` either, so they are accepted and not stored.
async fn post_object(state: &Arc<Mutex<Fixture>>, input: dto::PostObjectInput) -> HandlerResult<dto::PostObject> {
    let bytes = drain(Some(input.body)).await?;
    let mut fields = input.fields;
    let lock_mode = fields.object_lock_mode.take();
    let lock_until = fields.object_lock_retain_until_date.take();
    let lock_hold = fields.object_lock_legal_hold_status.take();
    drop(fields.sse_customer_algorithm.take());
    drop(fields.sse_customer_key.take());
    drop(fields.sse_customer_key_md5.take());
    // The fixture stores a form's key, media type, metadata and lock only. The gateway grammar
    // these cases run under hands it no other member; one it did would be refused, never dropped.
    if !fields.is_empty() {
        return Err(HandlerError::not_implemented(
            "the fixture does not store a form's other PutObject members",
        ));
    }
    let mut fixture = state
        .lock()
        .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
    require_bucket(&fixture, &input.bucket)?;
    let lock_mode = lock_mode.as_ref().map(|mode| mode.as_str());
    let lock_hold = lock_hold.as_ref().map(|status| status.as_str());
    if lock_mode.is_some() || lock_until.is_some() || lock_hold.is_some() {
        require_object_lock(&fixture, input.bucket.as_str())?;
        validate_object_write_lock(lock_mode, lock_until.as_ref(), lock_hold, fixture.now)
            .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
    }
    let mut object = StoredObject::new(bytes, input.content_type, fixture.now);
    // Validated above: a mode and an instant arrive together or not at all.
    if let (Some(mode), Some(until)) = (lock_mode, lock_until) {
        object.retention = Some(dto::ObjectLockRetention {
            mode: Some(dto::Mode::custom(mode.to_owned())),
            retain_until_date: Some(until),
            // The write fields carry no event hold (2026-09-17 model, rustfs/gateway#815).
            event_hold: None,
            event_hold_duration: None,
        });
    }
    object.legal_hold = lock_hold.map(|status| dto::ObjectLockLegalHold {
        status: Some(dto::Status::custom(status.to_owned())),
    });
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
