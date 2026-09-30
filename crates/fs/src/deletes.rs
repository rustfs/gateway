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

//! Filesystem-backed `DeleteObjects`: many keys removed in one request, each with its own outcome.
//!
//! Responsible for: running every requested key through the same single-key deletion
//! `DeleteObject` uses, and reporting each one exactly once — as a deleted entry, or as an error
//! entry carrying the code and message that key's deletion answered — and, when the backend was
//! told which keys the storage it stands in for refuses ([`FsBackend::refusing_batch_deletes_of`]),
//! answering each of those on its own instead of deleting it.
//! NOT responsible for: the request's `Content-MD5`/checksum requirement or its XML grammar, which
//! the framework enforces before this handler runs, or what a deletion does under each versioning
//! state, which is `super::versioning`'s.
//! Upstream: `FsBackend::delete_object_version`. Downstream: the CRUD registry.

use rustfs_gateway::dto::{DeleteObjectOutput, DeleteObjects, DeleteObjectsOutput, DeletedObject, Error};
use rustfs_gateway::{ErrorCode, Handler, HandlerError, HandlerResult, ObjectKey, Req, Resp};

use super::FsBackend;

impl FsBackend {
    /// Answers each key of a batch delete that `refuses` names with its own
    /// `400 InvalidArgument` "Invalid argument" error entry, and neither deletes it nor records a
    /// delete marker for it; every other key is deleted as before.
    ///
    /// For a deployment standing this backend in for a storage that refuses some keys outright —
    /// RustFS's refuses a key with a `.` or `..` segment, `//` or a NUL, and answers a batch delete
    /// naming one this way (rustfs/gateway#1145). A batch's keys are read from its authorized
    /// resources, which nothing in front of the handler can narrow, so this is the one place the
    /// refusal can be made; every single-key operation can be refused before the backend is
    /// reached. Off by default.
    #[must_use]
    pub fn refusing_batch_deletes_of(mut self, refuses: fn(&str) -> bool) -> Self {
        self.batch_delete_refusal = Some(refuses);
        self
    }
}

/// The deleted entry for one key, shaped from what its single-key deletion reported.
///
/// An explicit version names itself in `VersionId`, and when that version was a delete marker the
/// entry says so and repeats the id as `DeleteMarkerVersionId`. A key deleted without a version in
/// a versioning bucket gains a delete marker, which the entry reports by its new id.
fn deleted_entry(key: ObjectKey, requested_version: Option<String>, outcome: DeleteObjectOutput) -> DeletedObject {
    let removed_marker = outcome.delete_marker == Some(true);
    match requested_version {
        Some(version_id) => DeletedObject {
            key: Some(key),
            delete_marker: removed_marker.then_some(true),
            delete_marker_version_id: removed_marker.then(|| version_id.clone()),
            version_id: Some(version_id),
        },
        None => DeletedObject {
            key: Some(key),
            delete_marker: removed_marker.then_some(true),
            delete_marker_version_id: removed_marker.then_some(outcome.version_id).flatten(),
            version_id: None,
        },
    }
}

impl Handler<DeleteObjects> for FsBackend {
    async fn call(&self, request: Req<DeleteObjects>) -> HandlerResult<DeleteObjects> {
        // The key list is read from the authorized resources, never from the input: the framework
        // clears `delete.objects` once authorization has run, so a post-authorization mutation of
        // the DTO cannot add a key nobody authorized.
        let entries = request
            .resources()
            .resolve(request.read_proof())
            .ok_or_else(|| HandlerError::internal_error("the delete authorization proof did not match"))?
            .map(|(key, version_id)| (key.clone(), version_id.map(ToOwned::to_owned)))
            .collect::<Vec<_>>();
        let input = request.into_input();
        let bucket = input.bucket.as_str();
        // A missing bucket fails the whole request rather than every entry: there is no key in it
        // whose outcome could be reported.
        self.require_bucket(bucket).await?;
        let quiet = input.delete.quiet.unwrap_or(false);
        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        for (key, version_id) in entries {
            if self.batch_delete_refusal.is_some_and(|refuses| refuses(key.as_str())) {
                errors.push(Error {
                    key: Some(key),
                    version_id,
                    code: Some(ErrorCode::INVALID_ARGUMENT.as_str().to_owned()),
                    message: Some("Invalid argument".to_owned()),
                });
                continue;
            }
            match self.delete_object_version(bucket, key.as_str(), version_id.as_deref()).await {
                // Quiet mode reports only the keys that failed; a success is the absence of an
                // error entry.
                Ok(_) if quiet => {}
                Ok(outcome) => deleted.push(deleted_entry(key, version_id, outcome)),
                Err(error) => errors.push(Error {
                    key: Some(key),
                    version_id,
                    code: Some(error.code().as_str().to_owned()),
                    message: Some(error.message().to_owned()),
                }),
            }
        }
        Ok(Resp::new(DeleteObjectsOutput {
            deleted,
            errors,
            ..DeleteObjectsOutput::default()
        }))
    }
}
