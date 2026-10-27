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

//! Test-only direct CopyObject adapter for the fixture.
//! Responsible for: converting a typed source into the fixture's direct-copy test input.
//! Not responsible for: production copy authorization or resource resolution.
//! Upstream: fixture unit tests. Downstream: the fixture's source-aware copy implementation.

use super::*;

impl Stub {
    /// A server-side copy: read the source, then write the destination. In that order.
    ///
    /// The order is the whole of this handler. Every refusal below happens before a single byte of
    /// the destination is touched, because the two published failures on this path are not wrong
    /// answers — they are correct answers delivered after the destination was already gone. A self
    /// copy that opens the target for writing before reading the source truncates the object it was
    /// asked to rewrite, and an authorization stage that runs after the write refuses the caller
    /// and destroys the object anyway.
    ///
    /// Reading the source into an owned [`StoredObject`] before anything else is what makes that
    /// impossible here rather than merely unlikely: the bytes the copy will write are already in
    /// hand when the destination is opened, so `source == dest` is not a special case to remember.
    ///
    /// # Where the head is committed, and why the source is not below it
    ///
    /// AWS documents a copy as flushing `200` before it knows the outcome, and the boundary it
    /// documents alongside is the one used here: *"if the error occurs before the copy action
    /// starts, you receive a standard Amazon S3 error"*. Naming the source, resolving it, gating it
    /// and evaluating both sets of conditions all happen before the copy action starts, so all of
    /// them keep their own status — which is what `c-copy-0026` and `c-copy-0034` assert, each a
    /// `404` for a source that is not there. What the commit covers is the copy itself.
    pub(super) fn copy_object(&self, input: &dto::CopyObjectInput) -> HandlerResult<dto::CopyObject> {
        use rustfs_gateway::CopySourceValue;
        let (bucket, key, version_id) = match &input.copy_source {
            CopySourceValue::Bucket { bucket, key, version_id } => (bucket.as_str(), key, version_id),
            CopySourceValue::AccessPoint {
                access_point_name,
                key,
                version_id,
                ..
            } => (access_point_name.as_str(), key, version_id),
            CopySourceValue::Outpost {
                outpost_id,
                key,
                version_id,
                ..
            } => {
                let (_, bucket) = outpost_id.split_once("/bucket/").ok_or_else(unknown_source_arn)?;
                (bucket, key, version_id)
            }
        };
        let source = CopySource {
            bucket: source_bucket(bucket)?,
            key: source_key(key)?,
            version_id: version_id.clone(),
        };
        self.copy_object_with_source(input, source)
    }
}
