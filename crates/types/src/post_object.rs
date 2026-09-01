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

//! The DTO surface for browser POST Object uploads omitted by the Smithy S3 model.
//!
//! Responsible for: the owned bucket, resolved key, live file stream, selected object headers,
//! and storage result passed between the POST Object codec and a backend handler.
//! NOT responsible for: multipart framing, POST-policy evaluation, routing, or success-action
//! rendering. Upstream: the authenticated gateway form pipeline. Downstream: backend handlers.

use rustfs_gateway_stream::ByteStream;

use crate::{BucketName, ETag, ObjectKey};

/// The standard S3 POST Object operation marker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PostObject;

/// A browser upload after its form fields and POST policy have been accepted.
#[derive(Debug)]
pub struct PostObjectInput {
    /// The bucket named by both the route and the accepted policy.
    pub bucket: BucketName,
    /// The object key after `${filename}` substitution and name validation.
    pub key: ObjectKey,
    /// The file part as a live, policy-bounded stream.
    pub body: ByteStream,
    /// The file part's media type, or `None` for the S3 default.
    pub content_type: Option<String>,
    /// User metadata from accepted `x-amz-meta-*` form fields.
    pub metadata: Vec<(String, String)>,
}

/// The storage result used to render a POST Object response.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PostObjectOutput {
    /// The entity tag assigned to the stored object.
    pub e_tag: Option<ETag>,
    /// The version identifier assigned by a versioned bucket.
    pub version_id: Option<String>,
}
