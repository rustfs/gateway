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

//! Filesystem-backed `CopyObject` execution after the framework authorizes its source.
//!
//! Responsible for: selecting the authorized source representation, applying source conditions,
//! classifying self copies, choosing COPY or REPLACE metadata, and publishing the destination.
//! NOT responsible for: parsing `x-amz-copy-source` or authorizing either resource; the framework
//! seals the raw header and supplies the proof consumed here. Upstream: `rustfs-gateway` copy and
//! conditional contracts plus `super::reads`. Downstream: the CRUD registry.

use rustfs_gateway::dto::{CopyObject, CopyObjectInput, CopyObjectOutput, MetadataDirective};
use rustfs_gateway::{
    ConditionalOutcome, ETag, ErrorCode, Handler, HandlerError, HandlerResult, MetadataSource, ObjectValidators,
    PRECONDITION_FAILED_MESSAGE, Preconditions, Req, RequestKind, Resp, Timestamp, classify_self_copy,
    copy_source_guards_before_target_write, copy_source_if_match_miss_proceeds, evaluate, parse_conditional_etag,
};

use super::reads::Representation;
use super::records::ObjectAttributes;
use super::versioning::PublishedObject;
use super::{FsBackend, etag};

fn directive(input: &CopyObjectInput) -> Result<MetadataSource, HandlerError> {
    MetadataSource::parse(input.metadata_directive.as_ref().map(MetadataDirective::as_str))
        .ok_or_else(|| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "x-amz-metadata-directive must be COPY or REPLACE"))
}

fn conditional_etag(value: Option<&str>) -> Result<Option<ETag>, HandlerError> {
    value
        .map(parse_conditional_etag)
        .transpose()
        .map_err(|_| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "a copy-source condition has an invalid entity tag"))
}

fn source_conditions(input: &CopyObjectInput, observed_at: Timestamp) -> Result<Preconditions, HandlerError> {
    Ok(Preconditions {
        if_match: conditional_etag(input.copy_source_if_match.as_deref())?,
        if_none_match: conditional_etag(input.copy_source_if_none_match.as_deref())?,
        if_modified_since: input.copy_source_if_modified_since,
        if_unmodified_since: input.copy_source_if_unmodified_since,
        observed_at: Some(observed_at),
    })
}

fn guard_source(input: &CopyObjectInput, source: &Representation, observed_at: Timestamp) -> Result<(), HandlerError> {
    let conditions = source_conditions(input, observed_at)?;
    // These validators describe the representation being read, so all four read-side conditions
    // are evaluated. CopyObject itself is still a write: either negative read verdict becomes its
    // 412 rather than a 304 response.
    let outcome = evaluate(
        &conditions,
        &ObjectValidators {
            exists: true,
            etag: Some(source.e_tag.clone()),
            last_modified: Some(source.last_modified),
        },
        RequestKind::Read,
    )
    .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
    let only_if_match = input.copy_source_if_match.is_some()
        && input.copy_source_if_unmodified_since.is_none()
        && input.copy_source_if_none_match.is_none()
        && input.copy_source_if_modified_since.is_none();
    if only_if_match && copy_source_if_match_miss_proceeds() {
        return Ok(());
    }
    match outcome {
        ConditionalOutcome::Proceed => Ok(()),
        ConditionalOutcome::NotModified | ConditionalOutcome::PreconditionFailed(_) => {
            Err(HandlerError::new(ErrorCode::PRECONDITION_FAILED, PRECONDITION_FAILED_MESSAGE))
        }
        ConditionalOutcome::Conflict => Err(HandlerError::internal_error("the copy-source condition reported a write race")),
    }
}

async fn publish(
    backend: &FsBackend,
    input: &CopyObjectInput,
    source: &Representation,
    attributes: &ObjectAttributes,
) -> Result<(PublishedObject, ETag), HandlerError> {
    let e_tag = etag(&source.bytes)?;
    let published = backend
        .publish_object(input.bucket.as_str(), input.key.as_str(), &source.bytes, &e_tag, attributes)
        .await?;
    Ok((published, e_tag))
}

impl Handler<CopyObject> for FsBackend {
    async fn call(&self, request: Req<CopyObject>) -> HandlerResult<CopyObject> {
        let source = request
            .resources()
            .source()
            .resolve(request.read_proof())
            .ok_or_else(|| HandlerError::internal_error("the copy-source authorization proof did not match"))?;
        let input = request.into_input();
        let metadata_source = directive(&input)?;
        let source_representation = self
            .representation(source.bucket().as_str(), source.key().as_str(), source.version_id())
            .await?;
        let self_copy = classify_self_copy(&source, &input.bucket, &input.key, metadata_source.changes_the_object());
        if let Some(rejection) = self_copy.rejection() {
            return Err(HandlerError::new(rejection.code().clone(), rejection.reason()));
        }
        // The directive decides the representation headers together with the user metadata: S3
        // copies both from the source under COPY and rebuilds both from the request under REPLACE.
        let attributes = match metadata_source {
            MetadataSource::FromSource => ObjectAttributes {
                metadata: source_representation.metadata.clone(),
                headers: source_representation.headers.clone(),
            },
            MetadataSource::FromRequest => ObjectAttributes {
                metadata: input.metadata.clone(),
                headers: request_content_headers!(input),
            },
        };

        let guard_before_write = copy_source_guards_before_target_write();
        let mut result = if guard_before_write {
            None
        } else {
            Some(publish(self, &input, &source_representation, &attributes).await?)
        };
        guard_source(&input, &source_representation, Timestamp::from_secs(self.clock.now().unix_seconds()))?;
        if result.is_none() {
            result = Some(publish(self, &input, &source_representation, &attributes).await?);
        }
        let Some((published, e_tag)) = result else {
            return Err(HandlerError::internal_error("the copy destination was not published"));
        };

        Ok(Resp::new(CopyObjectOutput {
            e_tag,
            last_modified: Some(published.last_modified),
            copy_source_version_id: source
                .version_id()
                .map(ToOwned::to_owned)
                .or(source_representation.version_id),
            version_id: published.version_id,
            ..CopyObjectOutput::default()
        }))
    }
}
