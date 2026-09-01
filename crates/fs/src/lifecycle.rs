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

//! Persistent bucket lifecycle configuration handlers.
//!
//! Responsible for: validating one complete lifecycle document, atomically replacing its durable
//! record, and serving or deleting that same record after restart.
//! NOT responsible for: evaluating expiration/transition actions, lifecycle scheduling, or tags.
//! Upstream: generated lifecycle DTOs and the historical persistence codec. Downstream: production handlers.

use std::io;

use rustfs_gateway::dto::{
    AbortIncompleteMultipartUpload, BucketLifecycleConfiguration, DeleteBucketLifecycle, DeleteBucketLifecycleOutput,
    GetBucketLifecycleConfiguration, GetBucketLifecycleConfigurationOutput, LifecycleExpiration, LifecycleRule,
    LifecycleRuleAndOperator, LifecycleRuleFilter, NoncurrentVersionExpiration, NoncurrentVersionTransition,
    PutBucketLifecycleConfiguration, PutBucketLifecycleConfigurationOutput, Status, StorageClass, Tag, Transition,
    TransitionDefaultMinimumObjectSize,
};
use rustfs_gateway::persistence::{
    PersistedAbortIncompleteMultipartUpload, PersistedLifecycleAnd, PersistedLifecycleConfiguration,
    PersistedLifecycleExpiration, PersistedLifecycleFilter, PersistedLifecycleRule, PersistedLifecycleTag,
    PersistedNoncurrentVersionExpiration, PersistedNoncurrentVersionTransition, PersistedTransition, parse_lifecycle,
    serialize_lifecycle,
};
use rustfs_gateway::{
    ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp, Timestamp, TimestampFormat, validate_lifecycle,
};

use super::{FsBackend, storage_error};

pub(super) const RECORD_FILE: &str = "lifecycle";
const RECORD_MAGIC: &[u8] = b"FSLC1\n";

struct LifecycleRecord {
    configuration: BucketLifecycleConfiguration,
    minimum_object_size: Option<TransitionDefaultMinimumObjectSize>,
}

impl FsBackend {
    fn lifecycle_path(&self, bucket: &str) -> std::path::PathBuf {
        self.bucket_path(bucket).join(RECORD_FILE)
    }

    async fn read_lifecycle(&self, bucket: &str) -> Result<LifecycleRecord, HandlerError> {
        self.require_bucket(bucket).await?;
        let path = self.lifecycle_path(bucket);
        let metadata = match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => return Err(unsafe_record()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(no_such_lifecycle()),
            Err(_) => return Err(storage_error()),
        };
        if !metadata.is_file() {
            return Err(unsafe_record());
        }
        let bytes = tokio::fs::read(path).await.map_err(|_| storage_error())?;
        decode_record(&bytes).map_err(|_| storage_error())
    }

    async fn write_lifecycle(&self, bucket: &str, record: &LifecycleRecord) -> Result<(), HandlerError> {
        self.require_bucket(bucket).await?;
        let destination = self.lifecycle_path(bucket);
        match tokio::fs::symlink_metadata(&destination).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(unsafe_record()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage_error()),
        }
        let bytes = encode_record(record).map_err(|_| storage_error())?;
        self.write_atomic(&self.bucket_path(bucket), &destination, &bytes).await
    }

    async fn delete_lifecycle(&self, bucket: &str) -> Result<(), HandlerError> {
        self.require_bucket(bucket).await?;
        let path = self.lifecycle_path(bucket);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                tokio::fs::remove_file(path).await.map_err(|_| storage_error())
            }
            Ok(_) => Err(unsafe_record()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(storage_error()),
        }
    }
}

impl Handler<GetBucketLifecycleConfiguration> for FsBackend {
    async fn call(&self, request: Req<GetBucketLifecycleConfiguration>) -> HandlerResult<GetBucketLifecycleConfiguration> {
        let record = self.read_lifecycle(request.input().bucket.as_str()).await?;
        Ok(Resp::new(GetBucketLifecycleConfigurationOutput {
            rules: record.configuration.rules,
            transition_default_minimum_object_size: record.minimum_object_size,
        }))
    }
}

impl Handler<PutBucketLifecycleConfiguration> for FsBackend {
    async fn call(&self, request: Req<PutBucketLifecycleConfiguration>) -> HandlerResult<PutBucketLifecycleConfiguration> {
        let input = request.into_input();
        self.require_bucket(input.bucket.as_str()).await?;
        let Some(configuration) = input.lifecycle_configuration else {
            return Err(HandlerError::new(ErrorCode::MALFORMED_XML, "the request carries no lifecycle document"));
        };
        validate_lifecycle(&configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        let record = LifecycleRecord {
            configuration,
            minimum_object_size: input.transition_default_minimum_object_size.clone(),
        };
        self.write_lifecycle(input.bucket.as_str(), &record).await?;
        Ok(Resp::new(PutBucketLifecycleConfigurationOutput {
            transition_default_minimum_object_size: input.transition_default_minimum_object_size,
        }))
    }
}

impl Handler<DeleteBucketLifecycle> for FsBackend {
    async fn call(&self, request: Req<DeleteBucketLifecycle>) -> HandlerResult<DeleteBucketLifecycle> {
        self.delete_lifecycle(request.input().bucket.as_str()).await?;
        Ok(Resp::new(DeleteBucketLifecycleOutput::default()))
    }
}

fn encode_record(record: &LifecycleRecord) -> Result<Vec<u8>, ()> {
    let persisted = to_persisted(&record.configuration)?;
    let document = serialize_lifecycle(&persisted).map_err(|_| ())?;
    let minimum = record
        .minimum_object_size
        .as_ref()
        .map_or_else(|| "-".to_owned(), |value| hex::encode(value.as_str()));
    let mut bytes = Vec::with_capacity(RECORD_MAGIC.len() + minimum.len() + document.len() + 1);
    bytes.extend_from_slice(RECORD_MAGIC);
    bytes.extend_from_slice(minimum.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&document);
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<LifecycleRecord, ()> {
    let bytes = bytes.strip_prefix(RECORD_MAGIC).ok_or(())?;
    let newline = bytes.iter().position(|byte| *byte == b'\n').ok_or(())?;
    let minimum = match &bytes[..newline] {
        b"-" => None,
        encoded => {
            let decoded = hex::decode(encoded).map_err(|_| ())?;
            let value = String::from_utf8(decoded).map_err(|_| ())?;
            Some(TransitionDefaultMinimumObjectSize::custom(value))
        }
    };
    let persisted = parse_lifecycle(&bytes[newline + 1..]).map_err(|_| ())?;
    Ok(LifecycleRecord {
        configuration: from_persisted(persisted)?,
        minimum_object_size: minimum,
    })
}

fn to_persisted(value: &BucketLifecycleConfiguration) -> Result<PersistedLifecycleConfiguration, ()> {
    Ok(PersistedLifecycleConfiguration {
        expiry_updated_at: None,
        rules: value.rules.iter().map(rule_to_persisted).collect::<Result<Vec<_>, _>>()?,
    })
}

fn rule_to_persisted(value: &LifecycleRule) -> Result<PersistedLifecycleRule, ()> {
    Ok(PersistedLifecycleRule {
        abort_incomplete_multipart_upload: value.abort_incomplete_multipart_upload.as_ref().map(|action| {
            PersistedAbortIncompleteMultipartUpload {
                days_after_initiation: action.days_after_initiation,
            }
        }),
        del_marker_expiration: None,
        expiration: value
            .expiration
            .as_ref()
            .map(|expiration| {
                Ok(PersistedLifecycleExpiration {
                    date: expiration
                        .date
                        .map(|date| date.render(TimestampFormat::Iso8601).map_err(|_| ()))
                        .transpose()?,
                    days: expiration.days,
                    expired_object_all_versions: None,
                    expired_object_delete_marker: expiration.expired_object_delete_marker,
                })
            })
            .transpose()?,
        filter: value.filter.as_ref().map(filter_to_persisted).transpose()?,
        id: value.id.clone(),
        noncurrent_version_expiration: value.noncurrent_version_expiration.as_ref().map(|action| {
            PersistedNoncurrentVersionExpiration {
                newer_noncurrent_versions: action.newer_noncurrent_versions,
                noncurrent_days: action.noncurrent_days,
            }
        }),
        noncurrent_version_transitions: (!value.noncurrent_version_transitions.is_empty()).then(|| {
            value
                .noncurrent_version_transitions
                .iter()
                .map(|action| PersistedNoncurrentVersionTransition {
                    newer_noncurrent_versions: action.newer_noncurrent_versions,
                    noncurrent_days: action.noncurrent_days,
                    storage_class: action.storage_class.as_ref().map(|class| class.as_str().to_owned()),
                })
                .collect()
        }),
        prefix: value.prefix.clone(),
        status: value.status.as_str().to_owned(),
        transitions: (!value.transitions.is_empty())
            .then(|| {
                value
                    .transitions
                    .iter()
                    .map(|action| {
                        Ok(PersistedTransition {
                            date: action
                                .date
                                .map(|date| date.render(TimestampFormat::Iso8601).map_err(|_| ()))
                                .transpose()?,
                            days: action.days,
                            storage_class: action.storage_class.as_ref().map(|class| class.as_str().to_owned()),
                        })
                    })
                    .collect::<Result<Vec<_>, ()>>()
            })
            .transpose()?,
    })
}

fn filter_to_persisted(value: &LifecycleRuleFilter) -> Result<PersistedLifecycleFilter, ()> {
    Ok(PersistedLifecycleFilter {
        and: value
            .and
            .as_ref()
            .map(|and| {
                Ok(PersistedLifecycleAnd {
                    object_size_greater_than: and.object_size_greater_than,
                    object_size_less_than: and.object_size_less_than,
                    prefix: and.prefix.clone(),
                    tags: (!and.tags.is_empty()).then(|| and.tags.iter().map(tag_to_persisted).collect::<Vec<_>>()),
                })
            })
            .transpose()?,
        object_size_greater_than: value.object_size_greater_than,
        object_size_less_than: value.object_size_less_than,
        prefix: value.prefix.clone(),
        tag: value.tag.as_ref().map(tag_to_persisted),
    })
}

fn tag_to_persisted(value: &Tag) -> PersistedLifecycleTag {
    PersistedLifecycleTag {
        key: Some(value.key.clone()),
        value: Some(value.value.clone()),
    }
}

fn from_persisted(value: PersistedLifecycleConfiguration) -> Result<BucketLifecycleConfiguration, ()> {
    if value.expiry_updated_at.is_some() {
        return Err(());
    }
    Ok(BucketLifecycleConfiguration {
        rules: value
            .rules
            .into_iter()
            .map(rule_from_persisted)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn rule_from_persisted(value: PersistedLifecycleRule) -> Result<LifecycleRule, ()> {
    if value.del_marker_expiration.is_some() {
        return Err(());
    }
    Ok(LifecycleRule {
        abort_incomplete_multipart_upload: value
            .abort_incomplete_multipart_upload
            .map(|action| AbortIncompleteMultipartUpload {
                days_after_initiation: action.days_after_initiation,
            }),
        expiration: value
            .expiration
            .map(|expiration| {
                if expiration.expired_object_all_versions.is_some() {
                    return Err(());
                }
                Ok(LifecycleExpiration {
                    date: expiration
                        .date
                        .map(|date| Timestamp::parse(&date, TimestampFormat::Iso8601).map_err(|_| ()))
                        .transpose()?,
                    days: expiration.days,
                    expired_object_delete_marker: expiration.expired_object_delete_marker,
                })
            })
            .transpose()?,
        filter: value.filter.map(filter_from_persisted).transpose()?,
        id: value.id,
        prefix: value.prefix,
        status: Status::custom(value.status),
        transitions: value
            .transitions
            .unwrap_or_default()
            .into_iter()
            .map(|action| {
                Ok(Transition {
                    date: action
                        .date
                        .map(|date| Timestamp::parse(&date, TimestampFormat::Iso8601).map_err(|_| ()))
                        .transpose()?,
                    days: action.days,
                    storage_class: action.storage_class.map(StorageClass::custom),
                })
            })
            .collect::<Result<Vec<_>, ()>>()?,
        noncurrent_version_transitions: value
            .noncurrent_version_transitions
            .unwrap_or_default()
            .into_iter()
            .map(|action| NoncurrentVersionTransition {
                noncurrent_days: action.noncurrent_days,
                storage_class: action.storage_class.map(StorageClass::custom),
                newer_noncurrent_versions: action.newer_noncurrent_versions,
            })
            .collect(),
        noncurrent_version_expiration: value.noncurrent_version_expiration.map(|action| NoncurrentVersionExpiration {
            noncurrent_days: action.noncurrent_days,
            newer_noncurrent_versions: action.newer_noncurrent_versions,
        }),
    })
}

fn filter_from_persisted(value: PersistedLifecycleFilter) -> Result<LifecycleRuleFilter, ()> {
    Ok(LifecycleRuleFilter {
        prefix: value.prefix,
        tag: value.tag.map(tag_from_persisted).transpose()?,
        object_size_greater_than: value.object_size_greater_than,
        object_size_less_than: value.object_size_less_than,
        and: value
            .and
            .map(|and| {
                Ok(LifecycleRuleAndOperator {
                    prefix: and.prefix,
                    tags: and
                        .tags
                        .unwrap_or_default()
                        .into_iter()
                        .map(tag_from_persisted)
                        .collect::<Result<Vec<_>, _>>()?,
                    object_size_greater_than: and.object_size_greater_than,
                    object_size_less_than: and.object_size_less_than,
                })
            })
            .transpose()?,
    })
}

fn tag_from_persisted(value: PersistedLifecycleTag) -> Result<Tag, ()> {
    Ok(Tag {
        key: value.key.ok_or(())?,
        value: value.value.ok_or(())?,
    })
}

fn no_such_lifecycle() -> HandlerError {
    HandlerError::new(ErrorCode::NO_SUCH_LIFECYCLE_CONFIGURATION, "The lifecycle configuration does not exist")
}

fn unsafe_record() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_REQUEST, "the lifecycle storage path is not a safe regular file")
}
