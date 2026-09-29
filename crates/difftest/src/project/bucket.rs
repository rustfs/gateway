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

//! Bucket-level projections: CreateBucket, DeleteBucket, HeadBucket, ListBuckets,
//! GetBucketLocation, GetBucketVersioning, PutBucketVersioning.
//!
//! Responsible for: reading each operation's gateway input and pinned s3s input into the same
//! member paths. Nested request documents are flattened to one path per leaf
//! (`create_bucket_configuration.location_constraint`), so a difference names the leaf.
//! NOT responsible for: comparing, or any object-level operation.
//! Upstream: the two DTOs. Downstream: `project/mod.rs`.

use rustfs_gateway::dto;

use super::{gateway_projection, oracle_projection};
use crate::s3s::dto as oracle;

gateway_projection! {
    fn gateway_create_bucket(request: dto::CreateBucket => input) as CREATE_BUCKET_MEMBERS {
        put: [bucket],
        opt: [
            acl, grant_full_control, grant_read, grant_read_acp, grant_write, grant_write_acp,
            object_lock_enabled_for_bucket, object_ownership,
        ],
        custom: [create_bucket_configuration],
    }
    |fields| {
        match &input.create_bucket_configuration {
            None => fields.set("create_bucket_configuration", crate::fields::FieldValue::Absent),
            Some(configuration) => {
                fields.set("create_bucket_configuration", crate::fields::FieldValue::Present("<document>".to_owned()));
                fields.opt("create_bucket_configuration.location_constraint", configuration.location_constraint.as_ref());
            }
        }
        None
    }
}

oracle_projection! {
    fn oracle_create_bucket(oracle::CreateBucketInput) {
        put: [bucket],
        opt: [
            acl, bucket_namespace, grant_full_control, grant_read, grant_read_acp, grant_write, grant_write_acp,
            object_lock_enabled_for_bucket, object_ownership,
        ],
        custom: [create_bucket_configuration],
    }
    |fields| {
        match &create_bucket_configuration {
            None => fields.set("create_bucket_configuration", crate::fields::FieldValue::Absent),
            Some(configuration) => {
                fields.set("create_bucket_configuration", crate::fields::FieldValue::Present("<document>".to_owned()));
                fields.opt("create_bucket_configuration.location_constraint", configuration.location_constraint.as_ref());
                fields.opt("create_bucket_configuration.location.name", configuration.location.as_ref().and_then(|location| location.name.as_ref()));
                fields.opt("create_bucket_configuration.location.type", configuration.location.as_ref().and_then(|location| location.type_.as_ref()));
                fields.opt("create_bucket_configuration.bucket.data_redundancy", configuration.bucket.as_ref().and_then(|bucket| bucket.data_redundancy.as_ref()));
                fields.opt("create_bucket_configuration.bucket.type", configuration.bucket.as_ref().and_then(|bucket| bucket.type_.as_ref()));
                fields.opt(
                    "create_bucket_configuration.tags",
                    configuration.tags.as_ref().map(|tags| {
                        crate::fields::render_map(tags.iter().map(|tag| (tag.key.as_deref().unwrap_or(""), tag.value.as_deref().unwrap_or(""))))
                    }).as_ref(),
                );
            }
        }
        None
    }
}

gateway_projection! {
    fn gateway_delete_bucket(request: dto::DeleteBucket => input) as DELETE_BUCKET_MEMBERS {
        put: [bucket],
        opt: [expected_bucket_owner],
        custom: [],
    }
    |fields| { None }
}

oracle_projection! {
    fn oracle_delete_bucket(oracle::DeleteBucketInput) {
        put: [bucket],
        opt: [expected_bucket_owner, force_delete],
        custom: [],
    }
    |fields| { None }
}

gateway_projection! {
    fn gateway_head_bucket(request: dto::HeadBucket => input) as HEAD_BUCKET_MEMBERS {
        put: [bucket],
        opt: [expected_bucket_owner],
        custom: [],
    }
    |fields| { None }
}

oracle_projection! {
    fn oracle_head_bucket(oracle::HeadBucketInput) {
        put: [bucket],
        opt: [expected_bucket_owner],
        custom: [],
    }
    |fields| { None }
}

gateway_projection! {
    fn gateway_list_buckets(request: dto::ListBuckets => input) as LIST_BUCKETS_MEMBERS {
        put: [],
        opt: [bucket_region, continuation_token, max_buckets, prefix],
        custom: [],
    }
    |fields| { None }
}

oracle_projection! {
    fn oracle_list_buckets(oracle::ListBucketsInput) {
        put: [],
        opt: [bucket_region, continuation_token, max_buckets, prefix],
        custom: [],
    }
    |fields| { None }
}

gateway_projection! {
    fn gateway_get_bucket_location(request: dto::GetBucketLocation => input) as GET_BUCKET_LOCATION_MEMBERS {
        put: [bucket],
        opt: [expected_bucket_owner],
        custom: [],
    }
    |fields| { None }
}

oracle_projection! {
    fn oracle_get_bucket_location(oracle::GetBucketLocationInput) {
        put: [bucket],
        opt: [expected_bucket_owner],
        custom: [],
    }
    |fields| { None }
}

gateway_projection! {
    fn gateway_get_bucket_versioning(request: dto::GetBucketVersioning => input) as GET_BUCKET_VERSIONING_MEMBERS {
        put: [bucket],
        opt: [expected_bucket_owner],
        custom: [],
    }
    |fields| { None }
}

oracle_projection! {
    fn oracle_get_bucket_versioning(oracle::GetBucketVersioningInput) {
        put: [bucket],
        opt: [expected_bucket_owner],
        custom: [],
    }
    |fields| { None }
}

gateway_projection! {
    fn gateway_put_bucket_versioning(request: dto::PutBucketVersioning => input) as PUT_BUCKET_VERSIONING_MEMBERS {
        put: [bucket],
        opt: [checksum_algorithm, content_md5, expected_bucket_owner, mfa],
        custom: [versioning_configuration],
    }
    |fields| {
        let configuration = &input.versioning_configuration;
        fields.opt("versioning_configuration.exclude_folders", configuration.exclude_folders.as_ref());
        fields.set(
            "versioning_configuration.excluded_prefixes",
            if configuration.excluded_prefixes.is_empty() {
                crate::fields::FieldValue::Absent
            } else {
                crate::fields::FieldValue::Present(
                    configuration
                        .excluded_prefixes
                        .iter()
                        .map(|entry| entry.prefix.clone().unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
            },
        );
        fields.opt("versioning_configuration.mfa_delete", configuration.mfa_delete.as_ref());
        fields.opt("versioning_configuration.status", configuration.status.as_ref());
        None
    }
}

oracle_projection! {
    fn oracle_put_bucket_versioning(oracle::PutBucketVersioningInput) {
        put: [bucket],
        opt: [checksum_algorithm, content_md5, expected_bucket_owner, mfa],
        custom: [versioning_configuration],
    }
    |fields| {
        // The pinned s3s is built with `minio`, whose versioning document carries RustFS's two
        // prefix-exclusion members; the gateway carries both too (rd-cfg-0006).
        let oracle::VersioningConfiguration {
            exclude_folders,
            excluded_prefixes,
            mfa_delete,
            status,
        } = versioning_configuration;
        fields.opt("versioning_configuration.exclude_folders", exclude_folders.as_ref());
        fields.set(
            "versioning_configuration.excluded_prefixes",
            excluded_prefixes.map_or(crate::fields::FieldValue::Absent, |prefixes| {
                crate::fields::FieldValue::Present(
                    prefixes.iter().map(|prefix| prefix.prefix.clone().unwrap_or_default()).collect::<Vec<_>>().join("\n"),
                )
            }),
        );
        fields.opt("versioning_configuration.mfa_delete", mfa_delete.as_ref());
        fields.opt("versioning_configuration.status", status.as_ref());
        None
    }
}
