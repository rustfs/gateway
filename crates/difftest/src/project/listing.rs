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

//! Listing projections: ListObjects, ListObjectsV2, ListObjectVersions, ListMultipartUploads.
//!
//! Responsible for: reading each listing's gateway input and pinned s3s input into the same member
//! paths, `optional_object_attributes` (a comma-delimited header list on both stacks) as its
//! comma-joined values.
//! NOT responsible for: comparing, or pagination semantics (a decode diff compares what was read,
//! not what a listing then does with it).
//! Upstream: the two DTOs. Downstream: `project/mod.rs`.

use rustfs_gateway::dto;

use super::{gateway_projection, oracle_projection};
use crate::fields::FieldValue;
use crate::s3s::dto as oracle;

/// The list-valued attribute header either stack reads, as its comma-joined values.
fn optional_attributes<T: crate::fields::Render>(fields: &mut crate::fields::Fields, attributes: Option<&Vec<T>>) {
    fields.set(
        "optional_object_attributes",
        attributes.map_or(FieldValue::Absent, |attributes| {
            FieldValue::Present(
                attributes
                    .iter()
                    .map(crate::fields::Render::render)
                    .collect::<Vec<_>>()
                    .join(","),
            )
        }),
    );
}

gateway_projection! {
    fn gateway_list_objects(request: dto::ListObjects => input) as LIST_OBJECTS_MEMBERS {
        put: [bucket],
        opt: [delimiter, encoding_type, expected_bucket_owner, marker, max_keys, prefix, request_payer],
        custom: [optional_object_attributes],
    }
    |fields| {
        // The gateway holds the header list as a plain list, empty when the header is absent.
        let attributes = &input.optional_object_attributes;
        optional_attributes(&mut fields, (!attributes.is_empty()).then_some(attributes));
        None
    }
}

oracle_projection! {
    fn oracle_list_objects(oracle::ListObjectsInput) {
        put: [bucket],
        opt: [delimiter, encoding_type, expected_bucket_owner, marker, max_keys, prefix, request_payer],
        custom: [optional_object_attributes],
    }
    |fields| {
        optional_attributes(&mut fields, optional_object_attributes.as_ref());
        None
    }
}

gateway_projection! {
    fn gateway_list_objects_v2(request: dto::ListObjectsV2 => input) as LIST_OBJECTS_V2_MEMBERS {
        put: [bucket],
        opt: [
            continuation_token, delimiter, encoding_type, expected_bucket_owner, fetch_owner, max_keys, prefix,
            request_payer, start_after,
        ],
        custom: [optional_object_attributes],
    }
    |fields| {
        // The gateway holds the header list as a plain list, empty when the header is absent.
        let attributes = &input.optional_object_attributes;
        optional_attributes(&mut fields, (!attributes.is_empty()).then_some(attributes));
        None
    }
}

oracle_projection! {
    fn oracle_list_objects_v2(oracle::ListObjectsV2Input) {
        put: [bucket],
        opt: [
            continuation_token, delimiter, encoding_type, expected_bucket_owner, fetch_owner, max_keys, prefix,
            request_payer, start_after,
        ],
        custom: [optional_object_attributes],
    }
    |fields| {
        optional_attributes(&mut fields, optional_object_attributes.as_ref());
        None
    }
}

gateway_projection! {
    fn gateway_list_object_versions(request: dto::ListObjectVersions => input) as LIST_OBJECT_VERSIONS_MEMBERS {
        put: [bucket],
        opt: [
            delimiter, encoding_type, expected_bucket_owner, key_marker, max_keys, prefix, request_payer,
            version_id_marker,
        ],
        custom: [optional_object_attributes],
    }
    |fields| {
        // The gateway holds the header list as a plain list, empty when the header is absent.
        let attributes = &input.optional_object_attributes;
        optional_attributes(&mut fields, (!attributes.is_empty()).then_some(attributes));
        None
    }
}

oracle_projection! {
    fn oracle_list_object_versions(oracle::ListObjectVersionsInput) {
        put: [bucket],
        opt: [
            delimiter, encoding_type, expected_bucket_owner, key_marker, max_keys, prefix, request_payer,
            version_id_marker,
        ],
        custom: [optional_object_attributes],
    }
    |fields| {
        optional_attributes(&mut fields, optional_object_attributes.as_ref());
        None
    }
}

gateway_projection! {
    fn gateway_list_multipart_uploads(request: dto::ListMultipartUploads => input) as LIST_MULTIPART_UPLOADS_MEMBERS {
        put: [bucket],
        opt: [
            delimiter, encoding_type, expected_bucket_owner, key_marker, max_uploads, prefix, request_payer,
            upload_id_marker,
        ],
        custom: [],
    }
    |fields| { None }
}

oracle_projection! {
    fn oracle_list_multipart_uploads(oracle::ListMultipartUploadsInput) {
        put: [bucket],
        opt: [
            delimiter, encoding_type, expected_bucket_owner, key_marker, max_uploads, prefix, request_payer,
            upload_id_marker,
        ],
        custom: [],
    }
    |fields| { None }
}
