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

//! Request rows for overlapping operation selectors and their exact registered differences.
//!
//! Responsible for: selector precedence regression fixtures.
//! NOT responsible for: matching findings or registering differences.
//! Upstream: the shared request row. Downstream: the combined request matrix and its consumers.

use super::{RequestRow, row};
use crate::RawRequest;

pub(super) fn rows() -> Vec<RequestRow> {
    vec![
        row(
            "multipart-create-complete-overlap",
            RawRequest::post("/bkt/k?uploads&uploadId=u", super::COMPLETE_BODY),
            &["kd-decode-0112"],
        ),
        row(
            "attributes-upload-id-nightly-artifact",
            RawRequest::get("/bkt/k?uploadId=up=aS&g-inture=4&attributes=cted-bucket-o"),
            &["kd-decode-0110", "kd-decode-0111"],
        ),
        row(
            "annotation-upload-id-nightly-artifact",
            RawRequest::put("/bkt/k?annotation=1&uploadId=u", b"")
                .header("x-amz-checksum-sha512", "MJ7MSJwS1utMxA9QyQLydNbxf9JlnDaNCVbRbDP2DDoH2Bdz33Fd"),
            &["kd-decode-0085", "kd-decode-0086"],
        ),
        row(
            "copy-annotation-query",
            RawRequest::put("/bkt/k?annotation=1", b"").header("x-amz-copy-source", "/src/k"),
            &["kd-decode-0087", "kd-decode-0088"],
        ),
        row(
            "part-annotation-query",
            RawRequest::put("/bkt/k?annotation=1&uploadId=u&partNumber=2", b""),
            &["kd-decode-0089", "kd-decode-0090"],
        ),
        row(
            "bucket-events-query",
            RawRequest::get("/bkt?events"),
            &["kd-decode-0091", "kd-decode-0092"],
        ),
        row(
            "multipart-events-query",
            RawRequest::get("/bkt?uploads&events"),
            &["kd-decode-0093", "kd-decode-0094"],
        ),
        row(
            "versions-events-query",
            RawRequest::get("/bkt?versions&events"),
            &["kd-decode-0095", "kd-decode-0096"],
        ),
        row(
            "list-v2-events-query",
            RawRequest::get("/bkt?list-type=2&events"),
            &["kd-decode-0097", "kd-decode-0098"],
        ),
        row(
            "location-events-query",
            RawRequest::get("/bkt?location&events"),
            &["kd-decode-0099", "kd-decode-0100"],
        ),
        row(
            "versioning-events-query",
            RawRequest::get("/bkt?versioning&events"),
            &["kd-decode-0101", "kd-decode-0102"],
        ),
        row(
            "list-parts-annotations-query",
            RawRequest::get("/bkt/k?annotation&uploadId=u"),
            &["kd-decode-0103", "kd-decode-0104"],
        ),
        row(
            "list-parts-named-annotation-query",
            RawRequest::get("/bkt/k?annotation&annotationName=a&uploadId=u"),
            &["kd-decode-0105", "kd-decode-0106"],
        ),
        row(
            "abort-part-annotation-query",
            RawRequest::new(http::Method::DELETE, "/bkt/k?annotation&uploadId=u"),
            &["kd-decode-0107", "kd-decode-0108"],
        ),
        row(
            "abort-part-named-annotation-query",
            RawRequest::new(http::Method::DELETE, "/bkt/k?annotation&annotationName=a&uploadId=u"),
            &["kd-decode-0107", "kd-decode-0109"],
        ),
    ]
}
