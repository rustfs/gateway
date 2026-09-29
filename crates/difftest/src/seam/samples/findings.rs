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

//! Seam rows that pin each registered finding with a request of its own, so a finding cannot
//! outlive the difference it names and cannot hide inside a row that sets fifty members.
//!
//! Responsible for: one row per finding the decode matrix does not already exercise on its own,
//! and the neighbouring values that must stay identical.
//! NOT responsible for: judging (`tests/seam.rs`). Upstream: none. Downstream: `super`.

use http::Method;

use super::{Expect, SeamRow, row};
use crate::request::RawRequest;
use crate::samples::UPLOAD_ID;

const VERSION: &str = "0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0";

fn force(value: &str) -> RawRequest {
    RawRequest::delete("/bucket").header("x-minio-force-delete", value)
}

pub(super) fn rows() -> Vec<SeamRow> {
    let mut rows = vec![
        row("delete-bucket-force-true", force("true"), Expect::Identical),
        row("delete-bucket-force-capitalised-false", force("False"), Expect::Identical),
        row("delete-bucket-force-empty-is-absent", force(""), Expect::Identical),
        row("delete-bucket-force-numeric", force("1"), Expect::BothRefuse("x-minio-force-delete")),
        row("delete-bucket-force-uppercase", force("TRUE"), Expect::BothRefuse("x-minio-force-delete")),
        row("delete-bucket-force-on", force("on"), Expect::BothRefuse("x-minio-force-delete")),
        row(
            "delete-bucket-force-twice",
            force("true").header("x-minio-force-delete", "true"),
            Expect::BothRefuse("x-minio-force-delete"),
        ),
        row(
            "copy-object-minio-target-version",
            RawRequest::new(Method::PUT, &format!("/bucket/k?versionId={VERSION}")).header("x-amz-copy-source", "/src/k"),
            Expect::Identical,
        ),
        row(
            "copy-object-minio-target-version-encoded",
            RawRequest::new(Method::PUT, "/bucket/k?versionId=a%2Bb+c&x-id=CopyObject").header("x-amz-copy-source", "/src/k"),
            Expect::Identical,
        ),
        row(
            "copy-object-minio-target-version-twice",
            RawRequest::new(Method::PUT, "/bucket/k?versionId=a&versionId=b").header("x-amz-copy-source", "/src/k"),
            Expect::NeitherHandsOver,
        ),
        row(
            "create-multipart-upload-minio-version",
            RawRequest::post(&format!("/bucket/k?uploads&versionId={VERSION}"), b""),
            Expect::Identical,
        ),
        row(
            "create-multipart-upload-minio-empty-version",
            RawRequest::post("/bucket/k?uploads&versionId=", b""),
            Expect::Identical,
        ),
        row(
            "list-objects-empty-optional-attributes",
            RawRequest::get("/bucket").header("x-amz-optional-object-attributes", ""),
            Expect::Differs(&["sd-0037", "sd-0025"]),
        ),
        row(
            "list-objects-v2-empty-optional-attributes",
            RawRequest::get("/bucket?list-type=2").header("x-amz-optional-object-attributes", ""),
            Expect::Differs(&["sd-0038", "sd-0026", "sd-0027"]),
        ),
        row(
            "list-object-versions-empty-optional-attributes",
            RawRequest::get("/bucket?versions").header("x-amz-optional-object-attributes", ""),
            Expect::Differs(&["sd-0039", "sd-0028"]),
        ),
        row(
            "get-object-empty-range-is-absent",
            RawRequest::get("/bucket/k").header("range", ""),
            Expect::Identical,
        ),
        row(
            "get-object-attributes-joined-list",
            RawRequest::get("/bucket/k?attributes").header("x-amz-object-attributes", "ETag, ObjectSize"),
            Expect::Differs(&["sd-0015"]),
        ),
        row(
            "get-object-attributes-one-value",
            RawRequest::get("/bucket/k?attributes").header("x-amz-object-attributes", "ETag"),
            Expect::Identical,
        ),
    ];
    // The query split the seam reproduces for `?versionId=`, against the legacy decoder's own.
    for (index, query) in [
        "versionId=a%2Bb+c",
        "versionId=%zz",
        "&&versionId=v&&",
        "versionId",
        "=x&versionId=v",
        "versionId=%E2%9C%93",
        "versionId=%FF",
        "versionid=lower&versionId=v",
    ]
    .into_iter()
    .enumerate()
    {
        let name: &'static str = Box::leak(format!("create-multipart-upload-version-query-{index}").into_boxed_str());
        rows.push(row(name, RawRequest::post(&format!("/bucket/k?uploads&{query}"), b""), Expect::Identical));
    }
    for (operation, request, finding) in [
        ("put", RawRequest::put("/bucket/k", b"x"), "sd-0017"),
        (
            "copy",
            RawRequest::new(Method::PUT, "/bucket/k").header("x-amz-copy-source", "/src/k"),
            "sd-0020",
        ),
        ("create-mpu", RawRequest::post("/bucket/k?uploads", b""), "sd-0023"),
    ] {
        let name: &'static str = Box::leak(format!("{operation}-event-hold-days").into_boxed_str());
        rows.push(row(
            name,
            request.header("x-amz-object-lock-event-hold-duration-days", "3"),
            Expect::FailsClosed(finding),
        ));
    }
    for (name, target, body, finding) in [
        (
            "put-object-lock-configuration-default-event-hold",
            "/bucket?object-lock",
            "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode>\
             <Days>1</Days><DefaultEventHold><Days>3</Days></DefaultEventHold></DefaultRetention></Rule></ObjectLockConfiguration>",
            "sd-0040",
        ),
        (
            "put-object-retention-event-hold",
            "/bucket/k?retention",
            "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00.000Z</RetainUntilDate><EventHold>ON</EventHold></Retention>",
            "sd-0041",
        ),
        (
            "put-object-retention-event-hold-duration",
            "/bucket/k?retention",
            "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00.000Z</RetainUntilDate>\
             <EventHoldDuration><Days>2</Days></EventHoldDuration></Retention>",
            "sd-0042",
        ),
    ] {
        rows.push(row(name, super::document(Method::PUT, target, body), Expect::FailsClosed(finding)));
    }
    rows.push(row(
        "upload-part-with-a-body-and-no-checksum",
        RawRequest::put(&format!("/bucket/k?partNumber=1&uploadId={UPLOAD_ID}"), b"0123456789"),
        Expect::Identical,
    ));
    rows
}
