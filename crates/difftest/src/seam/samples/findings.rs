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
        row("delete-bucket-force-true", force("true"), Expect::Differs(&["sd-0005"])),
        row("delete-bucket-force-capitalised-false", force("False"), Expect::Differs(&["sd-0005"])),
        row("delete-bucket-force-empty-is-absent", force(""), Expect::Identical),
        row("delete-bucket-force-numeric", force("1"), Expect::LegacyRefuses("sd-0006")),
        row("delete-bucket-force-uppercase", force("TRUE"), Expect::LegacyRefuses("sd-0006")),
        row("delete-bucket-force-on", force("on"), Expect::LegacyRefuses("sd-0006")),
        row(
            "delete-bucket-force-twice",
            force("true").header("x-minio-force-delete", "true"),
            Expect::LegacyRefuses("sd-0006"),
        ),
        row(
            "copy-object-minio-target-version",
            RawRequest::new(Method::PUT, &format!("/bucket/k?versionId={VERSION}")).header("x-amz-copy-source", "/src/k"),
            Expect::Differs(&["sd-0003"]),
        ),
        row(
            "create-multipart-upload-minio-version",
            RawRequest::post(&format!("/bucket/k?uploads&versionId={VERSION}"), b""),
            Expect::Differs(&["sd-0004"]),
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
    rows.push(row(
        "upload-part-with-a-body-and-no-checksum",
        RawRequest::put(&format!("/bucket/k?partNumber=1&uploadId={UPLOAD_ID}"), b"0123456789"),
        Expect::Identical,
    ));
    rows
}
