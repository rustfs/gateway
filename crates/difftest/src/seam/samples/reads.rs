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

//! Seam rows for the bucket lifecycle and every read: create and delete a bucket, the bucket and
//! object sub-resource reads, the configuration deletes, and the listings.
//!
//! Responsible for: rows that set every member of those operations' legacy inputs between them,
//! beside what the decode matrix (`crate::samples`) already sends.
//! NOT responsible for: judging (`tests/seam.rs`). Upstream: none. Downstream: `super`.

use http::Method;

use super::{Expect, SeamRow, document, row};
use crate::request::RawRequest;
use crate::samples::{OWNER, UPLOAD_ID, VERSION_ID, sse};

/// Every bucket sub-resource GET and DELETE whose input is the bucket and the owner check only.
const BUCKET_READS: [(&str, &str); 22] = [
    ("GET", "accelerate"),
    ("GET", "acl"),
    ("GET", "cors"),
    ("GET", "encryption"),
    ("GET", "lifecycle"),
    ("GET", "logging"),
    ("GET", "notification"),
    ("GET", "policy"),
    ("GET", "policyStatus"),
    ("GET", "replication"),
    ("GET", "requestPayment"),
    ("GET", "tagging"),
    ("GET", "versioning"),
    ("GET", "website"),
    ("GET", "object-lock"),
    ("GET", "publicAccessBlock"),
    ("DELETE", "cors"),
    ("DELETE", "encryption"),
    ("DELETE", "lifecycle"),
    ("DELETE", "policy"),
    ("DELETE", "replication"),
    ("DELETE", "website"),
];

fn bucket_reads() -> Vec<SeamRow> {
    let mut rows: Vec<SeamRow> = BUCKET_READS
        .iter()
        .map(|(method, resource)| {
            let method = if *method == "GET" { Method::GET } else { Method::DELETE };
            let name: &'static str = Box::leak(format!("{method}-bucket-{resource}").to_lowercase().into_boxed_str());
            row(
                name,
                RawRequest::new(method, &format!("/bucket?{resource}"))
                    .header("x-amz-expected-bucket-owner", OWNER)
                    .header("x-amz-request-payer", "requester"),
                Expect::Identical,
            )
        })
        .collect();
    rows.extend([
        row(
            "delete-bucket-tagging",
            RawRequest::delete("/bucket?tagging").header("x-amz-expected-bucket-owner", OWNER),
            Expect::Identical,
        ),
        row(
            "delete-public-access-block",
            RawRequest::delete("/bucket?publicAccessBlock").header("x-amz-expected-bucket-owner", OWNER),
            Expect::Identical,
        ),
        row(
            "get-bucket-location",
            RawRequest::get("/bucket?location").header("x-amz-expected-bucket-owner", OWNER),
            Expect::Identical,
        ),
        row(
            "head-bucket-every-member",
            RawRequest::head("/bucket").header("x-amz-expected-bucket-owner", OWNER),
            Expect::Identical,
        ),
        row(
            "list-buckets-every-member",
            RawRequest::get("/?max-buckets=10&continuation-token=tok&prefix=b&bucket-region=us-east-1"),
            Expect::Identical,
        ),
    ]);
    rows
}

fn buckets() -> Vec<SeamRow> {
    vec![
        row(
            "create-bucket-every-member",
            document(
                Method::PUT,
                "/new-bucket",
                "<CreateBucketConfiguration><LocationConstraint>us-west-2</LocationConstraint></CreateBucketConfiguration>",
            )
            .header("x-amz-acl", "private")
            .header("x-amz-grant-full-control", "id=\"owner-1\"")
            .header("x-amz-grant-read", "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"")
            .header("x-amz-grant-read-acp", "emailAddress=\"a@example.com\"")
            .header("x-amz-grant-write", "id=\"writer\"")
            .header("x-amz-grant-write-acp", "id=\"owner-2\"")
            .header("x-amz-bucket-object-lock-enabled", "true")
            .header("x-amz-object-ownership", "BucketOwnerEnforced"),
            Expect::Identical,
        ),
        row("create-bucket-bodiless", RawRequest::put("/new-bucket", b""), Expect::Identical),
        row(
            "delete-bucket-owner-check",
            RawRequest::delete("/bucket").header("x-amz-expected-bucket-owner", OWNER),
            Expect::Identical,
        ),
    ]
}

fn object_reads() -> Vec<SeamRow> {
    vec![
        row(
            "get-object-attributes-every-member-but-the-list",
            sse(RawRequest::get(&format!("/bucket/k?attributes&versionId={VERSION_ID}"))
                .header("x-amz-object-attributes", "ETag")
                .header("x-amz-max-parts", "10")
                .header("x-amz-part-number-marker", "2")
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester")),
            Expect::Identical,
        ),
        row(
            "get-object-acl-every-member",
            RawRequest::get(&format!("/bucket/k?acl&versionId={VERSION_ID}"))
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "get-object-tagging-every-member",
            RawRequest::get(&format!("/bucket/k?tagging&versionId={VERSION_ID}"))
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "get-object-retention-every-member",
            RawRequest::get(&format!("/bucket/k?retention&versionId={VERSION_ID}"))
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "get-object-legal-hold-every-member",
            RawRequest::get(&format!("/bucket/k?legal-hold&versionId={VERSION_ID}"))
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "get-object-torrent-every-member",
            RawRequest::get("/bucket/k?torrent")
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "list-parts-every-member",
            sse(RawRequest::get(&format!("/bucket/k?uploadId={UPLOAD_ID}&max-parts=5&part-number-marker=2"))
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester")),
            Expect::Identical,
        ),
        row(
            "list-multipart-uploads-every-member",
            RawRequest::get("/bucket?uploads&delimiter=%2F&encoding-type=url&key-marker=a&max-uploads=5&prefix=p&upload-id-marker=u")
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester"),
            Expect::Identical,
        ),
        row(
            "list-object-versions-every-member",
            RawRequest::get("/bucket?versions&delimiter=%2F&encoding-type=url&key-marker=a&max-keys=5&prefix=p&version-id-marker=v")
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester")
                .header("x-amz-optional-object-attributes", "RestoreStatus"),
            Expect::Identical,
        ),
        row(
            "list-objects-every-member",
            RawRequest::get("/bucket?delimiter=%2F&encoding-type=url&marker=m&max-keys=5&prefix=p")
                .header("x-amz-expected-bucket-owner", OWNER)
                .header("x-amz-request-payer", "requester")
                .header("x-amz-optional-object-attributes", "RestoreStatus"),
            Expect::Identical,
        ),
        row(
            "list-objects-v2-every-member",
            RawRequest::get(
                "/bucket?list-type=2&continuation-token=t&delimiter=%2F&encoding-type=url&fetch-owner=true&max-keys=5&prefix=p&start-after=s",
            )
            .header("x-amz-expected-bucket-owner", OWNER)
            .header("x-amz-request-payer", "requester")
            .header("x-amz-optional-object-attributes", "RestoreStatus"),
            Expect::Identical,
        ),
    ]
}

pub(super) fn rows() -> Vec<SeamRow> {
    let mut rows = buckets();
    rows.extend(bucket_reads());
    rows.extend(object_reads());
    rows
}
