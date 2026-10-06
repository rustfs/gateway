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

//! Allocation-free spellings for measured fixed metadata names.
//!
//! Responsible for: using static HeaderName storage for the measured GetObject/PutObject names.
//! NOT responsible for: accepting a request, restricting other names or interpreting values.
//! Upstream: MetaView string lookups. Downstream: the unchanged HeaderView map lookup.

use http::HeaderName;
use http::header::InvalidHeaderName;

pub(super) fn parse(name: &str) -> Result<HeaderName, InvalidHeaderName> {
    let fixed = match name {
        "content-md5" => "content-md5",
        "x-amz-acl" => "x-amz-acl",
        "x-amz-checksum-mode" => "x-amz-checksum-mode",
        "x-amz-expected-bucket-owner" => "x-amz-expected-bucket-owner",
        "x-amz-grant-full-control" => "x-amz-grant-full-control",
        "x-amz-grant-read" => "x-amz-grant-read",
        "x-amz-grant-read-acp" => "x-amz-grant-read-acp",
        "x-amz-grant-write-acp" => "x-amz-grant-write-acp",
        "x-amz-object-lock-event-hold" => "x-amz-object-lock-event-hold",
        "x-amz-object-lock-event-hold-duration-days" => "x-amz-object-lock-event-hold-duration-days",
        "x-amz-object-lock-event-hold-duration-years" => "x-amz-object-lock-event-hold-duration-years",
        "x-amz-object-lock-legal-hold" => "x-amz-object-lock-legal-hold",
        "x-amz-object-lock-mode" => "x-amz-object-lock-mode",
        "x-amz-object-lock-retain-until-date" => "x-amz-object-lock-retain-until-date",
        "x-amz-request-payer" => "x-amz-request-payer",
        "x-amz-sdk-checksum-algorithm" => "x-amz-sdk-checksum-algorithm",
        "x-amz-server-side-encryption" => "x-amz-server-side-encryption",
        "x-amz-server-side-encryption-aws-kms-key-id" => "x-amz-server-side-encryption-aws-kms-key-id",
        "x-amz-server-side-encryption-bucket-key-enabled" => "x-amz-server-side-encryption-bucket-key-enabled",
        "x-amz-server-side-encryption-context" => "x-amz-server-side-encryption-context",
        "x-amz-server-side-encryption-customer-algorithm" => "x-amz-server-side-encryption-customer-algorithm",
        "x-amz-server-side-encryption-customer-key" => "x-amz-server-side-encryption-customer-key",
        "x-amz-server-side-encryption-customer-key-md5" => "x-amz-server-side-encryption-customer-key-md5",
        "x-amz-storage-class" => "x-amz-storage-class",
        "x-amz-tagging" => "x-amz-tagging",
        "x-amz-website-redirect-location" => "x-amz-website-redirect-location",
        "x-amz-write-offset-bytes" => "x-amz-write-offset-bytes",
        _ => return HeaderName::from_bytes(name.as_bytes()),
    };
    Ok(HeaderName::from_static(fixed))
}
