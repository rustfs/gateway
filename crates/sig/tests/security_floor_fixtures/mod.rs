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

//! The fixtures both halves of the security-floor suite are built from.
//!
//! Responsible for: one timestamp, one credential scope, one signature, and the request shapes
//! spelled around them — a header-signed request, a presigned URL, a POST form — plus the two
//! operations the cases route against.
//! NOT responsible for: any assertion. A fixture that asserted would make the two suites share a
//! guarantee rather than share a request, and a case would then be able to pass because another
//! file changed.
//! Upstream: the `rustfs-gateway-sig` public API. Downstream: `tests/security_floor.rs` and
//! `tests/security_floor_schemes.rs`.

// Each test binary uses a subset of these: the shapes are shared, the cases are not.
#![allow(dead_code)]

use http::header::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_sig::{OperationFloor, RegionSet, RequestNow, SigService};

pub(crate) const SIGNED_AT: &str = "20150830T123600Z";
/// The same instant as seconds since the Unix epoch.
pub(crate) const SIGNED_AT_UNIX: i64 = 1_440_938_160;
pub(crate) const CRED: &str = "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request";
pub(crate) const SIG_HEX: &str = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";

pub(crate) fn now() -> RequestNow {
    RequestNow::from_unix_seconds(SIGNED_AT_UNIX)
}

pub(crate) fn regions() -> RegionSet {
    RegionSet::new(["us-east-1", "eu-west-1"]).expect("a non-empty region set")
}

pub(crate) fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("a valid header name");
        let value = HeaderValue::from_str(value).expect("a valid header value");
        map.append(name, value);
    }
    map
}

/// The headers of a SigV4 header-signed request, signed at `signed_at`.
pub(crate) fn signed_headers(signed_at: &str) -> HeaderMap {
    header_map(&[
        (
            "authorization",
            &format!("AWS4-HMAC-SHA256 Credential={CRED}, SignedHeaders=host;x-amz-date, Signature={SIG_HEX}"),
        ),
        ("x-amz-date", signed_at),
    ])
}

/// The query of a presigned SigV4 URL.
pub(crate) fn presigned_query(signed_at: &str, expires: &str) -> String {
    format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={CRED}&X-Amz-Date={signed_at}\
         &X-Amz-Expires={expires}&X-Amz-SignedHeaders=host&X-Amz-Signature={SIG_HEX}"
    )
}

/// A POST-policy form, which signs in form fields rather than in a header or the query.
pub(crate) fn post_form(signed_at: &str) -> Vec<(&'static str, String)> {
    vec![
        ("x-amz-algorithm", "AWS4-HMAC-SHA256".to_owned()),
        ("x-amz-credential", CRED.to_owned()),
        ("x-amz-date", signed_at.to_owned()),
        ("policy", "eyJleHBpcmF0aW9uIjoiIn0=".to_owned()),
        ("x-amz-signature", SIG_HEX.to_owned()),
    ]
}

pub(crate) fn form_view<'a>(fields: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    fields.iter().map(|(name, value)| (*name, value.as_str())).collect()
}

pub(crate) fn s3_object_op() -> OperationFloor {
    OperationFloor::builtin("GetObject", SigService::S3)
        .allow_presigned()
        .expect("GetObject is not privileged")
}

pub(crate) fn admin_op() -> OperationFloor {
    OperationFloor::builtin("AdminSetConfig", SigService::S3).mark_privileged()
}
