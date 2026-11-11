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

//! Query-parameter redaction: a presigned signature and a zip-download bearer `token` in an entry's
//! target.
//!
//! Responsible for: refusing an entry that still carries either, and sanitizing the token while a
//! neighbouring `continuation-token` survives.
//! NOT responsible for: header, body or form redaction, which `super` covers.
//! Upstream: `rustfs_gateway_corpus::redact`, `super::base_entry`. Downstream: nothing.

use rustfs_gateway_corpus::redact;

use super::base_entry;

#[test]
fn presigned_signature_query_parameter_is_refused() {
    let mut entry = base_entry();
    entry.target = "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900\
                    &X-Amz-Signature=1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
        .to_owned();
    let refusal = redact::admit(&entry).unwrap_err();
    assert!(
        refusal
            .findings
            .iter()
            .any(|finding| finding.reason == redact::Reason::LiveCredentialField
                && finding.site == redact::Site::QueryParam("x-amz-signature".to_owned())),
        "{refusal}"
    );
}

/// Negative — the bearer `token` of a RustFS zip-download URL (ADR-0042) is credential material:
/// an entry still carrying it is refused, whatever its case.
#[test]
fn a_zip_download_token_query_parameter_is_refused() {
    for name in ["token", "Token"] {
        let mut entry = base_entry();
        entry.target = format!("/rustfs/admin/v3/object-zip-downloads/abc.zip?{name}=opaque-bearer-value");
        let refusal = redact::admit(&entry).unwrap_err();
        assert!(
            refusal
                .findings
                .iter()
                .any(|finding| finding.reason == redact::Reason::LiveCredentialField
                    && finding.site == redact::Site::QueryParam("token".to_owned())),
            "{refusal}"
        );
    }
}

/// Negative — a listing's `continuation-token` is not the bearer `token`: sanitizing a zip URL
/// redacts the token and leaves a neighbouring `continuation-token` untouched.
#[test]
fn sanitize_redacts_a_zip_download_token_and_keeps_continuation_token() {
    let mut entry = base_entry();
    entry.target = "/rustfs/admin/v3/object-zip-downloads/abc.zip?token=opaque-bearer-value&continuation-token=page2".to_owned();
    let touched = redact::sanitize(&mut entry);
    assert_eq!(touched, vec!["token"]);
    assert!(!entry.target.contains("opaque-bearer-value"), "{}", entry.target);
    assert!(entry.target.contains("token=__REDACTED__"), "{}", entry.target);
    assert!(entry.target.contains("continuation-token=page2"), "{}", entry.target);
    redact::admit(&entry).unwrap();
}
