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

//! Host-verified header token cases for the recorded-corpus redaction gate.
//!
//! Responsible for: proving that the token headers a RustFS host accepts for OpenStack Keystone,
//! `x-auth-token` and `x-storage-token`, are treated as credential material by admission and
//! redaction in a recorded request, whatever their case, while a header that merely resembles one
//! is left alone.
//! NOT responsible for: the gateway's admission of such a token (ADR-0051), which is exercised
//! where the header token claim lives, or any other header a host may claim, which that host
//! redacts itself.
//! Upstream: the integration target, which supplies the `with_header` fixture. Downstream:
//! `rustfs_gateway_corpus::redact`, which supplies the verdict.

use rustfs_gateway_corpus::redact;

use super::with_header;

const TOKEN: &str = "gAAAAABopaque-header-token-value";

/// Negative — a recorded request still carrying a Keystone token header is refused, whatever the
/// header's case: the header is a live credential.
#[test]
fn a_host_token_header_is_refused() {
    for name in ["x-auth-token", "X-Auth-Token", "x-storage-token", "X-Storage-Token"] {
        let entry = with_header(name, TOKEN);
        let refusal = redact::admit(&entry).unwrap_err();
        assert!(
            refusal
                .findings
                .iter()
                .any(|finding| finding.reason == redact::Reason::LiveCredentialField
                    && finding.site == redact::Site::RequestHeader(name.to_ascii_lowercase())),
            "{name}: {refusal}"
        );
    }
}

/// Negative — sanitizing redacts the token header and records it, and leaves a neighbouring
/// header whose name merely contains `token` untouched; the sanitized entry is then admitted.
#[test]
fn sanitize_redacts_a_host_token_header_and_keeps_its_neighbours() {
    for name in ["x-auth-token", "x-storage-token"] {
        let mut entry = with_header(name, TOKEN);
        entry.headers.push(("x-auth-token-type".to_owned(), "fernet".to_owned()));
        let touched = redact::sanitize(&mut entry);
        assert_eq!(touched, vec![name], "{name}");
        let value_of = |wanted: &str| {
            entry
                .headers
                .iter()
                .find(|(header, _)| header == wanted)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value_of(name), Some("__REDACTED__"), "{name}");
        assert_eq!(value_of("x-auth-token-type"), Some("fernet"), "{name}");
        assert!(entry.headers.iter().all(|(_, value)| !value.contains(TOKEN)), "{name}");
        redact::admit(&entry).unwrap();
    }
}
