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

//! Live AWS SDK for JavaScript v3 Website source-(b) captures.
//!
//! Responsible for: binding three semantic SDK captures to byte-exact provenance.
//! NOT responsible for: SDK execution, persistence export, or website request routing.
//! Upstream: official SDK against disposable RustFS. Downstream: Website corpus and census.

use rustfs_gateway_types::persistence::{
    PersistedErrorDocument, PersistedIndexDocument, PersistedRedirect, PersistedRedirectAllRequestsTo, PersistedRoutingRule,
    PersistedRoutingRuleCondition, PersistedWebsiteConfiguration,
};
#[cfg(test)]
use sha2::{Digest, Sha256};

use crate::{ConfigKind, CorpusVariant, GoldenSample, SampleOrigin};

const DOCUMENTS_XML: &[u8] = b"<WebsiteConfiguration><ErrorDocument><Key>errors/js-v3.html</Key></ErrorDocument><IndexDocument><Suffix>landing-js-v3.html</Suffix></IndexDocument></WebsiteConfiguration>";
const REDIRECT_ALL_XML: &[u8] = b"<WebsiteConfiguration><RedirectAllRequestsTo><HostName>static-js-v3.example.test</HostName><Protocol>https</Protocol></RedirectAllRequestsTo></WebsiteConfiguration>";
const ROUTING_RULE_XML: &[u8] = b"<WebsiteConfiguration><IndexDocument><Suffix>home-js-v3.html</Suffix></IndexDocument><RoutingRules><RoutingRule><Condition><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals><KeyPrefixEquals>legacy-js-v3/</KeyPrefixEquals></Condition><Redirect><HostName>docs-js-v3.example.test</HostName><HttpRedirectCode>307</HttpRedirectCode><Protocol>https</Protocol><ReplaceKeyPrefixWith>current-js-v3/</ReplaceKeyPrefixWith></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>";
const DOCUMENTS_SHA256: &str = "c6c23366c1dfea9ff0cc9af328d00c2815ccd303e2fa5ccbeeb5c4172ac9400e";
const REDIRECT_ALL_SHA256: &str = "a696deccf0ecfc0c2e1b4198b96bfb6eaafffc3a257f525b4bd46bca3747299c";
const ROUTING_RULE_SHA256: &str = "400b7e7d870d7d54dcb9b118083e3da204d6bdeaba87a05b8d2102a737b3f424";
const DOCUMENTS_METADATA_SHA256: &str = "4d3ee2a8c07a5063e08e6de844a8d9f52f0666344185d007fbe8ce21607cdcf9";
const REDIRECT_ALL_METADATA_SHA256: &str = "c4f17319e475ab64543322a63dbf7f8cc546d4d66fa268354e927d09fc7c118e";
const ROUTING_RULE_METADATA_SHA256: &str = "10a90959f3ef9459e6fe91716066492ccbe8318788c2e93b3565307d10521b2e";
const CANONICAL_VARIANT: &[CorpusVariant] = &[CorpusVariant::Canonical];

fn origin(sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: "Source-(b) live AWS SDK for JavaScript v3 Website capture".to_owned(),
        producer: "official AWS SDK for JavaScript v3 against disposable RustFS; rustfs-cli offline raw export".to_owned(),
        version: crate::source_b_js_v3::CAPTURE_VERSION.to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn sample(
    bytes: &[u8],
    sha256: &str,
    value: PersistedWebsiteConfiguration,
    notes: String,
) -> (GoldenSample<PersistedWebsiteConfiguration>, &'static [CorpusVariant]) {
    (
        GoldenSample {
            kind: ConfigKind::Website,
            bytes: bytes.to_vec(),
            value,
            origin: origin(sha256),
            notes,
        },
        CANONICAL_VARIANT,
    )
}

pub(crate) fn cases() -> Vec<(GoldenSample<PersistedWebsiteConfiguration>, &'static [CorpusVariant])> {
    vec![
        sample(
            DOCUMENTS_XML,
            DOCUMENTS_SHA256,
            PersistedWebsiteConfiguration {
                error_document: Some(PersistedErrorDocument {
                    key: "errors/js-v3.html".to_owned(),
                }),
                index_document: Some(PersistedIndexDocument {
                    suffix: "landing-js-v3.html".to_owned(),
                }),
                ..PersistedWebsiteConfiguration::default()
            },
            format!(
                "byte-exact index/error Website XML persisted after SDK Put and confirmed by SDK Get; raw metadata SHA-256 {DOCUMENTS_METADATA_SHA256}"
            ),
        ),
        sample(
            REDIRECT_ALL_XML,
            REDIRECT_ALL_SHA256,
            PersistedWebsiteConfiguration {
                redirect_all_requests_to: Some(PersistedRedirectAllRequestsTo {
                    host_name: "static-js-v3.example.test".to_owned(),
                    protocol: Some("https".to_owned()),
                }),
                ..PersistedWebsiteConfiguration::default()
            },
            format!(
                "byte-exact redirect-all Website XML persisted after SDK Put and confirmed by SDK Get; raw metadata SHA-256 {REDIRECT_ALL_METADATA_SHA256}"
            ),
        ),
        sample(
            ROUTING_RULE_XML,
            ROUTING_RULE_SHA256,
            PersistedWebsiteConfiguration {
                index_document: Some(PersistedIndexDocument {
                    suffix: "home-js-v3.html".to_owned(),
                }),
                routing_rules: Some(vec![PersistedRoutingRule {
                    condition: Some(PersistedRoutingRuleCondition {
                        http_error_code_returned_equals: Some("404".to_owned()),
                        key_prefix_equals: Some("legacy-js-v3/".to_owned()),
                    }),
                    redirect: PersistedRedirect {
                        host_name: Some("docs-js-v3.example.test".to_owned()),
                        http_redirect_code: Some("307".to_owned()),
                        protocol: Some("https".to_owned()),
                        replace_key_prefix_with: Some("current-js-v3/".to_owned()),
                        replace_key_with: None,
                    },
                }]),
                ..PersistedWebsiteConfiguration::default()
            },
            format!(
                "byte-exact conditional-routing Website XML persisted after SDK Put and confirmed by SDK Get; raw metadata SHA-256 {ROUTING_RULE_METADATA_SHA256}"
            ),
        ),
    ]
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct CaptureBinding {
    label: &'static str,
    bytes: &'static [u8],
    sha256: &'static str,
    metadata_sha256: &'static str,
}

#[cfg(test)]
fn capture_bindings() -> [CaptureBinding; 3] {
    [
        CaptureBinding {
            label: "documents-concrete",
            bytes: DOCUMENTS_XML,
            sha256: DOCUMENTS_SHA256,
            metadata_sha256: DOCUMENTS_METADATA_SHA256,
        },
        CaptureBinding {
            label: "redirect-all-concrete",
            bytes: REDIRECT_ALL_XML,
            sha256: REDIRECT_ALL_SHA256,
            metadata_sha256: REDIRECT_ALL_METADATA_SHA256,
        },
        CaptureBinding {
            label: "routing-rule-concrete",
            bytes: ROUTING_RULE_XML,
            sha256: ROUTING_RULE_SHA256,
            metadata_sha256: ROUTING_RULE_METADATA_SHA256,
        },
    ]
}

#[cfg(test)]
fn validate_census(captures: &[CaptureBinding]) -> Result<(), String> {
    if captures.len() != 3 {
        return Err(format!("expected 3 JavaScript v3 Website captures, found {}", captures.len()));
    }
    for capture in captures {
        let observed = hex::encode(Sha256::digest(capture.bytes));
        if observed != capture.sha256 {
            return Err(format!("raw export SHA-256 mismatch for {}", capture.label));
        }
        if capture.metadata_sha256.len() != 64 || !capture.metadata_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("invalid metadata SHA-256 for {}", capture.label));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_javascript_v3_website_captures_are_registered() {
        let registered = capture_bindings();
        validate_census(&registered).expect("the JavaScript v3 Website census must be byte-exact");
        assert_eq!(
            registered.map(|capture| capture.label),
            ["documents-concrete", "redirect-all-concrete", "routing-rule-concrete"]
        );
        assert_eq!(registered.map(|capture| capture.bytes.len()), [170, 164, 487]);
        assert_eq!(cases().len(), 3);
    }

    #[test]
    fn census_rejects_a_stale_raw_export_digest() {
        let mut stale = capture_bindings();
        stale[0].sha256 = "d6c23366c1dfea9ff0cc9af328d00c2815ccd303e2fa5ccbeeb5c4172ac9400e";
        let error = validate_census(&stale).expect_err("a stale Website digest must fail closed");
        assert!(error.contains("documents-concrete"));
        assert!(error.contains("SHA-256 mismatch"));
    }

    #[test]
    fn census_rejects_a_non_hex_metadata_digest() {
        let mut stale = capture_bindings();
        stale[2].metadata_sha256 = "z0a90959f3ef9459e6fe91716066492ccbe8318788c2e93b3565307d10521b2e";
        let error = validate_census(&stale).expect_err("a malformed metadata digest must fail closed");
        assert!(error.contains("routing-rule-concrete"));
        assert!(error.contains("metadata SHA-256"));
    }
}
