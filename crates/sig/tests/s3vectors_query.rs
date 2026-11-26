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

//! S3 Vectors list-valued query signing through the public signer.
//!
//! Responsible for: preserving every tagKeys value, encoded ordering and exact service isolation.
//! NOT responsible for: HTTP operation registration or signature verification in the gateway.
//! Upstream: SigningScope and SigV4Signer. Downstream: the integration test runner.

use http::{HeaderMap, Method};
use rustfs_gateway_sig::{
    AmzDate, PayloadMode, QueryExclusion, RawHost, RawQuery, ScopeDate, SigService, SigV4Signer, SignerError, SigningCredentials,
    SigningRequest, SigningScope,
};

fn canonical_query(service: SigService, query: &str) -> Result<String, SignerError> {
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("synthetic credentials");
    let scope = SigningScope::new(ScopeDate::parse("20150830").expect("a date"), "us-east-1", service)
        .expect("a supported signing scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let headers = HeaderMap::new();
    let host = RawHost::from_host_header(b"vectors.example.com").expect("a host");
    let request = SigningRequest::new(
        &Method::DELETE,
        "/tags/resource",
        query,
        &headers,
        &host,
        PayloadMode::Empty,
        AmzDate::parse("20150830T123600Z").expect("a timestamp"),
    );
    signer.sign_headers(&request).map(|signed| {
        signed
            .canonical_request()
            .lines()
            .nth(2)
            .expect("the canonical request contains a query line")
            .to_owned()
    })
}

#[test]
fn s3vectors_tag_keys_sort_by_encoded_value_independently_of_wire_order() {
    for (query, expected) in [
        ("tagKeys=~&tagKeys=z&tagKeys=%20", "tagKeys=%20&tagKeys=z&tagKeys=~"),
        ("tagKeys=z&tagKeys=%20&tagKeys=~", "tagKeys=%20&tagKeys=z&tagKeys=~"),
        ("tagKeys=%C3%A9&tagKeys=z", "tagKeys=%C3%A9&tagKeys=z"),
        ("tagKeys=z&tagKeys=%C3%A9", "tagKeys=%C3%A9&tagKeys=z"),
    ] {
        assert_eq!(canonical_query(SigService::S3Vectors, query).expect("a list-valued query"), expected);
    }
}

#[test]
fn s3vectors_tag_keys_preserve_repeated_values() {
    assert_eq!(
        canonical_query(SigService::S3Vectors, "tagKeys=b&tagKeys=a&tagKeys=a").expect("repeated list values"),
        "tagKeys=a&tagKeys=a&tagKeys=b"
    );
}

#[test]
fn s3vectors_tag_keys_accept_percent_encoded_name_aliases() {
    assert_eq!(
        canonical_query(SigService::S3Vectors, "tag%4Beys=b&%74agKeys=a").expect("the same decoded list name"),
        "tagKeys=a&tagKeys=b"
    );
}

#[test]
fn n_default_canonical_query_keeps_rejecting_duplicate_tag_keys() {
    assert!(RawQuery::new("tagKeys=a&tagKeys=b").canonical(QueryExclusion::None).is_err());
}

#[test]
fn n_s3_signer_rejects_duplicate_tag_keys() {
    assert!(canonical_query(SigService::S3, "tagKeys=a&tagKeys=b").is_err());
}

#[test]
fn n_other_service_signers_reject_duplicate_tag_keys() {
    for service in [
        SigService::Sts,
        SigService::S3Express,
        SigService::S3ObjectLambda,
        SigService::S3Outposts,
    ] {
        assert!(canonical_query(service, "tagKeys=a&tagKeys=b").is_err(), "service {service}");
    }
}

#[test]
fn n_s3vectors_rejects_duplicate_names_other_than_tag_keys() {
    for name in ["other", "resourceArn", "TagKeys", "tagkeys", "tagKeys[]"] {
        assert!(
            canonical_query(SigService::S3Vectors, &format!("{name}=a&{name}=b")).is_err(),
            "name {name}"
        );
    }
}

#[test]
fn n_s3vectors_rejects_duplicate_signing_parameters() {
    for name in [
        "X-Amz-Algorithm",
        "X-Amz-Credential",
        "X-Amz-Date",
        "X-Amz-Expires",
        "X-Amz-SignedHeaders",
        "X-Amz-Signature",
        "X-Amz-Security-Token",
    ] {
        assert!(
            canonical_query(SigService::S3Vectors, &format!("{name}=a&{name}=b")).is_err(),
            "name {name}"
        );
    }
}

#[test]
fn n_s3vectors_rejects_encoded_aliases_of_other_duplicate_names() {
    for query in ["other=a&%6Fther=b", "X-Amz-Date=a&X-Amz-%44ate=b", "TagKeys=a&Tag%4Beys=b"] {
        assert!(canonical_query(SigService::S3Vectors, query).is_err(), "query {query}");
    }
}

#[test]
fn n_s3vectors_rejects_malformed_list_queries() {
    for query in ["tagKeys=a&tagKeys=%zz", "tagKeys=a&&tagKeys=b", "tagKeys=a&=b", "tagKeys=a&"] {
        assert!(canonical_query(SigService::S3Vectors, query).is_err(), "query {query}");
    }
}

fn sign_canonical(service: SigService, method: &Method, path: &str, query: &str) -> Result<String, SignerError> {
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("synthetic credentials");
    let scope = SigningScope::new(ScopeDate::parse("20150830").expect("a date"), "us-east-1", service)
        .expect("a supported signing scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let headers = HeaderMap::new();
    let host = RawHost::from_host_header(b"vectors.example.com").expect("a host");
    let request = SigningRequest::new(
        method,
        path,
        query,
        &headers,
        &host,
        PayloadMode::Empty,
        AmzDate::parse("20150830T123600Z").expect("a timestamp"),
    );
    signer
        .sign_headers(&request)
        .map(|signed| signed.canonical_request().to_owned())
}

#[test]
fn s3vectors_signer_double_encodes_tag_resource_arn_canonical_path() {
    let raw_path = "/tags/arn%3Aaws%3As3vectors%3Aus-east-1%3A123456789012%3Abucket%2Fmy-bucket";
    let canonical = sign_canonical(SigService::S3Vectors, &Method::GET, raw_path, "").expect("s3vectors signed");
    let canonical_uri = canonical.lines().nth(1).expect("canonical URI line");
    assert_eq!(
        canonical_uri,
        "/tags/arn%253Aaws%253As3vectors%253Aus-east-1%253A123456789012%253Abucket%252Fmy-bucket"
    );

    let action = sign_canonical(SigService::S3Vectors, &Method::POST, "/PutVectors", "").expect("action signed");
    assert_eq!(action.lines().nth(1).expect("canonical URI line"), "/PutVectors");
}

#[test]
fn n_s3_and_s3express_signers_keep_single_encoded_canonical_path() {
    let raw_path = "/tags/arn%3Aaws%3As3vectors%3Aus-east-1%3A123456789012%3Abucket%2Fmy-bucket";
    for service in [SigService::S3, SigService::S3Express] {
        let canonical = sign_canonical(service, &Method::GET, raw_path, "").expect("s3-family signed");
        let canonical_uri = canonical.lines().nth(1).expect("canonical URI line");
        assert_eq!(canonical_uri, raw_path, "service {service} must keep single-encoding");
    }
}

#[test]
fn s3vectors_signer_accepts_repeated_tag_keys_on_delete_tags_arn() {
    let raw_path = "/tags/arn%3Aaws%3As3vectors%3Aus-east-1%3A123456789012%3Abucket%2Fmy-bucket";
    let canonical = sign_canonical(SigService::S3Vectors, &Method::DELETE, raw_path, "tagKeys=b&tagKeys=a")
        .expect("UntagResource allows repeated tagKeys");
    assert_eq!(
        canonical.lines().nth(1).expect("canonical URI"),
        "/tags/arn%253Aaws%253As3vectors%253Aus-east-1%253A123456789012%253Abucket%252Fmy-bucket"
    );
    assert_eq!(canonical.lines().nth(2).expect("canonical query"), "tagKeys=a&tagKeys=b");
}

#[test]
fn n_s3vectors_signer_rejects_repeated_tag_keys_on_non_untag_routes() {
    for (method, path) in [
        (Method::POST, "/PutVectors"),
        (Method::GET, "/tags/resource"),
        (Method::POST, "/tags/resource"),
        (Method::PUT, "/tags/resource"),
        (Method::DELETE, "/PutVectors"),
        (Method::DELETE, "/tags"),
        (Method::DELETE, "/tags/"),
        (Method::DELETE, "/tags///"),
    ] {
        assert!(
            sign_canonical(SigService::S3Vectors, &method, path, "tagKeys=a&tagKeys=b").is_err(),
            "repeated tagKeys must be rejected on {method} {path}"
        );
    }
}
