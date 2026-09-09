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

//! The POST-policy parser's focused unit suite.
//!
//! Responsible for: positive proof construction and malformed, expired, mismatched, and bounded
//! policy controls. NOT responsible for: service assembly or multipart transport.
//! Upstream: `super`. Downstream: Cargo's test harness.

use super::*;

const POLICY: &str = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsic3RhcnRzLXdpdGgiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9XX0=";

#[test]
fn c_sig_0417_valid_policy_produces_a_proof_and_final_receipt() {
    let key = SigningKey::from_array([7u8; 32]);
    let signature = hex_encode(&hmac_sha256(key.expose(), POLICY.as_bytes()));
    let fields = valid_fields(&signature);
    let policy = parse(&fields, "../report.txt").expect("valid policy");
    assert_eq!(policy.final_key(), "uploads/report.txt");
    assert!(policy.verify(&key).is_ok());
    assert!(policy.enforce_final("example-bucket", "uploads/report.txt", 1).is_ok());
}

#[test]
fn c_sig_0418_case_only_duplicate_fields_are_rejected() {
    let signature = "0".repeat(64);
    let mut fields = valid_fields(&signature);
    fields.push(("X-Amz-Date", "20150830T123600Z"));
    assert_eq!(parse(&fields, "report.txt").err(), Some(PostPolicyError::Malformed));
}

#[test]
fn c_sig_0419_missing_filename_for_a_template_is_rejected() {
    let signature = "0".repeat(64);
    assert_eq!(parse(&valid_fields(&signature), "").err(), Some(PostPolicyError::ConditionFailed));
}

#[test]
fn c_sig_0420_control_character_in_filename_is_rejected() {
    let signature = "0".repeat(64);
    assert_eq!(parse(&valid_fields(&signature), "bad\0name").err(), Some(PostPolicyError::Malformed));
}

#[test]
fn c_sig_0421_wrong_field_value_is_rejected() {
    let signature = "0".repeat(64);
    let mut fields = valid_fields(&signature);
    fields[1].1 = "other-bucket";
    assert_eq!(parse(&fields, "report.txt").err(), Some(PostPolicyError::ConditionFailed));
}

#[test]
fn c_sig_0422_bad_base64_padding_is_rejected() {
    let signature = "0".repeat(64);
    let mut fields = valid_fields(&signature);
    fields[6].1 = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsic3RhcnRzLXdpdGgiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9XX0gIB==";
    assert_eq!(parse(&fields, "report.txt").err(), Some(PostPolicyError::Malformed));
}

#[test]
fn c_sig_0423_duplicate_json_keys_are_rejected() {
    let signature = "0".repeat(64);
    let mut fields = valid_fields(&signature);
    fields[6].1 = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsic3RhcnRzLXdpdGgiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9XX0=";
    assert_eq!(parse(&fields, "report.txt").err(), Some(PostPolicyError::Malformed));
}

#[test]
fn c_sig_0424_unknown_condition_operators_are_rejected() {
    let signature = "0".repeat(64);
    let mut fields = valid_fields(&signature);
    fields[6].1 = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsiY29udGFpbnMiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9XX0=";
    assert_eq!(parse(&fields, "report.txt").err(), Some(PostPolicyError::Malformed));
}

#[test]
fn c_sig_0425_expired_policy_is_rejected() {
    let signature = "0".repeat(64);
    let fields = valid_fields(&signature);
    let result = PostPolicy::parse(
        &fields,
        "report.txt",
        PostPolicyLimits::default(),
        RequestNow::from_unix_seconds(1_440_941_761),
    );
    assert_eq!(result.err(), Some(PostPolicyError::Expired));
}

#[test]
fn c_sig_0426_wrong_signature_is_rejected() {
    let signature = "0".repeat(64);
    let policy = parse(&valid_fields(&signature), "report.txt").expect("policy shape is valid");
    assert_eq!(
        policy.verify(&SigningKey::from_array([7u8; 32])).err(),
        Some(PostPolicyError::SignatureMismatch)
    );
}

#[test]
fn c_sig_0427_final_size_bounds_are_enforced_both_ways() {
    let signature = "0".repeat(64);
    let mut policy = parse(&valid_fields(&signature), "report.txt").expect("policy shape is valid");
    policy.minimum_file_bytes = 2;
    policy.maximum_file_bytes = 3;
    assert_eq!(
        policy.enforce_final("example-bucket", "uploads/report.txt", 1).err(),
        Some(PostPolicyError::EntityTooSmall)
    );
    assert_eq!(
        policy.enforce_final("example-bucket", "uploads/report.txt", 4).err(),
        Some(PostPolicyError::EntityTooLarge)
    );
}

fn parse(fields: &[(&str, &str)], filename: &str) -> Result<PostPolicy, PostPolicyError> {
    PostPolicy::parse(
        fields,
        filename,
        PostPolicyLimits::default(),
        RequestNow::from_unix_seconds(1_440_938_160),
    )
}

fn valid_fields(signature: &str) -> Vec<(&str, &str)> {
    vec![
        ("key", "uploads/${filename}"),
        ("bucket", "example-bucket"),
        ("x-amz-algorithm", ALGORITHM),
        ("x-amz-credential", "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"),
        ("x-amz-date", "20150830T123600Z"),
        ("x-amz-signature", signature),
        ("policy", POLICY),
    ]
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// `success_action_redirect` construction (rustfs/gateway#656). The helper promises a `Location`
// value a caller can emit without re-checking it, so an authority that is missing or malformed
// must be refused here rather than by every caller.

fn redirect(raw: &str) -> Result<String, PostPolicyError> {
    build_success_action_redirect(raw, "bucket", "key", "\"etag\"", None)
}

#[test]
fn a_redirect_with_an_authority_gains_its_parameters_before_the_fragment() {
    assert_eq!(
        redirect("https://example.com/done?x=1#top").expect("a valid redirect"),
        "https://example.com/done?x=1&bucket=bucket&key=key&etag=%22etag%22#top"
    );
    assert_eq!(
        redirect("http://example.com:8080").expect("a bare authority with a port"),
        "http://example.com:8080?bucket=bucket&key=key&etag=%22etag%22"
    );
    assert_eq!(
        redirect("https://[::1]:8443/cb").expect("an IPv6 literal with a port"),
        "https://[::1]:8443/cb?bucket=bucket&key=key&etag=%22etag%22"
    );
}

#[test]
fn a_redirect_without_an_authority_is_malformed() {
    for raw in [
        "https:///missing-host",
        "https://",
        "https://?x=1",
        "https://#top",
        "https://:8443/path",
        "http:///",
    ] {
        assert_eq!(redirect(raw).err(), Some(PostPolicyError::Malformed), "{raw}");
    }
}

#[test]
fn a_redirect_with_a_malformed_authority_is_malformed() {
    for raw in [
        "https://exa mple.com/",
        "https://example.com:port/",
        "https://example.com:80 80/",
        "https://[::1/",
        "https://[]/",
        "https://[::1]x/",
        "https://exam<ple.com/",
        "https://exam\"ple.com/",
        "https://exam^ple.com/",
        "https://exam|ple.com/",
        "https://exam{ple}.com/",
    ] {
        assert_eq!(redirect(raw).err(), Some(PostPolicyError::Malformed), "{raw}");
    }
}

#[test]
fn a_redirect_with_userinfo_is_malformed() {
    // `allowed.example:x@evil.com` reads as host `allowed.example` to a naive port split while a
    // browser goes to `evil.com`; userinfo has no place in a redirect target, so it is refused.
    for raw in [
        "https://user@example.com/",
        "https://user:secret@example.com/",
        "https://allowed.example:x@evil.com/",
    ] {
        assert_eq!(redirect(raw).err(), Some(PostPolicyError::Malformed), "{raw}");
    }
}

#[test]
fn the_host_allowlist_compares_the_host_alone() {
    let allowed = Some(["Example.COM", "[::1]"].as_slice());
    let permitted = |raw: &str| build_success_action_redirect(raw, "b", "k", "e", allowed);
    assert!(permitted("https://example.com:8443/cb").is_ok());
    assert!(permitted("https://[::1]/cb").is_ok());
    assert!(permitted("https://[::1]:8443/cb").is_ok());
    assert_eq!(permitted("https://example.com.evil/cb").err(), Some(PostPolicyError::Malformed));
    assert_eq!(permitted("https://[::2]/cb").err(), Some(PostPolicyError::Malformed));
    assert_eq!(permitted("https://example.com:x@evil.com/cb").err(), Some(PostPolicyError::Malformed));
}
