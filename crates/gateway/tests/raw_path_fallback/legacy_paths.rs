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

//! Explicit RustFS path compatibility through header and query authentication (#1314, #1315).
//!
//! Responsible for: signed, forged, unknown-key, query and default-mode boundaries.
//! NOT responsible for: the candidate codec's unit-level byte matrix.
//! Upstream: the parent independent signer and production service. Downstream: Cargo tests.

use super::*;

fn assembly(literal: bool) -> (S3Service, Arc<Mutex<Vec<String>>>) {
    let keys = Arc::new(Mutex::new(Vec::new()));
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("fixture")));
    let mut auth = SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("region"));
    if literal {
        auth = auth.verify_paths_as_legacy_rustfs();
    }
    let service = ServiceBuilder::new()
        .authenticator(auth)
        .authorizer(allow_when(|_| true))
        .address_paths_as_legacy_rustfs()
        .accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report()
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::GetObject, _>(Arc::new(Backend(Arc::clone(&keys))))
        .build()
        .expect("assembly");
    (service, keys)
}

fn presigned(wire: &str, signed: &str) -> http::Request<Bytes> {
    let stamp = support::SIGNED_AT_STAMP;
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F{day}%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date={stamp}&X-Amz-Expires=60&X-Amz-SignedHeaders=host"
    );
    let canonical = format!("GET\n{signed}\n{query}\nhost:s3.example.com\n\nhost\nUNSIGNED-PAYLOAD");
    let to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac_sha256(b"AWS4secret", day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));
    http::Request::builder()
        .uri(format!("{wire}?{query}&X-Amz-Signature={signature}"))
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("fixture")
}

const PATHS: [(&str, &str, &str); 5] = [
    ("/bucket/bad%zz", "/bucket/bad%25zz", "bad%zz"),
    ("/bucket/bad%", "/bucket/bad%25", "bad%"),
    ("/bucket/bad%2", "/bucket/bad%252", "bad%2"),
    ("/bucket/a%20b%zz", "/bucket/a%20b%25zz", "a b%zz"),
    ("/bucket/%%41", "/bucket/%25A", "%A"),
];

type Sign = fn(&str, &str) -> http::Request<Bytes>;
const SIGNERS: [Sign; 2] = [get, presigned];
const SEPARATORS: [(&str, &str, &str); 4] = [
    ("/bucket/a%2Fb", "/bucket/a/b", "a/b"),
    ("/bucket/a%2fb", "/bucket/a/b", "a/b"),
    ("/bucket/a%2Fb%zz", "/bucket/a/b%25zz", "a/b%zz"),
    ("/bucket/a%252Fb", "/bucket/a%252Fb", "a%2Fb"),
];

#[tokio::test]
async fn legacy_paths_reach_the_handler_only_after_signature_verification() {
    for sign in SIGNERS {
        for (wire, signed, key) in PATHS.into_iter().chain(SEPARATORS) {
            let (service, keys) = assembly(true);
            let (status, body) = support::exchange(&service, sign(wire, signed)).await;
            assert_eq!(status, http::StatusCode::OK, "{wire}: {body}");
            assert_eq!(*keys.lock().expect("record"), [key.to_owned()]);
        }
    }
}

#[tokio::test]
async fn n_default_authentication_still_refuses_literal_percent() {
    for sign in SIGNERS {
        for (wire, signed, _) in PATHS {
            let (service, keys) = assembly(false);
            let (status, body) = support::exchange(&service, sign(wire, signed)).await;
            assert_eq!(status, http::StatusCode::BAD_REQUEST, "{wire}: {body}");
            assert!(body.contains("<Code>AuthorizationHeaderMalformed</Code>"), "{body}");
            assert!(keys.lock().expect("record").is_empty());
        }
    }
}

#[tokio::test]
async fn n_forged_and_raw_spelling_signatures_do_not_reach_the_handler() {
    for sign in SIGNERS {
        for (wire, _, _) in PATHS {
            for signed in ["/bucket/wrong", wire] {
                let (service, keys) = assembly(true);
                let (status, body) = support::exchange(&service, sign(wire, signed)).await;
                assert_eq!(status, http::StatusCode::FORBIDDEN, "{wire}: {body}");
                assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
                assert!(keys.lock().expect("record").is_empty());
            }
        }
    }
}

#[tokio::test]
async fn n_unknown_credentials_do_not_reach_the_handler() {
    for sign in SIGNERS {
        let (service, keys) = assembly(true);
        let mut request = sign("/bucket/bad%zz", "/bucket/bad%25zz");
        if let Some(header) = request.headers_mut().get_mut(http::header::AUTHORIZATION) {
            *header = header
                .to_str()
                .expect("text")
                .replace("AKIDEXAMPLE", "UNKNOWNKEY")
                .parse()
                .expect("header");
        } else {
            *request.uri_mut() = request
                .uri()
                .to_string()
                .replace("AKIDEXAMPLE", "UNKNOWNKEY")
                .parse()
                .expect("uri");
        }
        let (status, body) = support::exchange(&service, request).await;
        assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("<Code>InvalidAccessKeyId</Code>"), "{body}");
        assert!(keys.lock().expect("record").is_empty());
    }
}

#[tokio::test]
async fn n_path_compatibility_never_relaxes_query_percent_decoding() {
    for sign in SIGNERS {
        for (query, code) in [
            ("bad=%zz", "AuthorizationHeaderMalformed"),
            ("bad=%", "AuthorizationHeaderMalformed"),
            ("%zz=value", "InvalidArgument"),
        ] {
            let (service, keys) = assembly(true);
            let mut request = sign("/bucket/bad%zz", "/bucket/bad%25zz");
            let separator = if request.uri().query().is_some() { '&' } else { '?' };
            *request.uri_mut() = format!("{}{separator}{query}", request.uri()).parse().expect("uri");
            let (status, body) = support::exchange(&service, request).await;
            assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
            assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
            assert!(keys.lock().expect("record").is_empty());
        }
    }
}

#[tokio::test]
async fn n_legacy_paths_refuse_signatures_over_encoded_separators() {
    for sign in SIGNERS {
        for (wire, signed) in [
            ("/bucket/a%2Fb", "/bucket/a%2Fb"),
            ("/bucket/a%2fb", "/bucket/a%2Fb"),
            ("/bucket/a%2Fb%zz", "/bucket/a%2Fb%25zz"),
        ] {
            let (service, keys) = assembly(true);
            let (status, body) = support::exchange(&service, sign(wire, signed)).await;
            assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
            assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
            assert!(keys.lock().expect("record").is_empty());
        }
    }
}

#[tokio::test]
async fn n_default_paths_keep_the_encoded_separator_contract() {
    for sign in SIGNERS {
        let (service, keys) = assembly(false);
        let (status, body) = support::exchange(&service, sign("/bucket/a%2Fb", "/bucket/a%2Fb")).await;
        assert_eq!(status, http::StatusCode::OK, "{body}");
        assert_eq!(*keys.lock().expect("record"), ["a/b"]);
    }
}
