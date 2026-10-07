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

//! RustFS's table catalog paths signed as generic AWS SigV4 signs them (rustfs/gateway#1232,
//! rustfs/rustfs#8291), through the whole service.
//!
//! Responsible for: a botocore capture reaching the catalog through the `rustfs` dialect under
//! `SigV4Authenticator::verify_paths_double_encoded_under` and refused without it; both published
//! prefixes, path-style and virtual-hosted; forged and unknown credentials; and the switch leaving
//! a request no claim took — an S3 object whose key starts with a prefix — verified as before.
//! NOT responsible for: the candidate's exact bytes (`rustfs-gateway-sig`'s `legacy_paths` tests),
//! the prefix boundary (`ext::authenticator_switches`'s unit test), or routing every catalog
//! operation (goldens' `rustfs_admin_dialect`).
//! Upstream: the parent's independent signer and production service. Downstream: Cargo tests.

use super::*;
use rustfs_gateway::{FixedClock, LegacyRustfsVirtualHosts};
use rustfs_gateway_dialect_rustfs_admin::ops::get_iceberg_by_warehouse_namespaces_by_namespace_tables_by_table::GetIcebergByWarehouseNamespacesByNamespaceTablesByTable as LoadTable;
use rustfs_gateway_dialect_rustfs_admin::{AdminResponse, TABLE_CATALOG_PREFIXES, rustfs_admin_dialect};

/// Every key the `GetObject` handler read, and an S3 service with no dialect: the RustFS profile's
/// path and key readings, and the table catalog's switch.
fn assembly(clock: FixedClock, access: &str, secret: &[u8]) -> (S3Service, Arc<Mutex<Vec<String>>>) {
    let keys = Arc::new(Mutex::new(Vec::new()));
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new(access, secret).expect("fixture")));
    let auth = SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("region"))
        .verify_paths_as_legacy_rustfs()
        .verify_paths_double_encoded_under(TABLE_CATALOG_PREFIXES);
    let service = ServiceBuilder::new()
        .authenticator(auth)
        .authorizer(allow_when(|_| true))
        .address_paths_as_legacy_rustfs()
        .accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report()
        .clock_with_skew_ack(clock, ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .register::<dto::GetObject, _>(Arc::new(Backend(Arc::clone(&keys))))
        .build()
        .expect("assembly");
    (service, keys)
}

fn signed_assembly() -> (S3Service, Arc<Mutex<Vec<String>>>) {
    assembly(support::fixed_clock(), "AKIDEXAMPLE", b"secret")
}

/// The request rustfs/rustfs#8291 pins, captured from botocore's `SigV4Auth` independently of any
/// server signer (`rustfs/src/admin/router.rs`, `iceberg_metadata_probe_passes_sigv4_verification`,
/// rustfs/rustfs `95268a3b9`), signed at 2020-01-01T00:00:00Z.
fn botocore_capture() -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::GET)
        .uri("/iceberg/v1/warehouse/namespaces/ods%1Fkfk_log_order/tables/files")
        .header(http::header::HOST, "catalog.example:9000")
        .header(http::header::CONTENT_TYPE, "application/json")
        .header("x-amz-date", "20200101T000000Z")
        .header("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .header(
            http::header::AUTHORIZATION,
            concat!(
                "AWS4-HMAC-SHA256 Credential=catalog-test-access/20200101/us-east-1/s3/aws4_request, ",
                "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, ",
                "Signature=38357111b8355d0efdc6746cc5e94930c455d2f6741ea38c65e6556fe45d882d"
            ),
        )
        .body(Bytes::new())
        .expect("the capture")
}

fn capture_assembly() -> (S3Service, Arc<Mutex<Vec<String>>>) {
    assembly(FixedClock::at_unix_seconds(1_577_836_800), "catalog-test-access", b"catalog-test-secret")
}

/// A presigned `GET` of `wire`, its canonical path spelled `signed`.
fn presigned_get(wire: &str, signed: &str) -> http::Request<Bytes> {
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

type Sign = fn(&str, &str) -> http::Request<Bytes>;
const SIGNERS: [Sign; 2] = [get, presigned_get];

/// (wire path, its doubly encoded spelling, its S3 spelling, the key the handler reads).
const CATALOG_PATHS: [(&str, &str, &str, &str); 4] = [
    ("/iceberg/v1/ns%20x", "/iceberg/v1/ns%2520x", "/iceberg/v1/ns%20x", "v1/ns x"),
    ("/iceberg/v1/a%1Fb/t", "/iceberg/v1/a%251Fb/t", "/iceberg/v1/a%1Fb/t", "v1/a\u{1f}b/t"),
    ("/iceberg/v1/a+b", "/iceberg/v1/a%2Bb", "/iceberg/v1/a%2Bb", "v1/a+b"),
    ("/iceberg/v1/%7E", "/iceberg/v1/%257E", "/iceberg/v1/~", "v1/~"),
];

/// Negative — no claim takes these requests (no dialect is installed), so the switch changes
/// nothing: an S3 object whose key starts with a catalog prefix is verified as S3 signs it, header
/// or presigned, and its doubly encoded spelling is refused; the botocore capture, a catalog
/// request, is refused too.
#[tokio::test]
async fn n_an_unclaimed_request_under_a_prefix_is_verified_as_s3_signs_it() {
    for sign in SIGNERS {
        for (wire, double, s3, key) in CATALOG_PATHS {
            let (service, keys) = signed_assembly();
            let (status, body) = support::exchange(&service, sign(wire, s3)).await;
            assert_eq!(status, http::StatusCode::OK, "{wire} signed as {s3}: {body}");
            assert_eq!(*keys.lock().expect("record"), [key.to_owned()], "{wire}");
            if double == s3 {
                continue;
            }
            let (service, keys) = signed_assembly();
            let (status, body) = support::exchange(&service, sign(wire, double)).await;
            assert_eq!(status, http::StatusCode::FORBIDDEN, "{wire} signed as {double}: {body}");
            assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
            assert!(keys.lock().expect("record").is_empty(), "{wire}");
        }
    }
    let (service, keys) = capture_assembly();
    let (status, body) = support::exchange(&service, botocore_capture()).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(keys.lock().expect("record").is_empty());
}

// ── through the `rustfs` dialect ────────────────────────────────────────────────────────────────

/// The parameters the table catalog's `LoadTable` handler was handed, in order.
type Handed = Arc<Mutex<Vec<(String, String)>>>;

struct Catalog(Handed);

impl Handler<LoadTable> for Catalog {
    async fn call(&self, request: Req<LoadTable>) -> HandlerResult<LoadTable> {
        let params = request
            .context()
            .path_params()
            .iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()));
        self.0.lock().expect("record").extend(params);
        Ok(Resp::new(AdminResponse::json("{}")))
    }
}

/// The RustFS profile's path and host readings with the `rustfs` dialect and a `LoadTable`
/// handler, the table catalog's switch on its published prefixes when `catalog` is set.
fn dialect_assembly(catalog: bool, clock: FixedClock, access: &str, secret: &[u8]) -> (S3Service, Handed) {
    let handed = Arc::new(Mutex::new(Vec::new()));
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new(access, secret).expect("fixture")));
    let mut auth =
        SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("region")).verify_paths_as_legacy_rustfs();
    if catalog {
        auth = auth.verify_paths_double_encoded_under(TABLE_CATALOG_PREFIXES);
    }
    let dialect = rustfs_admin_dialect().expect("the generated dialect");
    let service = ServiceBuilder::new()
        .authenticator(auth)
        .authorizer(allow_when(|_| true))
        .address_paths_as_legacy_rustfs()
        .host_resolver(LegacyRustfsVirtualHosts::new(["s3.example.com"]).expect("a base domain"))
        .clock_with_skew_ack(clock, ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .dialect(&dialect)
        .register::<LoadTable, _>(Arc::new(Catalog(Arc::clone(&handed))))
        .build()
        .expect("assembly");
    (service, handed)
}

fn handed(warehouse: &str, namespace: &str, table: &str) -> Vec<(String, String)> {
    [("warehouse", warehouse), ("namespace", namespace), ("table", table)]
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .to_vec()
}

/// Positive — the capture rustfs/rustfs#8291 pins reaches the table catalog's `LoadTable` through
/// the `rustfs` dialect under the switch, its two-level namespace `ods%1Fkfk_log_order` handed
/// over as one opaque segment (ADR-0040).
#[tokio::test]
async fn the_botocore_capture_reaches_the_table_catalog_through_the_dialect() {
    let at = FixedClock::at_unix_seconds(1_577_836_800);
    let (service, catalog) = dialect_assembly(true, at, "catalog-test-access", b"catalog-test-secret");
    let (status, body) = support::exchange(&service, botocore_capture()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(*catalog.lock().expect("record"), handed("warehouse", "ods\u{1f}kfk_log_order", "files"));
}

/// Negative — without the switch the same capture is `403 SignatureDoesNotMatch` and nothing runs:
/// neither the S3 nor the legacy spelling of its path is what botocore signed.
#[tokio::test]
async fn n_the_botocore_capture_is_refused_without_the_switch() {
    let at = FixedClock::at_unix_seconds(1_577_836_800);
    let (service, catalog) = dialect_assembly(false, at, "catalog-test-access", b"catalog-test-secret");
    let (status, body) = support::exchange(&service, botocore_capture()).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    assert!(catalog.lock().expect("record").is_empty());
}

/// Positive and negative — both published prefixes, header-signed (every catalog row's floor
/// refuses a presigned URL, as goldens' `n_a_presigned_row_is_refused_without_asking` pins): the
/// doubly encoded spelling reaches `LoadTable` with the namespace's levels joined by `\u{1f}`, and
/// the S3 spelling is refused before anything runs.
#[tokio::test]
async fn both_catalog_prefixes_verify_the_doubly_encoded_spelling_through_the_dialect() {
    for prefix in TABLE_CATALOG_PREFIXES {
        let wire = format!("{prefix}/lakehouse/namespaces/a%1Fb/tables/t");
        let double = format!("{prefix}/lakehouse/namespaces/a%251Fb/tables/t");
        let (service, catalog) = dialect_assembly(true, support::fixed_clock(), "AKIDEXAMPLE", b"secret");
        let (status, body) = support::exchange(&service, get(&wire, &double)).await;
        assert_eq!(status, http::StatusCode::OK, "{wire}: {body}");
        assert_eq!(*catalog.lock().expect("record"), handed("lakehouse", "a\u{1f}b", "t"), "{wire}");
        let (service, catalog) = dialect_assembly(true, support::fixed_clock(), "AKIDEXAMPLE", b"secret");
        let (status, body) = support::exchange(&service, get(&wire, &wire)).await;
        assert_eq!(status, http::StatusCode::FORBIDDEN, "{wire}: {body}");
        assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{wire}: {body}");
        assert!(catalog.lock().expect("record").is_empty(), "{wire}");
    }
}

/// A header-signed `GET` of `wire` on `host`, its canonical path spelled `signed`.
fn get_on(host: &str, wire: &str, signed: &str) -> http::Request<Bytes> {
    let mut request = get(wire, signed);
    let stamp = support::SIGNED_AT_STAMP;
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let payload = "UNSIGNED-PAYLOAD";
    let canonical = format!(
        "GET\n{signed}\n\nhost:{host}\nx-amz-content-sha256:{payload}\nx-amz-date:{stamp}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload}"
    );
    let to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac_sha256(b"AWS4secret", day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));
    let headers = request.headers_mut();
    headers.insert(http::header::HOST, host.parse().expect("a host"));
    headers.insert(
        http::header::AUTHORIZATION,
        format!("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}")
            .parse()
            .expect("an authorization"),
    );
    request
}

/// Positive and negative — on a host naming a bucket, the legacy split reads a catalog path
/// path-style, as legacy RustFS's router takes it whatever the host: the doubly encoded spelling
/// over that host reaches `LoadTable`, and the S3 spelling is refused before anything runs.
#[tokio::test]
async fn a_virtual_hosted_catalog_request_is_the_catalogs_and_signed_doubly_encoded() {
    let host = "photos.s3.example.com";
    let wire = "/iceberg/v1/lakehouse/namespaces/a%1Fb/tables/t";
    let (service, catalog) = dialect_assembly(true, support::fixed_clock(), "AKIDEXAMPLE", b"secret");
    let (status, body) =
        support::exchange(&service, get_on(host, wire, "/iceberg/v1/lakehouse/namespaces/a%251Fb/tables/t")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(*catalog.lock().expect("record"), handed("lakehouse", "a\u{1f}b", "t"));
    let (service, catalog) = dialect_assembly(true, support::fixed_clock(), "AKIDEXAMPLE", b"secret");
    let (status, body) = support::exchange(&service, get_on(host, wire, wire)).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(catalog.lock().expect("record").is_empty());
}

/// Negative — through the dialect under the switch, a forged signature over the doubly encoded
/// spelling is refused, and so is an access key nobody issued; nothing runs.
#[tokio::test]
async fn n_forged_and_unknown_credentials_stay_refused_under_the_switch() {
    let wire = "/iceberg/v1/lakehouse/namespaces/a%1Fb/tables/t";
    let double = "/iceberg/v1/lakehouse/namespaces/a%251Fb/tables/t";
    for (access, secret, code) in [
        ("AKIDEXAMPLE", &b"another-secret"[..], "SignatureDoesNotMatch"),
        ("AKIDOTHER", &b"secret"[..], "InvalidAccessKeyId"),
    ] {
        let (service, catalog) = dialect_assembly(true, support::fixed_clock(), access, secret);
        let (status, body) = support::exchange(&service, get(wire, double)).await;
        assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
        assert!(catalog.lock().expect("record").is_empty());
    }
}
