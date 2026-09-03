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

//! The one assembly of the system under test, and the evidence that it is the one that runs.
//!
//! Responsible for: opening the reference backend with the configured lifecycle cadence, reading
//! the operation set it really registers, and building the `S3Service` that `main` serves — with
//! every configured identity registered for signing, the bucket-owner registry installed as both
//! the authorizer and the `BucketOwnerSource`.
//! NOT responsible for: binding a socket (`main`), storing anything (`rustfs-gateway-fs`), or
//! deciding who owns what (`crate::ownership`).
//! Upstream: `crate::Options`. Downstream: `main`, and the tests below, which drive signed
//! requests through **this** function rather than through an assembly of their own — an assembly
//! written for a test proves nothing about the one the suites are pointed at.

use std::io;
use std::sync::Arc;

use rustfs_gateway::{Credentials, RegionSet, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials, decide_with};
use rustfs_gateway_fs::FsBackend;

use crate::Options;
use crate::ownership::{BucketOwners, decide};

/// Opens the reference backend, applying the configured lifecycle debug cadence when there is one.
///
/// # Errors
///
/// Any I/O error from opening the data root, and an invalid-input error for an unusable interval.
/// The configured region is handed to the backend as well as to the authenticator: it is what
/// `HeadBucket` and `GetBucketLocation` report, and a deployment whose signer and whose backend
/// disagreed about where its buckets are would answer a client two different regions depending on
/// which it asked first.
pub(crate) fn open_backend(options: &Options) -> io::Result<FsBackend> {
    let backend = FsBackend::open(&options.data)?.with_region(&options.region)?;
    match options.lifecycle_debug_interval {
        Some(interval) => backend.with_lifecycle_debug_interval(interval),
        None => Ok(backend),
    }
}

/// The operation names the assembled service really registers.
///
/// This is the capability boundary the matrix consults: a scenario needing an operation absent
/// from this list is recorded as `unsupported` with that operation named, never as a pass and
/// never as a failure. It is read from the backend rather than written down twice, so the
/// declared boundary cannot drift away from the registry.
pub(crate) fn capability_names(backend: &FsBackend) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = backend.supported_operations().collect();
    names.sort_unstable();
    names
}

/// Assembles the served service from the configured identities and the bucket-owner registry.
///
/// # Errors
///
/// An invalid credential, an unusable region, or an incomplete operation registry.
pub(crate) fn build_service(
    options: &Options,
    backend: &Arc<FsBackend>,
    owners: &Arc<BucketOwners>,
) -> Result<S3Service, Box<dyn std::error::Error>> {
    let mut credentials = StaticCredentials::new();
    for account in options.accounts.all() {
        credentials = credentials.with(Credentials::new(&account.access_key, account.secret_key.as_bytes())?);
    }
    let supported = capability_names(backend);
    let accounts = options.accounts.clone();
    let registry = Arc::clone(owners);
    let builder = backend.register_crud(
        ServiceBuilder::new()
            .authenticator(SigV4Authenticator::new(Arc::new(credentials), RegionSet::new([options.region.clone()])?))
            // Not an allow-all, and not a bare operation-set filter either: the matrix must see a
            // refusal for anything outside the reference backend's registered set, and the
            // external suites must see one identity refused on another identity's bucket. Both
            // refusals are `crate::ownership::decide`.
            .authorizer(decide_with(move |request| decide(&registry, &accounts, &supported, request)))
            // The same registry answers `x-amz-expected-bucket-owner`, so the owner id a caller
            // asserts is the very id the authorization decision was made against.
            .bucket_owner_source(Arc::clone(owners)),
    );
    let service = backend
        .register_tagging(
            backend
                .register_lifecycle(backend.register_listing(backend.register_versioning(backend.register_multipart(builder)))),
        )
        .build()?;
    Ok(service)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{build_service, open_backend};
    use crate::ownership::BucketOwners;
    use crate::{Options, parse_options};

    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
    use rustfs_gateway::{Limits, S3Service, Timestamp, TimestampFormat, WireRequest, WireResponse, collect};
    use rustfs_gateway_fs::FsBackend;
    use sha2::{Digest as _, Sha256};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    const MAIN_KEY: &str = "AKIAGATEWAYMAIN00000";
    const MAIN_SECRET: &str = "gateway-main-secret-for-a-throwaway-service";
    const ALT_KEY: &str = "AKIAGATEWAYALT000000";
    const ALT_SECRET: &str = "gateway-alt-secret-for-a-throwaway-service";
    const MAIN_OWNER: &str = "s3gate-main";
    const ALT_OWNER: &str = "s3gate-alt";

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "compat-sut-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("a unique test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("the exact test root is removable");
        }
    }

    /// The exact command line an external suite would use, parsed by the launcher's own parser.
    fn two_identity_options(root: &TestRoot, extra: &[&str]) -> Options {
        let mut arguments = vec![
            "--data".to_owned(),
            root.0.to_string_lossy().into_owned(),
            "--access-key".to_owned(),
            MAIN_KEY.to_owned(),
            "--secret-key".to_owned(),
            MAIN_SECRET.to_owned(),
            "--owner-id".to_owned(),
            MAIN_OWNER.to_owned(),
            "--display-name".to_owned(),
            MAIN_OWNER.to_owned(),
            "--alt-access-key".to_owned(),
            ALT_KEY.to_owned(),
            "--alt-secret-key".to_owned(),
            ALT_SECRET.to_owned(),
            "--alt-owner-id".to_owned(),
            ALT_OWNER.to_owned(),
            "--alt-display-name".to_owned(),
            ALT_OWNER.to_owned(),
        ];
        arguments.extend(extra.iter().map(|argument| (*argument).to_owned()));
        parse_options(arguments).expect("a valid two-identity command line")
    }

    fn assembled(options: &Options) -> (Arc<FsBackend>, S3Service) {
        let backend = Arc::new(open_backend(options).expect("a usable data root"));
        let owners = Arc::new(BucketOwners::default());
        let service = build_service(options, &backend, &owners).expect("a complete assembly");
        (backend, service)
    }

    /// Signs one request as the named identity, using the same signer any SDK would.
    fn signed(
        access_key: &str,
        secret_key: &str,
        method: http::Method,
        target: &str,
        body: Bytes,
        extra: &[(&str, &str)],
    ) -> http::Request<Bytes> {
        let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
        for (name, value) in extra {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).expect("a valid header name"),
                http::HeaderValue::from_str(value).expect("a valid header value"),
            );
        }
        let payload = if (method == http::Method::PUT && target.matches('/').count() >= 2) || !body.is_empty() {
            let digest: [u8; 32] = Sha256::digest(&body).into();
            let payload = PayloadMode::ExactSha256(digest);
            headers.insert(
                http::HeaderName::from_static("x-amz-content-sha256"),
                http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("a digest header"),
            );
            headers.insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(&body.len().to_string()).expect("a content length"),
            );
            payload
        } else {
            PayloadMode::Empty
        };
        let probe = http::Request::builder()
            .uri("/")
            .header(http::header::HOST, "s3.example.com")
            .body(Bytes::new())
            .expect("a valid host probe");
        let accepted = WireRequest::accept(probe, &Limits::default()).expect("an acceptable host");
        // The assembled service uses the production system clock — `build_service` installs no
        // fixed one — so the request must be stamped now, or every case here would fail on skew
        // rather than on what it is written to measure.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_secs();
        let rendered = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
            .render(TimestampFormat::Iso8601Basic)
            .expect("a representable signing stamp");
        let stamp = AmzDate::parse(&rendered).expect("a valid signing stamp");
        let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a valid signing scope");
        let credentials = SigningCredentials::new(access_key, secret_key.as_bytes()).expect("valid signing credentials");
        let signing = SigningRequest::new(&method, path, query, &headers, accepted.host().raw_for_signing(), payload, stamp)
            .with_wire_content_length(body.len() as u64);
        let mut signer = SigV4Signer::new(credentials, scope);
        let signed = signer.sign_headers(&signing).expect("a signable request");
        let mut request = http::Request::builder().method(method).uri(target);
        for (name, value) in signed.headers() {
            request = request.header(name, value);
        }
        request.body(body).expect("a valid signed request")
    }

    fn as_main(method: http::Method, target: &str, body: Bytes) -> http::Request<Bytes> {
        signed(MAIN_KEY, MAIN_SECRET, method, target, body, &[])
    }

    fn as_alt(method: http::Method, target: &str, body: Bytes) -> http::Request<Bytes> {
        signed(ALT_KEY, ALT_SECRET, method, target, body, &[])
    }

    async fn exchange(service: &S3Service, request: http::Request<Bytes>) -> WireResponse {
        collect(service.call_bytes(request).await).await.expect("a finite response")
    }

    fn body_of(response: &WireResponse) -> String {
        String::from_utf8_lossy(response.body()).into_owned()
    }

    /// The whole point of the second identity, end to end through the served assembly.
    ///
    /// Positive halves and negative halves in one case on purpose: a refusal that is not paired
    /// with the allowance it is supposed to be different from is satisfied by a service that
    /// refuses everything.
    #[tokio::test]
    async fn n_the_second_identity_is_refused_on_the_first_identitys_bucket() {
        let root = TestRoot::new();
        let options = two_identity_options(&root, &[]);
        let (_backend, service) = assembled(&options);

        // main owns it, and reaches it.
        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/main-bucket", Bytes::new()))
                .await
                .status(),
            200
        );
        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/main-bucket/key", Bytes::from_static(b"body")))
                .await
                .status(),
            200
        );
        let read = exchange(&service, as_main(http::Method::GET, "/main-bucket/key", Bytes::new())).await;
        assert_eq!(read.status(), 200);
        assert_eq!(read.body().as_ref(), b"body");

        // alt signs correctly, is authenticated, and is still refused.
        let refused = exchange(&service, as_alt(http::Method::GET, "/main-bucket/key", Bytes::new())).await;
        assert_eq!(refused.status(), 403, "{}", body_of(&refused));
        assert!(body_of(&refused).contains("AccessDenied"), "{}", body_of(&refused));
        let refused = exchange(&service, as_alt(http::Method::PUT, "/main-bucket/other", Bytes::from_static(b"x"))).await;
        assert_eq!(refused.status(), 403, "{}", body_of(&refused));
        let refused = exchange(&service, as_alt(http::Method::GET, "/main-bucket?list-type=2", Bytes::new())).await;
        assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    }

    /// Negative — the refusal is ownership, not rank. The first identity is refused the same way
    /// on the second identity's bucket, and the second identity is served on its own.
    #[tokio::test]
    async fn n_the_first_identity_is_refused_on_the_second_identitys_bucket() {
        let root = TestRoot::new();
        let options = two_identity_options(&root, &[]);
        let (_backend, service) = assembled(&options);

        assert_eq!(
            exchange(&service, as_alt(http::Method::PUT, "/alt-bucket", Bytes::new()))
                .await
                .status(),
            200
        );
        assert_eq!(
            exchange(&service, as_alt(http::Method::PUT, "/alt-bucket/key", Bytes::from_static(b"alt")))
                .await
                .status(),
            200
        );
        let refused = exchange(&service, as_main(http::Method::GET, "/alt-bucket/key", Bytes::new())).await;
        assert_eq!(refused.status(), 403, "{}", body_of(&refused));
        let allowed = exchange(&service, as_alt(http::Method::GET, "/alt-bucket/key", Bytes::new())).await;
        assert_eq!(allowed.status(), 200, "{}", body_of(&allowed));
        assert_eq!(allowed.body().as_ref(), b"alt");
    }

    /// Negative — with only one identity configured, no second identity can sign at all. This is
    /// what a suite that forgot to configure the second identity must run into: a service that
    /// cannot be reached as the second principal, rather than one that quietly serves it.
    #[tokio::test]
    async fn n_an_unconfigured_second_identity_cannot_authenticate() {
        let root = TestRoot::new();
        let options = parse_options([
            "--data",
            &root.0.to_string_lossy(),
            "--access-key",
            MAIN_KEY,
            "--secret-key",
            MAIN_SECRET,
        ])
        .expect("a valid single-identity command line");
        let (_backend, service) = assembled(&options);

        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/solo", Bytes::new()))
                .await
                .status(),
            200
        );
        let refused = exchange(&service, as_alt(http::Method::GET, "/solo", Bytes::new())).await;
        assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    }

    /// Negative — an unsigned request reaches no bucket, owned or not.
    #[tokio::test]
    async fn n_an_anonymous_request_is_refused() {
        let root = TestRoot::new();
        let options = two_identity_options(&root, &[]);
        let (_backend, service) = assembled(&options);

        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/main-bucket", Bytes::new()))
                .await
                .status(),
            200
        );
        let anonymous = http::Request::builder()
            .method(http::Method::GET)
            .uri("/main-bucket/key")
            .header(http::header::HOST, "s3.example.com")
            .body(Bytes::new())
            .expect("a valid unsigned request");
        let refused = exchange(&service, anonymous).await;
        assert!(refused.status() == 403 || refused.status() == 401, "{}", refused.status());
    }

    /// Positive and negative — the configured owner id is the value a caller may assert with
    /// `x-amz-expected-bucket-owner`, and the other identity's owner id is refused against the
    /// same bucket. This is what makes `--owner-id` a value the wire can observe rather than a
    /// string the launcher parsed and dropped.
    #[tokio::test]
    async fn the_configured_owner_id_answers_an_expected_bucket_owner_assertion() {
        let root = TestRoot::new();
        let options = two_identity_options(&root, &[]);
        let (_backend, service) = assembled(&options);

        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/owned", Bytes::new()))
                .await
                .status(),
            200
        );
        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/owned/key", Bytes::from_static(b"body")))
                .await
                .status(),
            200
        );

        let matching = signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::GET,
            "/owned/key",
            Bytes::new(),
            &[("x-amz-expected-bucket-owner", MAIN_OWNER)],
        );
        assert_eq!(exchange(&service, matching).await.status(), 200);

        let mismatched = signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::GET,
            "/owned/key",
            Bytes::new(),
            &[("x-amz-expected-bucket-owner", ALT_OWNER)],
        );
        let refused = exchange(&service, mismatched).await;
        assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    }

    /// The same document and the same checksum the reference backend's own lifecycle tests use, so
    /// that a failure here is about the launcher's wiring and not about a hand-rolled digest.
    const EXPIRE_ALL: &str = concat!(
        "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration>",
        "<ID>expire-all</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>",
        "</Rule></LifecycleConfiguration>"
    );
    const EXPIRE_ALL_MD5: &str = "5Y4m5g4gmXjRJtprF5EAXA==";

    async fn put_lifecycle(service: &S3Service, bucket: &str) {
        let request = signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            &format!("/{bucket}?lifecycle"),
            Bytes::from_static(EXPIRE_ALL.as_bytes()),
            &[("content-md5", EXPIRE_ALL_MD5)],
        );
        let response = exchange(service, request).await;
        assert_eq!(response.status(), 200, "{}", body_of(&response));
    }

    /// Positive — `--lc-debug-interval` reaches the backend and the sweeper, end to end: a
    /// one-day expiration rule retires an object within seconds instead of within a day.
    #[tokio::test]
    async fn the_lifecycle_debug_interval_expires_a_one_day_rule_in_seconds() {
        let root = TestRoot::new();
        let options = two_identity_options(&root, &["--lc-debug-interval", "1"]);
        let (backend, service) = assembled(&options);

        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/lc-debug", Bytes::new()))
                .await
                .status(),
            200
        );
        put_lifecycle(&service, "lc-debug").await;
        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/lc-debug/key", Bytes::from_static(b"body")))
                .await
                .status(),
            200
        );
        assert_eq!(
            exchange(&service, as_main(http::Method::GET, "/lc-debug/key", Bytes::new()))
                .await
                .status(),
            200
        );

        let scheduler = backend.start_lifecycle_scheduler().expect("a runtime is active");
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        let report = scheduler.shutdown().await.expect("the scheduler joins cleanly");

        assert!(report.sweeps >= 1, "no sweep ran: {report:?}");
        assert_eq!(report.failed_sweeps, 0, "{report:?}");
        assert_eq!(
            exchange(&service, as_main(http::Method::GET, "/lc-debug/key", Bytes::new()))
                .await
                .status(),
            404
        );
    }

    /// Negative — the same rule, the same wait, and no `--lc-debug-interval`: the object survives.
    /// Without this half the case above is satisfied by a backend that expires everything.
    #[tokio::test]
    async fn n_without_the_debug_interval_a_one_day_rule_expires_nothing() {
        let root = TestRoot::new();
        let options = two_identity_options(&root, &[]);
        let (backend, service) = assembled(&options);

        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/lc-debug", Bytes::new()))
                .await
                .status(),
            200
        );
        put_lifecycle(&service, "lc-debug").await;
        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/lc-debug/key", Bytes::from_static(b"body")))
                .await
                .status(),
            200
        );

        let scheduler = backend.start_lifecycle_scheduler().expect("a runtime is active");
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        let report = scheduler.shutdown().await.expect("the scheduler joins cleanly");

        assert_eq!(report.sweeps, 0, "a production cadence swept within seconds: {report:?}");
        assert_eq!(
            exchange(&service, as_main(http::Method::GET, "/lc-debug/key", Bytes::new()))
                .await
                .status(),
            200
        );
    }
}
