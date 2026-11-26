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

//! The assembled pipeline's own unit suite.
//!
//! Responsible for: the two claims decidable without a request — that an `S3Service` is one
//! pointer wide, and that the transport-security reader answers both ways rather than being stuck
//! on one.
//! NOT responsible for: what a request does to the pipeline, which is `crates/gateway/tests/`.
//! Upstream: `super`. Downstream: Cargo's test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;

/// Positive — cloning the service is one pointer's worth of work, which is what makes cloning
/// it per connection the right thing for a server to do.
#[test]
fn the_service_is_one_pointer_wide() {
    assert_eq!(core::mem::size_of::<S3Service>(), core::mem::size_of::<usize>());
}

/// Negative — a request nobody annotated is cleartext, so the customer-key gate is closed by
/// default rather than open by default.
#[test]
fn an_unannotated_request_is_cleartext() {
    assert_eq!(connection_security(&http::Extensions::new()), TransportSecurity::Plaintext);
}

/// Negative — and the other direction, so the reader is not simply stuck on one answer. A
/// function that returned `Plaintext` unconditionally satisfies every test above.
#[test]
fn n_a_transport_that_declares_tls_is_believed_and_one_that_declares_cleartext_is_too() {
    let mut encrypted = http::Extensions::new();
    encrypted.insert(TransportSecurity::Encrypted);
    assert_eq!(connection_security(&encrypted), TransportSecurity::Encrypted);
    let mut plaintext = http::Extensions::new();
    plaintext.insert(TransportSecurity::Plaintext);
    assert_eq!(connection_security(&plaintext), TransportSecurity::Plaintext);
}

#[cfg(feature = "server")]
mod server_connection_security {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rustfs_gateway_server::{Server, ServerConfig, TlsHandle, TlsMaterial};
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    use crate::{
        ClockSkewAck, Credentials, FixedClock, Handler, HandlerResult, RegionSet, Req, Resp, S3Service, ServiceBuilder,
        SigV4Authenticator, StaticCredentials, allow_when, dto,
        sig::{AmzDate, PayloadMode, SigV4Signer, SigningCredentials, SigningRequest, SigningScope},
    };

    const SIGNED_AT_SECONDS: i64 = 1_767_323_045;
    const SIGNED_AT_STAMP: &str = "20260102T030405Z";
    const KEY_32: &str = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
    const KEY_32_MD5: &str = "KYvwGXoFFJ42a2u2GDWhwQ==";

    struct CountingPut(Arc<AtomicUsize>);

    impl Handler<dto::PutObject> for CountingPut {
        async fn call(&self, _request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }

    fn sse_c_service() -> (S3Service, Arc<AtomicUsize>) {
        let handled = Arc::new(AtomicUsize::new(0));
        let credentials =
            Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
        let service = ServiceBuilder::new()
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
            .authorizer(allow_when(|_| true))
            .clock_with_skew_ack(
                FixedClock::at_unix_seconds(SIGNED_AT_SECONDS),
                ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            )
            .register::<dto::PutObject, _>(Arc::new(CountingPut(Arc::clone(&handled))))
            .build()
            .expect("a complete PutObject assembly");
        (service, handled)
    }

    fn raw_signed_sse_c_put() -> Vec<u8> {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
        headers.insert(
            "x-amz-server-side-encryption-customer-algorithm",
            http::HeaderValue::from_static("AES256"),
        );
        headers.insert("x-amz-server-side-encryption-customer-key", http::HeaderValue::from_static(KEY_32));
        headers.insert(
            "x-amz-server-side-encryption-customer-key-md5",
            http::HeaderValue::from_static(KEY_32_MD5),
        );
        let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("valid stamp");
        let scope = SigningScope::new(stamp.day(), "us-east-1", rustfs_gateway_sig::SigService::S3).expect("valid scope");
        let mut signer = SigV4Signer::new(SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid creds"), scope);
        let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("valid host");
        let request = SigningRequest::new(&http::Method::PUT, "/bucket/key", "", &headers, &host, PayloadMode::Empty, stamp)
            .with_wire_content_length(0);
        let signed = signer.sign_headers(&request).expect("request signs");
        let mut wire = String::from("PUT /bucket/key HTTP/1.1\r\n");
        for (name, value) in signed.headers() {
            wire.push_str(&format!("{name}: {}\r\n", value.to_str().expect("ascii")));
        }
        wire.push_str("connection: close\r\n\r\n");
        wire.into_bytes()
    }

    async fn exchange_raw<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, request: &[u8]) -> String {
        stream.write_all(request).await.expect("request writes");
        stream.flush().await.expect("request flushes");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .expect("response completes before deadline")
            .expect("response reads");
        String::from_utf8_lossy(&response).into_owned()
    }

    /// Positive — `rustfs-gateway-server`'s TLS `ConnectionInfo` is recognized as encrypted by
    /// `connection_security`, allowing SSE-C requests without an extra `TransportSecurity` layer.
    #[tokio::test]
    async fn server_tls_connection_info_accepts_sse_c_without_transport_security_extension() {
        let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("self-signed cert");
        let certificate = CertificateDer::from(certified.cert.der().to_vec());
        let material = TlsMaterial::from_der(vec![certified.cert.der().to_vec()], certified.signing_key.serialize_der());
        let (service, handled) = sse_c_service();
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: false,
            ..ServerConfig::default()
        };
        let running = Server::new(config, service)
            .with_tls(TlsHandle::new(material).expect("valid tls material"))
            .serve()
            .expect("TLS server starts");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("trust anchor");
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tcp = TcpStream::connect(running.local_addr).await.expect("TCP connects");
        let tls_stream = TlsConnector::from(Arc::new(tls))
            .connect(ServerName::try_from("localhost").expect("dns name").to_owned(), tcp)
            .await
            .expect("TLS handshake succeeds");
        let response = exchange_raw(tls_stream, &raw_signed_sse_c_put()).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "SSE-C over server TLS ConnectionInfo should succeed, got: {response}"
        );
        assert_eq!(handled.load(Ordering::SeqCst), 1);

        let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
        assert!(running.task.await.expect("server task joins").is_ok());
    }

    /// Negative — `rustfs-gateway-server`'s plaintext `ConnectionInfo` still refuses SSE-C.
    #[tokio::test]
    async fn n_server_plaintext_connection_info_refuses_sse_c() {
        let (service, handled) = sse_c_service();
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            ..ServerConfig::default()
        };
        let running = Server::new(config, service).serve().expect("plaintext server starts");

        let tcp = TcpStream::connect(running.local_addr).await.expect("TCP connects");
        let response = exchange_raw(tcp, &raw_signed_sse_c_put()).await;
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "SSE-C over server plaintext ConnectionInfo must be refused, got: {response}"
        );
        assert_eq!(handled.load(Ordering::SeqCst), 0);

        let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
        assert!(running.task.await.expect("server task joins").is_ok());
    }
}
