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

//! What an authorizer learns about the client, the query and the signature through
//! `RequestContext` (rustfs/backlog#2752).
//!
//! Responsible for: proving, through a recording `Authorizer`, which client facts
//! (`ClientFacts`), raw query and signature scheme both authorization stages are handed — over the
//! real server runtime (plain TCP and TLS) and through a host's `StageFilter::on_wire` override —
//! and that absent facts stay absent rather than defaulting towards allow.
//! NOT responsible for: policy decisions (the recorder allows everything), how the facts are
//! derived (`rustfs_gateway::ext::client_facts`), or the server's own admission rules.
//! Upstream: `rustfs_gateway::ServiceBuilder`, `rustfs_gateway_server::Server`, `support`.
//! Downstream: none; this file is a test.

use crate::support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use rustfs_gateway::sig::PayloadMode;
use rustfs_gateway::{
    AuthSchemeRef, Authorizer, AuthzRequest, BoxFuture, ClientAddr, ClientFacts, Decision, InputAuthzRequest, InputDecisions,
    RequestContext, S3Service, SecurityFloor, ServiceBuilder, TransportSecurity, WireHead, wire_filter,
};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, TlsHandle, TlsMaterial};
use rustfs_gateway_sig::sig_v2::{SigV2Mode, SigV2Signer, SigV2StringToSignSpec};
use rustfs_gateway_sig::{RawQuery, percent_encode};
use rustls::pki_types::{CertificateDer, ServerName};
use support::Ping;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

// ── the recording authorizer ───────────────────────────────────────────────────────────────────

/// The facts one stage was handed, as the recorder copied them out of the context.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Facts {
    client: Option<ClientFacts>,
    /// The server's own connection value, read through the typed `ServerExtensions` path.
    connection_peer: Option<SocketAddr>,
    raw_query: Option<String>,
    scheme: AuthSchemeRef,
}

#[derive(Clone, Debug)]
struct Seen {
    stage: &'static str,
    facts: Facts,
    /// `format!("{context:?}")`, for the assertions about what a log line could carry.
    rendered: String,
}

#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<Seen>>,
}

impl Recorder {
    fn record(&self, stage: &'static str, context: &RequestContext<'_>) {
        let facts = Facts {
            client: context.client().copied(),
            connection_peer: context
                .server_extensions()
                .get::<rustfs_gateway_server::ConnectionInfo>()
                .map(|connection| connection.peer_addr()),
            raw_query: context.raw_query().map(str::to_owned),
            scheme: context.auth_scheme(),
        };
        let rendered = format!("{context:?}");
        self.seen
            .lock()
            .expect("the recorder is not poisoned")
            .push(Seen { stage, facts, rendered });
    }

    fn stage(&self, stage: &'static str) -> Seen {
        self.seen
            .lock()
            .expect("the recorder is not poisoned")
            .iter()
            .find(|seen| seen.stage == stage)
            .cloned()
            .unwrap_or_else(|| panic!("the {stage} stage was never asked"))
    }

    fn route(&self) -> Seen {
        self.stage("route")
    }

    fn input(&self) -> Seen {
        self.stage("input")
    }
}

impl Authorizer for Recorder {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, _request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        self.record("route", context);
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.record("input", context);
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

// ── fixtures ───────────────────────────────────────────────────────────────────────────────────

fn builder(recorder: &Arc<Recorder>) -> ServiceBuilder {
    support::wired_at_signed_time()
        .authorizer(Arc::clone(recorder))
        .register::<Ping, _>(Arc::new(support::Backend))
        .dialect(&support::ping_dialect())
}

fn service(recorder: &Arc<Recorder>) -> S3Service {
    builder(recorder).build().expect("a complete assembly")
}

/// A host-corrected client address nothing on the wire could have produced.
fn corrected_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))
}

/// The address a forged forwarding header names, so a test can prove it never arrived.
const FORGED: &str = "203.0.113.9";

fn with_headers(mut request: http::Request<Bytes>, headers: &[(&str, &str)]) -> http::Request<Bytes> {
    for (name, value) in headers {
        request.headers_mut().append(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            http::HeaderValue::from_str(value).expect("a header value"),
        );
    }
    request
}

fn plain_config() -> ServerConfig {
    ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    }
}

fn tls_config() -> ServerConfig {
    ServerConfig {
        plaintext: false,
        ..plain_config()
    }
}

fn live_server(service: S3Service, config: ServerConfig, tls: Option<TlsHandle>) -> RunningServer {
    let service = tower::service_fn(move |request| {
        let mut service = service.clone();
        async move {
            let response = <S3Service as tower::Service<_>>::call(&mut service, request)
                .await
                .expect("the adapter error type is Infallible");
            let collected = rustfs_gateway::collect(response).await.expect("an in-memory response body");
            let (status, headers, body, _trailers) = collected.into_parts();
            let mut response = http::Response::new(Full::new(body));
            *response.status_mut() = status;
            for (name, value) in headers {
                response.headers_mut().append(name, value);
            }
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    let server = Server::new(config, service);
    let server = match tls {
        Some(tls) => server.with_tls(tls),
        None => server,
    };
    server.serve().expect("the server starts")
}

async fn stop(running: RunningServer) {
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("the server task joins").is_ok());
}

fn generated_material() -> (TlsMaterial, CertificateDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("certificate generation succeeds");
    let certificate = CertificateDer::from(certified.cert.der().to_vec());
    (
        TlsMaterial::from_der(vec![certified.cert.der().to_vec()], certified.signing_key.serialize_der()),
        certificate,
    )
}

async fn tls_connect(addr: SocketAddr, certificate: CertificateDer<'static>) -> TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certificate)
        .expect("the fixture certificate is a valid trust anchor");
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client));
    let name = ServerName::try_from("localhost").expect("a fixture DNS name").to_owned();
    connector
        .connect(name, TcpStream::connect(addr).await.expect("TCP connects"))
        .await
        .expect("the TLS handshake succeeds")
}

/// One HTTP/1.1 request as bytes on the wire, closing the connection after the answer.
fn wire_bytes(request: &http::Request<Bytes>) -> Vec<u8> {
    let target = request.uri().path_and_query().map_or("/", http::uri::PathAndQuery::as_str);
    let mut out = format!("{} {target} HTTP/1.1\r\n", request.method()).into_bytes();
    for (name, value) in request.headers() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !request.headers().contains_key(http::header::CONTENT_LENGTH) {
        out.extend_from_slice(format!("content-length: {}\r\n", request.body().len()).as_bytes());
    }
    out.extend_from_slice(b"connection: close\r\n\r\n");
    out.extend_from_slice(request.body());
    out
}

async fn exchange_over<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, request: &http::Request<Bytes>) -> String {
    stream.write_all(&wire_bytes(request)).await.expect("the request writes");
    let mut response = Vec::new();
    // A TLS peer that closes without `close_notify` surfaces as an error after the bytes arrived;
    // what the status line says is the assertion, not how the socket ended.
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("the response terminates");
    String::from_utf8_lossy(&response).into_owned()
}

/// One correctly SigV4-presigned `POST /` with an empty body and its exact digest, which is the
/// payload declaration a presigned request verifies under.
fn presigned_empty() -> http::Request<Bytes> {
    use sha2::{Digest as _, Sha256};

    let digest: [u8; 32] = Sha256::digest(b"").into();
    support::presigned_with_body(Bytes::new(), PayloadMode::ExactSha256(digest))
}

/// One correctly SigV2-signed `POST /?{query}`.
fn signed_v2(query: &str) -> http::Request<Bytes> {
    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    map.insert(http::header::DATE, http::HeaderValue::from_static("Fri, 02 Jan 2026 03:04:05 GMT"));
    let raw = RawQuery::new(query);
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &http::Method::POST, "/", &raw, &map, None);
    let signer = SigV2Signer::new("AKIDEXAMPLE", b"secret").expect("a valid access key id");
    let authorization = signer.authorization(&spec).expect("a signable request");
    let mut builder = http::Request::builder().method(http::Method::POST).uri(format!("/?{query}"));
    for (name, value) in &map {
        builder = builder.header(name, value);
    }
    builder
        .header("authorization", authorization)
        .body(Bytes::new())
        .expect("a valid request")
}

/// One correctly SigV2-presigned `POST /`.
fn presigned_v2() -> http::Request<Bytes> {
    let expires_at = u64::try_from(support::SIGNED_AT_UNIX_SECONDS).expect("a post-epoch fixture") + 900;
    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let raw = format!("AWSAccessKeyId=AKIDEXAMPLE&Expires={expires_at}");
    let query = RawQuery::new(&raw);
    let spec = SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &http::Method::POST, "/", &query, &map, None);
    let signer = SigV2Signer::new("AKIDEXAMPLE", b"secret").expect("a valid access key id");
    let rendered = signer.presigned_signature(&spec).expect("a signable request");
    let escaped = percent_encode(rendered.as_bytes());
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("/?{raw}&Signature={escaped}"))
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request")
}

// ── the server path: facts the listener observed ───────────────────────────────────────────────

/// Positive — over a plain TCP listener both stages see the socket peer, a cleartext transport,
/// the raw query and the anonymous scheme, and the typed read path reaches the server's own
/// `ConnectionInfo` with the same peer.
#[tokio::test]
async fn server_plain_tcp_reports_the_peer_cleartext_and_the_query() {
    let recorder = Arc::new(Recorder::default());
    let running = live_server(service(&recorder), plain_config(), None);
    let mut client = TcpStream::connect(running.local_addr).await.expect("the client connects");
    let local = client.local_addr().expect("the client socket has an address");
    let text = exchange_over(&mut client, &support::plain(http::Method::POST, "/?probe=1&via=tcp")).await;
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    stop(running).await;

    let route = recorder.route();
    assert_eq!(
        route.facts,
        Facts {
            client: Some(ClientFacts {
                peer: Some(local),
                transport_secure: false,
                client_ip: None,
            }),
            connection_peer: Some(local),
            raw_query: Some("probe=1&via=tcp".to_owned()),
            scheme: AuthSchemeRef::Anonymous,
        }
    );
    assert_eq!(recorder.input().facts, route.facts, "the input stage reads the same facts");
}

/// Positive — over TLS the transport is secure, the peer is the TLS client's socket, and a
/// header-signed request reports the SigV4 header scheme.
#[tokio::test]
async fn server_tls_reports_a_secure_transport_with_the_socket_peer() {
    let recorder = Arc::new(Recorder::default());
    let (material, certificate) = generated_material();
    let tls = TlsHandle::new(material).expect("the generated material is valid");
    let running = live_server(service(&recorder), tls_config(), Some(tls));
    let mut client = tls_connect(running.local_addr, certificate).await;
    let local = client.get_ref().0.local_addr().expect("the client socket has an address");
    let text = exchange_over(&mut client, &support::signed(http::Method::POST, "/?probe=tls")).await;
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    stop(running).await;

    let route = recorder.route();
    assert_eq!(
        route.facts,
        Facts {
            client: Some(ClientFacts {
                peer: Some(local),
                transport_secure: true,
                client_ip: None,
            }),
            connection_peer: Some(local),
            raw_query: Some("probe=tls".to_owned()),
            scheme: AuthSchemeRef::SigV4Header,
        }
    );
    assert_eq!(recorder.input().facts, route.facts, "the input stage reads the same facts");
}

/// Negative — a client's forwarding headers forge neither the client address nor the peer: the
/// peer is the socket's, no host corrected it, and the forged address reaches no fact.
#[tokio::test]
async fn n_forwarding_headers_from_the_client_forge_neither_the_peer_nor_the_client_ip() {
    let recorder = Arc::new(Recorder::default());
    let running = live_server(service(&recorder), plain_config(), None);
    let mut client = TcpStream::connect(running.local_addr).await.expect("the client connects");
    let local = client.local_addr().expect("the client socket has an address");
    let request = with_headers(
        support::plain(http::Method::POST, "/?probe=forged"),
        &[
            ("x-forwarded-for", FORGED),
            ("forwarded", "for=203.0.113.9;proto=https"),
            ("x-real-ip", FORGED),
            ("x-client-ip", FORGED),
        ],
    );
    let text = exchange_over(&mut client, &request).await;
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    stop(running).await;

    let client_facts = recorder.route().facts.client;
    assert_eq!(
        client_facts,
        Some(ClientFacts {
            peer: Some(local),
            transport_secure: false,
            client_ip: None,
        })
    );
    assert!(!format!("{client_facts:?}").contains(FORGED));
    assert_eq!(client_facts.and_then(|facts| facts.source_ip()), Some(local.ip()));
}

/// Negative — a client cannot claim a secure transport on a plain TCP connection: the proto
/// headers proxies use are headers, and the transport fact is a socket observation.
#[tokio::test]
async fn n_a_client_header_cannot_make_a_plain_tcp_transport_secure() {
    let recorder = Arc::new(Recorder::default());
    let running = live_server(service(&recorder), plain_config(), None);
    let mut client = TcpStream::connect(running.local_addr).await.expect("the client connects");
    let request = with_headers(
        support::plain(http::Method::POST, "/?probe=proto"),
        &[
            ("x-forwarded-proto", "https"),
            ("front-end-https", "on"),
            ("x-forwarded-ssl", "on"),
        ],
    );
    let text = exchange_over(&mut client, &request).await;
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    stop(running).await;

    assert_eq!(recorder.route().facts.client.map(|facts| facts.transport_secure), Some(false));
    assert_eq!(recorder.input().facts.client.map(|facts| facts.transport_secure), Some(false));
}

/// Positive — the override path over the real server: a filter reads what the transport
/// observed, corrects the client address, and the authorizer sees the corrected address beside
/// the socket peer it did not touch.
#[tokio::test]
async fn server_on_wire_override_corrects_the_client_ip_and_keeps_the_peer() {
    let recorder = Arc::new(Recorder::default());
    let service = builder(&recorder)
        .stage_filter(wire_filter(|head: &mut WireHead<'_>| {
            let observed = head.client_facts().copied().unwrap_or_default();
            head.set_client_facts(ClientFacts {
                client_ip: Some(corrected_ip()),
                ..observed
            });
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let running = live_server(service, plain_config(), None);
    let mut client = TcpStream::connect(running.local_addr).await.expect("the client connects");
    let local = client.local_addr().expect("the client socket has an address");
    let text = exchange_over(&mut client, &support::plain(http::Method::POST, "/?probe=override")).await;
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    stop(running).await;

    let client_facts = recorder.route().facts.client;
    assert_eq!(
        client_facts,
        Some(ClientFacts {
            peer: Some(local),
            transport_secure: false,
            client_ip: Some(corrected_ip()),
        })
    );
    assert_eq!(client_facts.and_then(|facts| facts.source_ip()), Some(corrected_ip()));
    assert_eq!(recorder.input().facts.client, client_facts);
}

// ── the in-process path: no listener, so nothing is observed unless a host says so ────────────

/// Negative — a request that arrives with no transport facts at all has no client: `None`, not a
/// cleartext placeholder and not a loopback guess. The query and the scheme are still known.
#[tokio::test]
async fn n_without_transport_facts_the_client_is_unknown() {
    let recorder = Arc::new(Recorder::default());
    let (status, body) = support::exchange(&service(&recorder), support::signed(http::Method::POST, "/?probe=none")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");

    let route = recorder.route();
    assert_eq!(
        route.facts,
        Facts {
            client: None,
            connection_peer: None,
            raw_query: Some("probe=none".to_owned()),
            scheme: AuthSchemeRef::SigV4Header,
        }
    );
    assert_eq!(recorder.input().facts, route.facts);
}

/// Negative — an override that names only the client address leaves the peer unknown and the
/// transport insecure; nothing fills the other fields in.
#[tokio::test]
async fn n_an_override_of_one_field_leaves_the_others_unknown() {
    let recorder = Arc::new(Recorder::default());
    let service = builder(&recorder)
        .stage_filter(wire_filter(|head: &mut WireHead<'_>| {
            head.set_client_facts(ClientFacts {
                client_ip: Some(corrected_ip()),
                ..ClientFacts::default()
            });
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let (status, body) = support::exchange(&service, support::signed(http::Method::POST, "/?probe=one")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");

    assert_eq!(
        recorder.route().facts.client,
        Some(ClientFacts {
            peer: None,
            transport_secure: false,
            client_ip: Some(corrected_ip()),
        })
    );
}

/// Positive — the override is the host's word: a host that terminated TLS in front of the
/// gateway may declare the transport secure and name the peer it saw, and both stages read it.
#[tokio::test]
async fn the_override_may_declare_what_no_socket_showed() {
    let recorder = Arc::new(Recorder::default());
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)), 5555);
    let service = builder(&recorder)
        .stage_filter(wire_filter(move |head: &mut WireHead<'_>| {
            head.set_client_facts(ClientFacts {
                peer: Some(peer),
                transport_secure: true,
                client_ip: Some(corrected_ip()),
            });
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let (status, body) = support::exchange(&service, support::signed(http::Method::POST, "/?probe=host")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");

    let expected = Some(ClientFacts {
        peer: Some(peer),
        transport_secure: true,
        client_ip: Some(corrected_ip()),
    });
    assert_eq!(recorder.route().facts.client, expected);
    assert_eq!(recorder.input().facts.client, expected);
}

/// Positive — the override wins over the facts a layer installed: a filter that disagrees with
/// the `TransportSecurity` and `ClientAddr` already in the request is what the authorizer sees.
#[tokio::test]
async fn the_override_replaces_facts_a_layer_installed() {
    let recorder = Arc::new(Recorder::default());
    let service = builder(&recorder)
        .stage_filter(wire_filter(|head: &mut WireHead<'_>| {
            assert_eq!(
                head.client_facts().map(|facts| facts.transport_secure),
                Some(true),
                "the filter is shown the layer's facts before it overrides them"
            );
            head.set_client_facts(ClientFacts {
                peer: None,
                transport_secure: false,
                client_ip: Some(corrected_ip()),
            });
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let mut request = support::signed(http::Method::POST, "/?probe=layer");
    request.extensions_mut().insert(TransportSecurity::Encrypted);
    request
        .extensions_mut()
        .insert(ClientAddr::from_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");

    assert_eq!(
        recorder.route().facts.client,
        Some(ClientFacts {
            peer: None,
            transport_secure: false,
            client_ip: Some(corrected_ip()),
        })
    );
}

/// Positive — the facts a host already installs for the customer-key gate and the governor are
/// reused: `TransportSecurity::Encrypted` and a `ClientAddr` in the request extensions become
/// client facts without any filter.
#[tokio::test]
async fn facts_a_host_installed_for_the_sse_gate_and_the_governor_are_reused() {
    let recorder = Arc::new(Recorder::default());
    let mut request = support::signed(http::Method::POST, "/?probe=layer");
    request.extensions_mut().insert(TransportSecurity::Encrypted);
    request.extensions_mut().insert(ClientAddr::from_peer(corrected_ip()));
    let (status, body) = support::exchange(&service(&recorder), request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");

    assert_eq!(
        recorder.route().facts.client,
        Some(ClientFacts {
            peer: None,
            transport_secure: true,
            client_ip: Some(corrected_ip()),
        })
    );
}

/// Negative — the other direction, so the reader is not stuck on one answer: a host that
/// declares cleartext is believed, and a `ClientAddr` alone does not make a transport secure.
#[tokio::test]
async fn n_a_declared_cleartext_transport_and_a_bare_client_address_are_not_secure() {
    let recorder = Arc::new(Recorder::default());
    let service = service(&recorder);
    let mut request = support::signed(http::Method::POST, "/?probe=plaintext");
    request.extensions_mut().insert(TransportSecurity::Plaintext);
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(
        recorder.route().facts.client,
        Some(ClientFacts {
            peer: None,
            transport_secure: false,
            client_ip: None,
        })
    );

    let recorder = Arc::new(Recorder::default());
    let service = self::service(&recorder);
    let mut request = support::signed(http::Method::POST, "/?probe=address");
    request.extensions_mut().insert(ClientAddr::from_peer(corrected_ip()));
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(
        recorder.route().facts.client,
        Some(ClientFacts {
            peer: None,
            transport_secure: false,
            client_ip: Some(corrected_ip()),
        })
    );
}

// ── the signature scheme and the query ─────────────────────────────────────────────────────────

/// Positive — a presigned request reports the presigned scheme, and the query it reports is the
/// one it was presigned with.
#[tokio::test]
async fn a_presigned_request_reports_the_presigned_scheme_and_its_query() {
    let recorder = Arc::new(Recorder::default());
    let request = presigned_empty();
    let query = request.uri().query().expect("a presigned query").to_owned();
    let (status, body) = support::exchange(&service(&recorder), request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");

    let route = recorder.route();
    assert_eq!(route.facts.scheme, AuthSchemeRef::SigV4Presigned);
    assert!(route.facts.scheme.is_presigned());
    assert!(route.facts.scheme.is_authenticated());
    assert_eq!(route.facts.raw_query.as_deref(), Some(query.as_str()));
    assert_eq!(recorder.input().facts.scheme, AuthSchemeRef::SigV4Presigned);
}

/// Negative — the context's `Debug` prints no query: a presigned query carries the signature,
/// and a log line that carried it would be a replayable credential.
#[tokio::test]
async fn n_the_context_debug_prints_neither_the_query_nor_the_signature() {
    let recorder = Arc::new(Recorder::default());
    let request = presigned_empty();
    let query = request.uri().query().expect("a presigned query").to_owned();
    let signature = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("X-Amz-Signature="))
        .expect("the presigned query carries a signature")
        .to_owned();
    let (status, body) = support::exchange(&service(&recorder), request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");

    for seen in [recorder.route(), recorder.input()] {
        assert!(!seen.rendered.contains(&signature), "{}", seen.rendered);
        assert!(!seen.rendered.contains("X-Amz-"), "{}", seen.rendered);
        assert!(!seen.rendered.contains(&query), "{}", seen.rendered);
    }
}

/// Positive — SigV2 is told apart from SigV4 on both carriers: the header scheme, and the
/// presigned one once the deployment opts into it.
#[tokio::test]
async fn sigv2_header_and_presigned_requests_report_their_own_schemes() {
    let recorder = Arc::new(Recorder::default());
    let (status, body) = support::exchange(&service(&recorder), signed_v2("probe=v2")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let route = recorder.route();
    assert_eq!(route.facts.scheme, AuthSchemeRef::SigV2Header);
    assert!(!route.facts.scheme.is_presigned());
    assert_eq!(route.facts.raw_query.as_deref(), Some("probe=v2"));

    let recorder = Arc::new(Recorder::default());
    let service = builder(&recorder)
        .security_floor(SecurityFloor::new().enable_sigv2_presigned_compatibility())
        .build()
        .expect("a complete assembly");
    let (status, body) = support::exchange(&service, presigned_v2()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorder.route().facts.scheme, AuthSchemeRef::SigV2Presigned);
    assert!(recorder.route().facts.scheme.is_presigned());
}

/// Negative — an anonymous request is the only unauthenticated one, and it is not presigned.
#[tokio::test]
async fn n_an_anonymous_request_is_neither_authenticated_nor_presigned() {
    let recorder = Arc::new(Recorder::default());
    let (status, body) = support::exchange(&service(&recorder), support::plain(http::Method::POST, "/?probe=anon")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");

    let scheme = recorder.route().facts.scheme;
    assert_eq!(scheme, AuthSchemeRef::Anonymous);
    assert!(!scheme.is_authenticated());
    assert!(!scheme.is_presigned());
    assert_eq!(recorder.input().facts.scheme, AuthSchemeRef::Anonymous);
}
