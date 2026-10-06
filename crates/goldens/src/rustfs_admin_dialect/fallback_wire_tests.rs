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

//! Socket observations for authenticated admin fallback body ordering (ADR-0039).
//!
//! Responsible for: actual response headers before a withheld request body, and a buffered
//! operation that cannot answer until its final body byte arrives.
//! NOT responsible for: inferring connection closure, native observations or inventory census.
//! Upstream: the assembled admin service and production server adapter. Downstream: nothing.

use std::time::Duration;

use bytes::Bytes;
use http::Request;
use rustfs_gateway::{RunningServer, Server, ServerConfig};
use rustfs_gateway_dialect_rustfs_admin::{BodyKind, ROUTES};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{Assembled, ContextRequest, PATH_HOST, REGION, assemble_with_profile, rustfs_profile_floor, wire};

const BODY: &[u8] = b"the client withholds these bytes until the control explicitly sends them";

struct Live {
    running: Option<RunningServer>,
    assembled: Assembled,
}

impl Live {
    fn start() -> Self {
        let assembled = assemble_with_profile(rustfs_profile_floor(), |_, _| true, true, None);
        let config = ServerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("loopback"),
            plaintext: true,
            ..ServerConfig::default()
        };
        let running = Server::new(config, assembled.service.clone())
            .serve()
            .expect("loopback server starts");
        Self {
            running: Some(running),
            assembled,
        }
    }

    async fn connect(&self, request: &Request<Bytes>) -> TcpStream {
        let mut client = TcpStream::connect(self.running.as_ref().expect("live server").local_addr)
            .await
            .expect("client connects");
        let mut head = format!("{} {} HTTP/1.1\r\n", request.method(), request.uri().path_and_query().expect("target"));
        for (name, value) in request.headers() {
            head.push_str(&format!("{}: {}\r\n", name, value.to_str().expect("fixture header")));
        }
        if !request.headers().contains_key("content-length") {
            head.push_str(&format!("Content-Length: {}\r\n", request.body().len()));
        }
        head.push_str("Connection: close\r\n\r\n");
        client.write_all(head.as_bytes()).await.expect("only the headers are sent");
        client
    }

    async fn stop(mut self) {
        let running = self.running.take().expect("live server");
        let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
        running.task.await.expect("server task").expect("server shutdown");
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(running) = &self.running {
            running.task.abort();
        }
    }
}

async fn response_head(client: &mut TcpStream) -> String {
    timeout(Duration::from_secs(5), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(client.read_u8().await.expect("response head before EOF"));
            assert!(bytes.len() < 32 * 1024, "bounded fixture response head");
        }
        String::from_utf8(bytes).expect("ASCII response head")
    })
    .await
    .expect("a response arrives while all request body bytes are withheld")
}

/// Negative — authenticated fallback selection cannot wait for a body, and invalid credentials
/// cannot obtain its downgrade signal. Both aliases use the actual server adapter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n_fallback_headers_do_not_wait_for_the_declared_payload() {
    let live = Live::start();
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        for (suffix, valid_status) in [("/v4/gateway-absent", 426), ("/v3/gateway-absent", 501)] {
            let path = format!("{prefix}{suffix}");
            let signed = ContextRequest::put_with_query(PATH_HOST, &path, "", BODY).signed(REGION);
            let mut anonymous = wire(&signed);
            anonymous.headers_mut().remove(http::header::AUTHORIZATION);
            for (request, status) in [(wire(&signed), valid_status), (wire(&signed.forged()), 403), (anonymous, 403)] {
                let mut client = live.connect(&request).await;
                let head = response_head(&mut client).await;
                assert!(head.starts_with(&format!("HTTP/1.1 {status} ")), "{path}: {head}");
                if status == 426 {
                    let lower = head.to_ascii_lowercase();
                    assert!(!lower.contains("\r\ncontent-type:"), "{head}");
                    assert!(!lower.contains("\r\nupgrade:"), "{head}");
                    assert!(lower.contains("\r\ncontent-length: 0\r\n"), "{head}");
                }
            }
        }
    }
    assert_eq!(live.assembled.admin.handed.lock().expect("recorded handlers").len(), 4);
    live.stop().await;
}

/// Negative — the same server must not answer a buffered registered operation before the last
/// payload byte. This distinguishes the observer from one that always sees an early response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n_a_buffered_admin_operation_waits_for_its_last_payload_byte() {
    let record = ROUTES
        .iter()
        .find(|record| record.operation == "rustfs:PutV3Config")
        .expect("buffered control");
    assert_eq!(record.request_body, BodyKind::Buffered);
    let live = Live::start();
    let request = wire(&ContextRequest::put_with_query(PATH_HOST, record.path, "", BODY).signed(REGION));
    let mut client = live.connect(&request).await;
    let (last, prefix) = BODY.split_last().expect("nonempty payload");
    client.write_all(prefix).await.expect("all but the last payload byte");
    assert!(
        timeout(Duration::from_millis(100), client.read_u8()).await.is_err(),
        "buffered request answered too early"
    );
    assert!(live.assembled.admin.handed.lock().expect("recorded handlers").is_empty());
    client.write_all(&[*last]).await.expect("final payload byte");
    let head = response_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    let reached: Vec<_> = live
        .assembled
        .admin
        .handed
        .lock()
        .expect("recorded handlers")
        .iter()
        .map(|call| call.operation)
        .collect();
    assert_eq!(reached, [record.operation]);
    assert_eq!(
        *live.assembled.admin.stored_bodies.lock().expect("stored payloads"),
        [Bytes::from_static(BODY)]
    );
    live.stop().await;
}

/// Negative — legacy CORS answers OPTIONS before authentication, while an undecodable raw path
/// is InvalidURI before a fallback can authorize or run. These are profile ordering controls.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n_legacy_options_and_invalid_utf8_do_not_reach_fallbacks() {
    let live = Live::start();
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        for authorization in [None, Some("invalid-authorization")] {
            let mut request = Request::builder()
                .method("OPTIONS")
                .uri(format!("{prefix}/v4/gateway-absent"))
                .header("host", PATH_HOST);
            if let Some(value) = authorization {
                request = request.header("authorization", value);
            }
            let mut client = live.connect(&request.body(Bytes::new()).expect("OPTIONS fixture")).await;
            let head = response_head(&mut client).await;
            assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        }
        let request = Request::builder()
            .uri(format!("{prefix}/v4/%FF"))
            .header("host", PATH_HOST)
            .body(Bytes::new())
            .expect("raw path fixture");
        let mut client = live.connect(&request).await;
        let head = response_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 400 "), "{head}");
        assert!(response_body(&mut client, &head).await.contains("<Code>InvalidURI</Code>"));
    }
    assert!(live.assembled.admin.handed.lock().expect("recorded handlers").is_empty());
    assert!(live.assembled.asked.lock().expect("recorded policy").is_empty());
    live.stop().await;
}

/// Negative — decoding the address must not turn an encoded v4 spelling or a neighboring prefix
/// into the downgrade selector. Raw request targets are sent over the profile's server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n_encoded_prefixes_do_not_select_the_v4_downgrade() {
    let live = Live::start();
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        for (suffix, status) in [
            ("/v4/gateway-absent", 426),
            ("/v4/", 426),
            ("/%764/gateway-absent", 501),
            ("/v%34/gateway-absent", 501),
            ("/v4%2Fgateway-absent", 501),
            ("/v4-extra/gateway-absent", 501),
            ("/v4/a%2Fb", 426),
            ("/v4/a%5Cb", 426),
            ("/v4/%2e%2e", 426),
            ("/v4/%00", 426),
            ("/v4/a//b", 426),
            ("/v4/bad%zz", 426),
            ("/v4/%2500", 426),
        ] {
            let path = format!("{prefix}{suffix}");
            // The frozen native probes keep malformed escapes literal (#1314) and decode
            // escaped slashes for signing (#1315). Routing still receives the original target.
            let signing_path = path.replace("bad%zz", "bad%25zz").replace("%2F", "/");
            let fixture = ContextRequest::get(PATH_HOST, &signing_path, "").signed(REGION);
            let headers = fixture
                .wire_headers(super::RequestNow::capture())
                .unwrap_or_else(|error| panic!("{path}: {error}"));
            let mut request = fixture.http_head(&headers).body(Bytes::new()).expect("fixture head");
            *request.uri_mut() = path.parse().expect("original raw target");
            let mut client = live.connect(&request).await;
            let head = response_head(&mut client).await;
            let error_body = if head.starts_with(&format!("HTTP/1.1 {status} ")) {
                String::new()
            } else {
                response_body(&mut client, &head).await
            };
            assert!(head.starts_with(&format!("HTTP/1.1 {status} ")), "{path}: {head}{error_body}");
        }
    }
    {
        let calls = live.assembled.admin.handed.lock().expect("recorded handlers");
        assert_eq!(calls.len(), 26);
        assert_eq!(calls.iter().filter(|call| call.operation == "rustfs:AdminV4Fallback").count(), 18);
    }
    live.stop().await;
}

async fn response_body(client: &mut TcpStream, head: &str) -> String {
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().expect("response length"))
        })
        .expect("error body has a declared length");
    assert!(length < 64 * 1024);
    let mut body = vec![0; length];
    timeout(Duration::from_secs(5), client.read_exact(&mut body))
        .await
        .expect("body arrives")
        .expect("complete error body");
    String::from_utf8(body).expect("XML error")
}
