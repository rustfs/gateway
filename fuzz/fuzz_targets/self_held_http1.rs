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

//! Exercises the self-held HTTP/1.1 driver's request parsing with arbitrary bytes on a real
//! loopback socket: request heads, `Content-Length` and chunked bodies with trailers,
//! `Expect`, pipelined requests and truncated input, through the production driver.
//! It does not check what a well-formed request is answered: `crates/gateway/tests/self_held_http1.rs`
//! does. A panic anywhere in the driver aborts the process, as libFuzzer's panic hook arranges,
//! and a listener that stops accepting fails the next input's connect.
//! Upstream: libFuzzer bytes, written to one fresh connection each, then the write side closed.
//! Downstream: `rustfs-gateway`'s `SelfHeldHttp1Driver` (rustfs/gateway#1223).

#![no_main]

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use http::{Request, Response};
use http_body_util::BodyExt;
use libfuzzer_sys::fuzz_target;
use rustfs_gateway::{Body, SelfHeldHttp1Driver, SelfHeldRequestBody};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

/// One runtime and one listener for the whole run: a server per input would fuzz start-up.
fn listener() -> &'static (Runtime, SocketAddr) {
    static LISTENER: OnceLock<(Runtime, SocketAddr)> = OnceLock::new();
    LISTENER.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the fuzz runtime starts");
        let address = runtime.block_on(async {
            let config = ServerConfig {
                bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                plaintext: true,
                header_read_timeout: Duration::from_secs(1),
                keep_alive_idle: Duration::from_secs(1),
                lingering_close_time: Duration::from_millis(50),
                ..ServerConfig::default()
            };
            // Reads every body to its end, trailers included, so body framing is decoded too.
            let service = tower::service_fn(|request: Request<SelfHeldRequestBody>| async move {
                let length = match request.into_body().collect().await {
                    Ok(collected) => collected.to_bytes().len(),
                    Err(_) => 0,
                };
                Ok::<_, Infallible>(Response::new(Body::from(length.to_string().into_bytes())))
            });
            let running: RunningServer = Server::new(config, service)
                .serve_with(SelfHeldHttp1Driver)
                .expect("the fuzz listener starts");
            let address = running.local_addr;
            // The listener lives for the process; its handle is deliberately leaked.
            std::mem::forget(running);
            address
        });
        (runtime, address)
    })
}

fuzz_target!(|input: &[u8]| {
    let (runtime, address) = listener();
    runtime.block_on(async {
        let mut stream = TcpStream::connect(address).await.expect("the listener still accepts");
        // An abortive close on the client side leaves no TIME_WAIT behind, so a run of thousands of
        // connections a second does not exhaust the loopback's ephemeral ports.
        stream.set_zero_linger().expect("the client socket takes SO_LINGER");
        let _ = stream.write_all(input).await;
        let _ = stream.shutdown().await;
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await;
    });
});
