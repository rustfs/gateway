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

//! Fuzzes `rustfs-gateway-server`'s `HyperConnectionDriver`, HTTP/1.1 & HTTP/2 preface handling,
//! `PrefixDispatch`, and connection admission over a real loopback socket.
//!
//! Responsible for: sending arbitrary wire bytes (including HTTP/1.1, HTTP/2 client prefaces,
//! pipelined/chunked bodies, and truncated frames) through `Server` + `HyperConnectionDriver` +
//! `PrefixDispatch` without panicking or stalling the listener.
//! NOT responsible for: `SelfHeldHttp1Driver` (`self_held_http1.rs`) or S3 protocol semantics.
//! Upstream: libFuzzer bytes written over loopback TCP. Downstream: `rustfs-gateway-server`.

#![no_main]

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use http::{Request, Response};
use http_body_util::BodyExt;
use libfuzzer_sys::fuzz_target;
use rustfs_gateway::Body;
use rustfs_gateway_server::{HyperConnectionDriver, PrefixDispatch, RunningServer, Server, ServerConfig, conn_memory_budget};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

fn listener() -> &'static (Runtime, SocketAddr) {
    static LISTENER: OnceLock<(Runtime, SocketAddr)> = OnceLock::new();
    LISTENER.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("fuzz runtime starts");
        let address = runtime.block_on(async {
            let config = ServerConfig {
                bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                plaintext: true,
                header_read_timeout: Duration::from_secs(1),
                keep_alive_idle: Duration::from_secs(1),
                lingering_close_time: Duration::from_millis(50),
                ..ServerConfig::default()
            };
            let _ = conn_memory_budget(config.max_connections);
            let admin = tower::service_fn(|request: Request<hyper::body::Incoming>| async move {
                let len = request.into_body().collect().await.map_or(0, |c| c.to_bytes().len());
                Ok::<_, Infallible>(Response::new(Body::from(format!("admin:{len}").into_bytes())))
            });
            let fallback = tower::service_fn(|request: Request<hyper::body::Incoming>| async move {
                let len = request.into_body().collect().await.map_or(0, |c| c.to_bytes().len());
                Ok::<_, Infallible>(Response::new(Body::from(format!("s3:{len}").into_bytes())))
            });
            let dispatch = PrefixDispatch::new(vec![("/rustfs/admin", admin)], fallback);
            let running: RunningServer = Server::new(config, dispatch)
                .serve_with(HyperConnectionDriver)
                .expect("hyper server fuzz listener starts");
            let address = running.local_addr;
            std::mem::forget(running);
            address
        });
        (runtime, address)
    })
}

fuzz_target!(|input: &[u8]| {
    let (runtime, address) = listener();
    runtime.block_on(async {
        let mut stream = TcpStream::connect(address).await.expect("listener still accepts");
        stream.set_zero_linger().expect("SO_LINGER=0");
        let _ = stream.write_all(input).await;
        let _ = stream.shutdown().await;
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await;
    });
});
