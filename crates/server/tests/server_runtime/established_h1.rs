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

//! Responsible for: the established-H1 shutdown fixture and its lease checkpoints.
//! NOT responsible for: production accept-loop behavior or TLS shutdown.
//! Upstream: runtime and load-isolation tests. Downstream: the public server API and TCP client.

use super::listener_stop::wait_for_listener_stop;
use super::*;

pub(crate) async fn observed_established_h1_shutdown(mut checkpoint: impl FnMut()) {
    let _exclusive_load_lease = crate::server_load::exclusive_server_load_lease().await;
    checkpoint();
    let entered = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let release = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let service = service_fn({
        let entered = std::sync::Arc::clone(&entered);
        let release = std::sync::Arc::clone(&release);
        move |_request: Request<hyper::body::Incoming>| {
            let entered = std::sync::Arc::clone(&entered);
            let release = std::sync::Arc::clone(&release);
            async move {
                entered.wait().await;
                release.wait().await;
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        }
    });
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(plaintext_config(), service).serve().expect("server starts");
    let mut stream = TcpStream::connect(local_addr).await.expect("connect succeeds");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    entered.wait().await;
    let shutdown_task = tokio::spawn(shutdown.trigger(Duration::from_secs(5)));
    wait_for_listener_stop(|| async { TcpStream::connect(local_addr).await.map(drop) })
        .await
        .expect("shutdown has stopped accept before the handler is released");
    assert!(!shutdown_task.is_finished(), "shutdown is still draining the established request");
    release.wait().await;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("draining response reads");
    let lower = String::from_utf8_lossy(&response).to_ascii_lowercase();
    assert!(lower.contains("connection: close"));
    assert_eq!(
        shutdown_task.await.expect("shutdown task joins"),
        ShutdownReport { drained: 1, aborted: 0 }
    );
    assert!(task.await.expect("server task joins").is_ok());
    checkpoint();
}
