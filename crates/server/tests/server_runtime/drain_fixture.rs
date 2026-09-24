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

//! Responsible for: the healthy shutdown drain fixture and its lease checkpoints.
//! NOT responsible for: load orchestration or production shutdown accounting.
//! Upstream: runtime and isolation tests. Downstream: the public server API and real TCP client.

use super::*;

pub(crate) async fn observed_shutdown_drain(mut checkpoint: impl FnMut()) {
    let _exclusive_load_lease = crate::server_load::exclusive_server_load_lease().await;
    checkpoint();
    const EXPECTED_BODY_LEN: usize = 100 * 1024 * 1024;
    let handler_entered = Arc::new(Notify::new());
    let service = service_fn({
        let handler_entered = Arc::clone(&handler_entered);
        move |_request: Request<hyper::body::Incoming>| {
            let handler_entered = Arc::clone(&handler_entered);
            async move {
                handler_entered.notify_one();
                tokio::time::sleep(Duration::from_millis(40)).await;
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(vec![b'x'; 100 * 1024 * 1024]))))
            }
        }
    });
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(plaintext_config(), service).serve().expect("server starts");
    let client = tokio::spawn(get(local_addr));
    tokio::time::timeout(Duration::from_secs(1), handler_entered.notified())
        .await
        .expect("the handler starts before shutdown");
    let report = shutdown.trigger(Duration::from_secs(2)).await;
    assert_eq!(report, ShutdownReport { drained: 1, aborted: 0 });
    let response = client.await.expect("client task completes");
    let body_start = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .expect("response has a complete HTTP head");
    assert!(response[..body_start].starts_with(b"HTTP/1.1 200"));
    let body = &response[body_start..];
    assert_eq!(body.len(), EXPECTED_BODY_LEN, "graceful shutdown drains the complete response body");
    assert!(body.iter().all(|byte| *byte == b'x'));
    assert!(task.await.expect("server task joins").is_ok());
    checkpoint();
}
