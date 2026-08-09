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

//! The one per-request configuration snapshot and its hot-update handle.
//!
//! Responsible for: proving a mid-request update cannot change the buffered-body ceiling already
//! chosen for that request, while the next request observes it.
//! NOT responsible for: body-ceiling mechanics, which `crate::gate` tests directly.
//! Upstream: `rustfs-gateway`. Downstream: nothing.

mod support;

use std::sync::Arc;
use std::sync::Mutex;

use bytes::Bytes;
use rustfs_gateway::{ConfigHandle, S3Error, ServiceConfig, StageFilter, WireHead};
use support::{Backend, ContentPing, content_ping_route, wired};

/// A wire filter that updates the service configuration after request entry.
///
/// If the service loads configuration again at a later stage, this update incorrectly widens the
/// current request. Loading once at request entry keeps the old ceiling for the whole pipeline.
struct UpdatingFilter {
    update: Mutex<Option<(ConfigHandle, ServiceConfig)>>,
}

impl UpdatingFilter {
    fn new(update: ConfigHandle, config: ServiceConfig) -> Self {
        Self {
            update: Mutex::new(Some((update, config))),
        }
    }
}

impl StageFilter for UpdatingFilter {
    fn on_wire(&self, _head: &mut WireHead<'_>) -> Result<(), S3Error> {
        if let Some((handle, config)) = self.update.lock().expect("not poisoned").take() {
            handle.store(config);
        }
        Ok(())
    }
}

/// a-asm-0006. A request observes one configuration snapshot even when the handle is updated
/// while its body is being polled; the following request observes the replacement.
#[tokio::test]
async fn a_hot_update_does_not_tear_an_inflight_request() {
    let (builder, handle) = wired().config(ServiceConfig::new(8));
    let service = builder
        .register::<ContentPing, _>(Arc::new(Backend))
        .route(content_ping_route())
        .stage_filter(UpdatingFilter::new(handle.clone(), ServiceConfig::new(32)))
        .build()
        .expect("a complete assembly");

    let first = http::Request::builder()
        .method(http::Method::PUT)
        .uri("/")
        .header("host", "s3.example.com")
        .body(http_body_util::Full::new(Bytes::from_static(b"sixteen-byte-body")))
        .expect("a valid request");
    let first = service.call(first).await;
    assert_eq!(first.status(), http::StatusCode::PAYLOAD_TOO_LARGE);

    let second = http::Request::builder()
        .method(http::Method::PUT)
        .uri("/")
        .header("host", "s3.example.com")
        .body(http_body_util::Full::new(Bytes::from_static(b"sixteen-byte-body")))
        .expect("a valid request");
    let second = service.call(second).await;
    assert_eq!(second.status(), http::StatusCode::OK);
}

/// a-asm-0007. Reconfiguring a builder does not detach a handle already handed to the caller.
#[tokio::test]
async fn an_earlier_handle_still_updates_after_config_is_called_again() {
    let (builder, first_handle) = wired().config(ServiceConfig::new(8));
    let (builder, _second_handle) = builder.config(ServiceConfig::new(16));
    first_handle.store(ServiceConfig::new(32));
    let service = builder
        .register::<ContentPing, _>(Arc::new(Backend))
        .route(content_ping_route())
        .build()
        .expect("a complete assembly");

    let request = http::Request::builder()
        .method(http::Method::PUT)
        .uri("/")
        .header("host", "s3.example.com")
        .body(http_body_util::Full::new(Bytes::from_static(b"twenty-four-byte-payload")))
        .expect("a valid request");
    let response = service.call(request).await;
    assert_eq!(response.status(), http::StatusCode::OK);
}
