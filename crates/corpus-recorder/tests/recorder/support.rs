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

//! Responsible for: the fixtures every recorder suite shares — a checked recorder over a scratch
//! file, a multi-frame body, an inner service that reports exactly what it received, and waiting
//! for the writer thread.
//! Not responsible for: any assertion.
//! Upstream: the suites beside it.
//! Downstream: `rustfs_gateway_corpus_recorder`.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame};
use rustfs_gateway_corpus::schema::{self, Entry};
use rustfs_gateway_corpus_recorder::{CorpusRecorderLayer, RECORD_ENV, RecorderConfig, RecorderStats, Sut};

/// A test access key that is on the allowlist.
pub(crate) const TEST_KEY: &str = "compatmatrixkey";

/// The environment a recorder is allowed to start in.
pub(crate) fn enabled(name: &str) -> Option<String> {
    (name == RECORD_ENV).then(|| "1".to_owned())
}

/// A fresh scratch directory for one test.
pub(crate) fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("corpus-recorder-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    path
}

/// A configuration writing to `<scratch>/out.jsonl`.
pub(crate) fn config(name: &str) -> RecorderConfig {
    RecorderConfig::new(
        scratch(name).join("out.jsonl"),
        "handwritten:gateway",
        Sut::GatewayFsReference,
        vec![TEST_KEY.to_owned()],
    )
}

/// A recorder that passed the runtime gate.
pub(crate) fn recorder(config: RecorderConfig) -> CorpusRecorderLayer {
    CorpusRecorderLayer::new_checked_with_env(config, enabled).expect("an enabled recorder over a test credential")
}

/// Waits until every request the recorder has seen has reached an outcome counter.
pub(crate) async fn settle(layer: &CorpusRecorderLayer, finished: u64) -> RecorderStats {
    for _ in 0..500 {
        let stats = layer.stats();
        if stats.recorded + stats.refused + stats.dropped_queue_full + stats.write_errors >= finished {
            return stats;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the writer did not finish {finished} record(s): {:?}", layer.stats());
}

/// Every entry in the recorder's output file.
pub(crate) fn entries(config: &RecorderConfig) -> Vec<Entry> {
    let text = std::fs::read_to_string(&config.output).unwrap_or_default();
    schema::load_jsonl(&text).expect("the recorder writes loadable JSONL")
}

/// A body delivered as the given frames, in order.
///
/// `announces_end` decides whether `is_end_stream` turns true after the last frame, as a body of
/// known length does, or stays false until a poll returns `None`, as a chunked one does.
pub(crate) struct Frames {
    frames: VecDeque<Bytes>,
    announces_end: bool,
}

impl Frames {
    pub(crate) fn of(parts: &[&[u8]]) -> Self {
        Self {
            frames: parts.iter().map(|part| Bytes::copy_from_slice(part)).collect(),
            announces_end: true,
        }
    }

    pub(crate) fn unannounced(parts: &[&[u8]]) -> Self {
        Self {
            announces_end: false,
            ..Self::of(parts)
        }
    }
}

impl Body for Frames {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.frames.pop_front().map(|bytes| Ok(Frame::data(bytes))))
    }

    fn is_end_stream(&self) -> bool {
        self.announces_end && self.frames.is_empty()
    }
}

/// The request every fixture service takes.
pub(crate) type Tapped = http::Request<rustfs_gateway_corpus_recorder::TapBody<Frames>>;

/// The future every boxed fixture service returns.
pub(crate) type Answer = Pin<Box<dyn std::future::Future<Output = Result<http::Response<String>, Infallible>> + Send>>;

/// What an inner service received.
#[derive(Clone, Default)]
pub(crate) struct Seen(pub Arc<Mutex<Vec<Vec<u8>>>>);

impl Seen {
    pub(crate) fn frames(&self) -> Vec<Vec<u8>> {
        self.0.lock().expect("never poisoned").clone()
    }
}

/// An inner service that reads the whole body frame by frame, remembers each frame, and answers
/// 200 with a `set-cookie` the recorder must redact.
pub(crate) fn reading_service(
    seen: Seen,
) -> impl tower::Service<Tapped, Response = http::Response<String>, Error = Infallible, Future = Answer> + Clone {
    tower::service_fn(move |request: Tapped| {
        let seen = seen.clone();
        let fut: Answer = Box::pin(async move {
            let mut body = request.into_body();
            while let Some(frame) = http_body_util::BodyExt::frame(&mut body).await {
                if let Ok(data) = frame.expect("an infallible body").into_data() {
                    seen.0.lock().expect("never poisoned").push(data.to_vec());
                }
            }
            Ok(http::Response::builder()
                .status(200)
                .header("set-cookie", "session=live-cookie-value")
                .body(String::new())
                .expect("a valid response"))
        });
        fut
    })
}

/// An inner service that reads frames only while `is_end_stream` is false, and never polls for
/// the final `None`.
pub(crate) fn stop_at_end_service()
-> impl tower::Service<Tapped, Response = http::Response<String>, Error = Infallible, Future = Answer> + Clone {
    tower::service_fn(|request: Tapped| {
        let fut: Answer = Box::pin(async move {
            let mut body = request.into_body();
            while !body.is_end_stream() {
                if http_body_util::BodyExt::frame(&mut body).await.is_none() {
                    break;
                }
            }
            Ok(http::Response::builder()
                .status(200)
                .body(String::new())
                .expect("a valid response"))
        });
        fut
    })
}

/// An inner service that answers without reading the body.
pub(crate) fn ignoring_service() -> impl tower::Service<
    Tapped,
    Response = http::Response<String>,
    Error = Infallible,
    Future = std::future::Ready<Result<http::Response<String>, Infallible>>,
> + Clone {
    tower::service_fn(|_request: Tapped| {
        std::future::ready(Ok(http::Response::builder()
            .status(403)
            .body(String::new())
            .expect("a valid response")))
    })
}

/// A request with the given method, target and headers over a framed body.
pub(crate) fn request(method: &str, target: &str, headers: &[(&str, &str)], body: Frames) -> http::Request<Frames> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(target)
        .header("host", "127.0.0.1:9000");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(body).expect("a valid request")
}
