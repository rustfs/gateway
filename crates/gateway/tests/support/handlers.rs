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

//! Handler implementations shared by the gateway integration fixtures.
//!
//! Responsible for: keeping each shared fixture backend's legacy and context-aware entries
//! equivalent during the backlog#1861 migration. NOT responsible for: operation codecs, routes,
//! or assertions. Upstream: the fixture types in `super`. Downstream: every integration suite that
//! assembles those backends.

use super::*;

impl Handler<ContentPing> for Backend {
    async fn call(&self, request: Req<ContentPing>) -> HandlerResult<ContentPing> {
        answer_ping(request.input())
    }

    async fn call_with_context(
        &self,
        request: Req<ContentPing>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<ContentPing> {
        answer_ping(request.input())
    }
}

impl Handler<HeadPing> for Backend {
    async fn call(&self, request: Req<HeadPing>) -> HandlerResult<HeadPing> {
        answer_ping(request.input())
    }

    async fn call_with_context(
        &self,
        request: Req<HeadPing>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<HeadPing> {
        answer_ping(request.input())
    }
}

impl Handler<Ping> for Backend {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }

    async fn call_with_context(&self, _request: Req<Ping>, _context: rustfs_gateway::HandlerContext) -> HandlerResult<Ping> {
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }
}

impl Handler<ListBuckets> for Backend {
    async fn call(&self, _request: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
        Ok(Resp::new(ListBucketsOutput {
            buckets: vec![Bucket {
                name: BucketName::new("alpha").expect("a valid bucket name"),
                // A real instant, not the default: `CreationDate` is bound to an ISO-8601
                // rendering, and the zero value has none — so a fixture that left it default
                // answered `500 InternalError` the first time anything managed to sign a request
                // and reach the encoder.
                creation_date: rustfs_gateway::Timestamp::from_secs(SIGNED_AT_UNIX_SECONDS),
                ..Bucket::default()
            }],
            ..ListBucketsOutput::default()
        }))
    }

    async fn call_with_context(
        &self,
        _request: Req<ListBuckets>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<ListBuckets> {
        Ok(Resp::new(ListBucketsOutput {
            buckets: vec![Bucket {
                name: BucketName::new("alpha").expect("a valid bucket name"),
                // A real instant, not the default: `CreationDate` is bound to an ISO-8601
                // rendering, and the zero value has none — so a fixture that left it default
                // answered `500 InternalError` the first time anything managed to sign a request
                // and reach the encoder.
                creation_date: rustfs_gateway::Timestamp::from_secs(SIGNED_AT_UNIX_SECONDS),
                ..Bucket::default()
            }],
            ..ListBucketsOutput::default()
        }))
    }
}

impl Handler<Unnamespaced> for Backend {
    async fn call(&self, _request: Req<Unnamespaced>) -> HandlerResult<Unnamespaced> {
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }

    async fn call_with_context(
        &self,
        _request: Req<Unnamespaced>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<Unnamespaced> {
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }
}

impl Handler<Impostor> for Backend {
    async fn call(&self, _request: Req<Impostor>) -> HandlerResult<Impostor> {
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }

    async fn call_with_context(
        &self,
        _request: Req<Impostor>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<Impostor> {
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }
}

impl Handler<Ping> for CountingBackend {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        self.reached.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }

    async fn call_with_context(&self, _request: Req<Ping>, _context: rustfs_gateway::HandlerContext) -> HandlerResult<Ping> {
        self.reached.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }
}

impl Handler<Ping> for Failing {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        Err(HandlerError::internal_error("the backend is not available"))
    }

    async fn call_with_context(&self, _request: Req<Ping>, _context: rustfs_gateway::HandlerContext) -> HandlerResult<Ping> {
        Err(HandlerError::internal_error("the backend is not available"))
    }
}

impl Handler<rustfs_gateway::dto::GetObjectAttributes> for Attributes {
    async fn call(
        &self,
        _request: Req<rustfs_gateway::dto::GetObjectAttributes>,
    ) -> HandlerResult<rustfs_gateway::dto::GetObjectAttributes> {
        Ok(Resp::new(rustfs_gateway::dto::GetObjectAttributesOutput {
            e_tag: Some(rustfs_gateway::ETag::new(BACKEND_ETAG).expect("a valid entity tag")),
            ..rustfs_gateway::dto::GetObjectAttributesOutput::default()
        }))
    }

    async fn call_with_context(
        &self,
        _request: Req<rustfs_gateway::dto::GetObjectAttributes>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<rustfs_gateway::dto::GetObjectAttributes> {
        Ok(Resp::new(rustfs_gateway::dto::GetObjectAttributesOutput {
            e_tag: Some(rustfs_gateway::ETag::new(BACKEND_ETAG).expect("a valid entity tag")),
            ..rustfs_gateway::dto::GetObjectAttributesOutput::default()
        }))
    }
}
