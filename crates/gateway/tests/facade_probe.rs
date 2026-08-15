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

//! Every facade export the conformance runner names, checked by naming it.
//!
//! Responsible for: proving that `rustfs_gateway::…` resolves for each entry of the runner's
//! `REQUIRED_FACADE_EXPORTS`, so that the list and this crate cannot drift apart silently.
//! NOT responsible for: exercising any of them; that is `tests/pipeline.rs`.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! `rustfs_gateway::sig::Signer` is an alias for `rustfs-gateway-sig`'s `SigV4Signer`, so that the
//! name the runner asks for resolves whatever the signature crate calls its own type.

#[allow(unused_imports)]
use rustfs_gateway::{
    Body, ByteStream, Clock, Credentials, HandlerResult, Req, Resp, RouterBuilder, S3Service, ServiceBuilder, Transport,
    WireRequest, WireResponse, dto::GetObject, handlers,
};

struct FacadeMacroBackend;

#[handlers]
impl FacadeMacroBackend {
    async fn get_object(&self, _request: Req<GetObject>) -> HandlerResult<GetObject> {
        Ok(Resp::new(rustfs_gateway::dto::GetObjectOutput::default()))
    }
}

/// Positive — every required export resolves, and the two that carry values round-trip.
#[test]
fn every_required_facade_export_resolves() {
    // ServiceBuilder — assemble a service and run it in process.
    let _: fn() -> ServiceBuilder = ServiceBuilder::new;
    // Transport — the assembly path the runner injects.
    assert_eq!(Transport::parse("hyper"), Some(Transport::Hyper));
    assert_eq!(Transport::parse("conn"), Some(Transport::Conn));
    // WireRequest / WireResponse — submit raw bytes, read the head, body and trailers back.
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(bytes::Bytes::new())
        .expect("a valid request");
    let accepted = WireRequest::accept(request, &rustfs_gateway::Limits::default()).expect("acceptable");
    assert_eq!(accepted.raw_path().as_str(), "/");
    let _: fn(&WireResponse) -> &[(http::HeaderName, http::HeaderValue)] = WireResponse::headers;
    // Body / ByteStream — feed a chunk sequence, observe what was consumed.
    assert!(Body::empty().is_empty());
    assert_eq!(ByteStream::from_bytes(bytes::Bytes::from_static(b"ab")).observed_length(), 0);
    // Clock — inject a fixed reading.
    let clock = rustfs_gateway::FixedClock::at_unix_seconds(1_440_938_160);
    assert_eq!(clock.now().unix_seconds(), 1_440_938_160);
    // Credentials — the fixture credentials a case names.
    let credentials = Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id");
    assert_eq!(credentials.identity().access_key_id(), "AKIDEXAMPLE");
    // sig::Signer — the client-side signer the runner needs to build a signed request.
    let _: Option<rustfs_gateway::sig::Signer> = None;
    // S3Service — the thing all of the above exist to drive.
    let _: fn(&S3Service) -> &rustfs_gateway::Limits = S3Service::limits;
}

/// The optional registration macro is re-exported beside its handler types.
#[test]
fn handlers_macro_is_reexported_by_the_facade() {
    let _: fn(&std::sync::Arc<FacadeMacroBackend>, RouterBuilder) -> RouterBuilder = FacadeMacroBackend::register;
}
