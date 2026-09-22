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

//! Responsible for: typed transport values surviving accepted request ownership transitions.
//! NOT responsible for: handler context assembly or protocol decoding.
//! Upstream: transport-installed extensions. Downstream: the read-only wire context.

use http::Request;
use rustfs_gateway_http::{Limits, WireRequest};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct TransportNote {
    clones: Arc<AtomicUsize>,
    value: &'static str,
}

impl Clone for TransportNote {
    fn clone(&self) -> Self {
        self.clones.fetch_add(1, Ordering::SeqCst);
        Self {
            clones: Arc::clone(&self.clones),
            value: self.value,
        }
    }
}

fn request() -> Request<()> {
    Request::builder()
        .uri("/bucket/key")
        .header("host", "s3.example.com")
        .body(())
        .expect("fixture request")
}

fn marked_wire() -> (WireRequest<()>, Arc<AtomicUsize>) {
    let clones = Arc::new(AtomicUsize::new(0));
    let mut request = request();
    request.extensions_mut().insert(TransportNote {
        clones: Arc::clone(&clones),
        value: "private-transport-note",
    });
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted fixture");
    (wire, clones)
}

#[test]
fn retained_transport_view_outlives_the_request_body() {
    let (wire, _) = marked_wire();
    let view = wire.transport_extensions().clone();
    drop(wire);
    assert_eq!(view.get::<TransportNote>().expect("retained value").value, "private-transport-note");
}

#[test]
fn acceptance_body_mapping_and_view_cloning_do_not_clone_transport_values() {
    let (wire, clones) = marked_wire();
    let view = wire.transport_extensions().clone();
    let mapped = wire.map_body(|()| 17_u8);
    assert_eq!(clones.load(Ordering::SeqCst), 0);
    assert!(core::ptr::eq(
        view.get::<TransportNote>().expect("original value"),
        mapped.transport_extensions().get::<TransportNote>().expect("mapped value"),
    ));
}

#[test]
fn absent_transport_types_are_not_substituted_or_recovered_from_headers() {
    let (wire, _) = marked_wire();
    assert!(wire.transport_extensions().get::<String>().is_none());
    let mut request = request();
    request
        .headers_mut()
        .insert("x-transport-note", http::HeaderValue::from_static("private-transport-note"));
    let empty = WireRequest::accept(request, &Limits::default()).expect("header is unrelated");
    assert!(empty.transport_extensions().get::<TransportNote>().is_none());
    assert!(empty.transport_extensions().get::<usize>().is_none());
}

#[test]
fn wire_and_view_debug_never_format_transport_values() {
    let (wire, _) = marked_wire();
    for rendered in [format!("{wire:?}"), format!("{:?}", wire.transport_extensions())] {
        assert!(!rendered.contains("private-transport-note"));
    }
}
