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

//! Allocation ceilings and reviewable timing records for the generated wire codecs.
//!
//! Responsible for: rustfs/backlog#1766's `xml/serialize_list_objects_1000`,
//! `xml/deserialize_delete_objects_1000` and `encode/get_object_response_head` rows — how many
//! heap blocks one encode or decode costs, held to a committed ceiling, and how long it takes,
//! printed and never asserted.
//! NOT responsible for: codec correctness, which the roundtrip suites own, or a time threshold.
//! Upstream: the generated codecs through `OperationCodec`. Downstream: `perf-evidence.yml`.

use std::hint::black_box;
use std::time::Instant;

use bytes::Bytes;
use http::Request;
use rustfs_gateway_core::MetaView;
use rustfs_gateway_core::codec::{OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto::{self, DeleteObjects, GetObject, ListObjectsV2};
use rustfs_gateway_types::{BucketName, ETag, ObjectKey, Timestamp};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const KEYS: usize = 1_000;

fn accepted(method: &str, target: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

fn listing() -> dto::ListObjectsV2Output {
    let contents = (0..KEYS)
        .map(|index| dto::Object {
            key: ObjectKey::new(format!("photos/2026/09/{index:06}.jpg")).expect("a key"),
            last_modified: Timestamp::from_secs(1_767_225_600 + index as i64),
            e_tag: ETag::new(format!("\"{index:032x}\"")).expect("an entity tag"),
            size: 4096 + index as i64,
            ..dto::Object::default()
        })
        .collect();
    dto::ListObjectsV2Output {
        name: BucketName::new("bucket").expect("a bucket name"),
        max_keys: 1_000,
        key_count: KEYS as i32,
        is_truncated: false,
        contents,
        ..dto::ListObjectsV2Output::default()
    }
}

fn delete_document() -> Bytes {
    let mut xml = String::from("<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Quiet>true</Quiet>");
    for index in 0..KEYS {
        xml.push_str(&format!("<Object><Key>photos/2026/09/{index:06}.jpg</Key></Object>"));
    }
    xml.push_str("</Delete>");
    Bytes::from(xml)
}

/// The `Content-MD5` DeleteObjects requires, computed here rather than borrowed from the codec.
fn content_md5(document: &[u8]) -> String {
    use md5::{Digest, Md5};
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let digest = Md5::digest(document);
    let mut out = String::new();
    for chunk in digest.chunks(3) {
        let bytes = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        for (index, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Blocks and bytes one `action` allocates.
fn allocations(action: impl FnOnce()) -> (u64, u64) {
    let profiler = dhat::Profiler::builder().testing().build();
    action();
    let stats = dhat::HeapStats::get();
    drop(profiler);
    (stats.total_blocks, stats.total_bytes)
}

fn gate(name: &str, ceiling: u64, (blocks, bytes): (u64, u64)) {
    println!("{name}: {blocks} allocs, {bytes} bytes (ceiling {ceiling} allocs)");
    assert!(
        blocks <= ceiling,
        "{name} allocated {blocks} heap blocks, past its committed ceiling of {ceiling}"
    );
    assert!(
        blocks > 0 || ceiling == 0,
        "{name} observed no allocation at all; is the dhat allocator installed?"
    );
}

fn record_time(name: &str, iterations: u32, mut action: impl FnMut()) {
    let started = Instant::now();
    for _ in 0..iterations {
        action();
    }
    let micros = started.elapsed().as_secs_f64() * 1_000_000.0 / f64::from(iterations);
    println!("{name}: {micros:.3} us/iteration ({iterations} iterations; record-only, non-blocking)");
}

fn main() {
    let list_request = accepted("GET", "/bucket?list-type=2", &[]);
    let list_view = MetaView::of(&list_request, TargetKind::Bucket).expect("a bucket view");
    let document = delete_document();
    let content_md5 = content_md5(&document);
    let delete_request = accepted("POST", "/bucket?delete", &[("content-md5", content_md5.as_str())]);
    let delete_view = MetaView::of(&delete_request, TargetKind::Bucket).expect("a bucket view");
    let get_request = accepted("GET", "/bucket/key", &[]);
    let get_view = MetaView::of(&get_request, TargetKind::Object).expect("an object view");
    let head = || dto::GetObjectOutput {
        content_length: Some(4096),
        e_tag: Some(ETag::new("\"0123456789abcdef0123456789abcdef\"").expect("an entity tag")),
        last_modified: Some(Timestamp::from_secs(1_767_225_600)),
        content_type: Some("image/jpeg".to_owned()),
        ..dto::GetObjectOutput::default()
    };

    // Warm every lazily initialised table before the first window.
    black_box(ListObjectsV2::encode(listing(), &list_view, 200).expect("the listing encodes"));
    black_box(DeleteObjects::decode(&delete_view, RequestBody::Buffered(document.clone())).expect("the document decodes"));
    black_box(GetObject::encode(head(), &get_view, 200).expect("the head encodes"));

    let output = listing();
    gate(
        "xml/serialize_list_objects_1000",
        LIST_ENCODE_CEILING,
        allocations(|| {
            black_box(ListObjectsV2::encode(output, &list_view, 200).expect("the listing encodes"));
        }),
    );
    let body = document.clone();
    gate(
        "xml/deserialize_delete_objects_1000",
        DELETE_DECODE_CEILING,
        allocations(|| {
            black_box(DeleteObjects::decode(&delete_view, RequestBody::Buffered(body)).expect("the document decodes"));
        }),
    );
    let output = head();
    gate(
        "encode/get_object_response_head",
        GET_HEAD_CEILING,
        allocations(|| {
            black_box(GetObject::encode(output, &get_view, 200).expect("the head encodes"));
        }),
    );

    record_time("xml/serialize_list_objects_1000", 200, || {
        black_box(ListObjectsV2::encode(listing(), &list_view, 200).expect("the listing encodes"));
    });
    record_time("xml/deserialize_delete_objects_1000", 200, || {
        black_box(DeleteObjects::decode(&delete_view, RequestBody::Buffered(document.clone())).expect("decodes"));
    });
    record_time("encode/get_object_response_head", 100_000, || {
        black_box(GetObject::encode(head(), &get_view, 200).expect("the head encodes"));
    });
}

/// Committed ceilings, measured on this revision; they may only be lowered.
const LIST_ENCODE_CEILING: u64 = 6_021;
const DELETE_DECODE_CEILING: u64 = 5_045;
const GET_HEAD_CEILING: u64 = 11;
