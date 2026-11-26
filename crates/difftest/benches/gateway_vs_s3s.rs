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

//! Head-to-head allocation, latency, and throughput comparison between `rustfs-gateway` and the
//! pinned `s3s` oracle across five core S3 operations: `GetObject`, `PutObject`, `ListObjectsV2`,
//! `DeleteObjects`, and `PostObject`.
//!
//! Responsible for: driving identical in-memory requests and minimal no-op backends through both
//! assembled services, verifying functional response invariants, measuring per-request heap
//! allocations via `dhat`, and printing non-blocking latency and throughput records.
//! NOT responsible for: disk/socket I/O, protocol conformance (owned by `crates/conformance`),
//! decode/encode diffing (owned by `src/decode.rs` and `src/encode.rs`), or a timing CI gate.
//! Upstream: `rustfs-gateway` and `rustfs-gateway-types`' `compat::s3s_0_17_0` seam.
//! Downstream: `.github/workflows/perf-evidence.yml` and manual comparison runs via
//! `cargo bench -p rustfs-gateway-difftest --bench gateway_vs_s3s`.

use std::error::Error;
use std::hint::black_box;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use http_body_util::BodyExt;
use md5::{Digest as _, Md5};
use rustfs_gateway::{RequestNow, S3Service};
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{
    AmzDate, EMPTY_PAYLOAD_SHA256_HEX, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope,
    TrailerSet,
};
use rustfs_gateway_types::compat::s3s_0_17_0::s3s;

#[path = "gateway_vs_s3s/backends.rs"]
mod backends;
use backends::{
    ACCESS_KEY, BUCKET, GatewayBackend, LIST_KEYS, REGION, S3sBackend, SECRET_KEY, SingleChunkBody, build_gateway, build_s3s,
};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const HOST: &str = "bench.invalid";
const KEY: &str = "objects/sample.bin";
const BOUNDARY: &str = "gateway-vs-s3s-boundary";
const PAYLOAD_BYTES: usize = 64 * 1024;
const DELETE_KEYS: usize = 100;

struct RequestTemplate {
    method: Method,
    uri: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
}

impl RequestTemplate {
    fn for_gateway(&self) -> Result<Request<SingleChunkBody>, Box<dyn Error>> {
        let mut builder = Request::builder().method(self.method.clone()).uri(&self.uri);
        for (name, value) in &self.headers {
            builder = builder.header(name, value);
        }
        Ok(builder.body(SingleChunkBody::new(self.body.clone()))?)
    }

    fn for_s3s(&self) -> Result<Request<s3s::Body>, Box<dyn Error>> {
        let mut builder = Request::builder().method(self.method.clone()).uri(&self.uri);
        for (name, value) in &self.headers {
            builder = builder.header(name, value);
        }
        let stream: s3s::stream::DynByteStream = Box::pin(SingleChunkBody::new(self.body.clone()));
        Ok(builder.body(s3s::Body::from(stream))?)
    }
}

fn amz_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let second_of_day = unix.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60
    )
}

fn base64_md5(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let digest = Md5::digest(data);
    let mut out = String::with_capacity(24);
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

fn signed_template(
    method: Method,
    path: &str,
    query: &str,
    extra_headers: &[(&str, &str)],
    payload_mode: PayloadMode,
    body: Bytes,
) -> Result<RequestTemplate, Box<dyn Error>> {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static(HOST));
    for (name, value) in extra_headers {
        headers.insert(HeaderName::from_bytes(name.as_bytes())?, HeaderValue::from_str(value)?);
    }
    if !body.is_empty() {
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    }
    let raw_host = RawHost::from_host_header(HOST.as_bytes()).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let stamp =
        AmzDate::parse(&amz_date(RequestNow::capture().unix_seconds())).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let scope = SigningScope::new(stamp.day(), REGION, SigService::S3).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let creds = SigningCredentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let mut signer = SigV4Signer::new(creds, scope);
    let mut signing = SigningRequest::new(&method, path, query, &headers, &raw_host, payload_mode, stamp);
    if !body.is_empty() {
        signing = signing.with_wire_content_length(body.len() as u64);
    }
    let signed = signer
        .sign_headers(&signing)
        .map_err(|e| io::Error::other(format!("{e:?}")))?;
    let uri = if query.is_empty() {
        format!("http://{HOST}{path}")
    } else {
        format!("http://{HOST}{path}?{query}")
    };
    let header_pairs = signed
        .headers()
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    Ok(RequestTemplate {
        method,
        uri,
        headers: header_pairs,
        body,
    })
}

fn post_object_template(payload: &[u8]) -> Result<RequestTemplate, Box<dyn Error>> {
    let mut wire = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{KEY}\r\n\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sample.bin\"\r\n\r\n"
    )
    .into_bytes();
    wire.extend_from_slice(payload);
    wire.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    let body = Bytes::from(wire);
    let headers = vec![
        (http::header::HOST, HeaderValue::from_static(HOST)),
        (
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(&format!("multipart/form-data; boundary={BOUNDARY}"))?,
        ),
        (http::header::CONTENT_LENGTH, HeaderValue::from(body.len())),
    ];
    Ok(RequestTemplate {
        method: Method::POST,
        uri: format!("http://{HOST}/{BUCKET}"),
        headers,
        body,
    })
}

fn sample_payload() -> Bytes {
    let mut buf = Vec::with_capacity(PAYLOAD_BYTES);
    let mut state = 0x51a7_29c3_u32;
    for _ in 0..PAYLOAD_BYTES {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        buf.push(state as u8);
    }
    Bytes::from(buf)
}

fn delete_xml() -> Bytes {
    let mut xml = String::from("<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Quiet>false</Quiet>");
    for index in 0..DELETE_KEYS {
        xml.push_str(&format!("<Object><Key>photos/2026/09/{index:06}.jpg</Key></Object>"));
    }
    xml.push_str("</Delete>");
    Bytes::from(xml)
}

async fn run_gateway_once(service: &S3Service, template: &RequestTemplate) -> Result<(StatusCode, Bytes), Box<dyn Error>> {
    let request = template.for_gateway()?;
    let response = service.call(request).await;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|_| io::Error::other("gateway response body failed"))?
        .to_bytes();
    Ok((status, body))
}

async fn run_s3s_once(
    service: &s3s::service::S3Service,
    template: &RequestTemplate,
) -> Result<(StatusCode, Bytes), Box<dyn Error>> {
    let request = template.for_s3s()?;
    let response = service
        .call(request)
        .await
        .map_err(|e| io::Error::other(format!("s3s service failed: {e:?}")))?;
    let (parts, mut body) = response.into_parts();
    let bytes = body
        .store_all_limited(64 << 20)
        .await
        .map_err(|e| io::Error::other(format!("s3s response body failed: {e}")))?;
    Ok((parts.status, bytes))
}

struct Measurement {
    blocks: u64,
    bytes: u64,
    us_per_iter: f64,
    mib_per_s: Option<f64>,
}

fn measure_stack(
    label: &str,
    iterations: u32,
    payload_bytes: Option<usize>,
    mut step: impl FnMut() -> Result<(), Box<dyn Error>>,
) -> Result<Measurement, Box<dyn Error>> {
    step()?;
    let profiler = dhat::Profiler::builder().testing().build();
    step()?;
    let stats = dhat::HeapStats::get();
    drop(profiler);
    assert!(stats.total_blocks > 0, "{label}: observed zero allocations; is dhat::Alloc installed?");
    println!("{label}: {} allocs, {} bytes", stats.total_blocks, stats.total_bytes);

    let started = Instant::now();
    for _ in 0..iterations {
        step()?;
    }
    let elapsed_secs = started.elapsed().as_secs_f64();
    let us_per_iter = elapsed_secs * 1_000_000.0 / f64::from(iterations);
    println!("{label}: {us_per_iter:.3} us/iteration ({iterations} iterations; record-only, non-blocking)");
    let mib_per_s = payload_bytes.map(|size| {
        let rate = (size as f64 * f64::from(iterations)) / (1024.0 * 1024.0) / elapsed_secs;
        println!("{label}: {rate:.2} MiB/s (record-only, non-blocking)");
        rate
    });
    Ok(Measurement {
        blocks: stats.total_blocks,
        bytes: stats.total_bytes,
        us_per_iter,
        mib_per_s,
    })
}

fn verify_case(
    name: &str,
    status: StatusCode,
    body: &Bytes,
    bytes_counter: &AtomicUsize,
    deletes_counter: &AtomicUsize,
    label: &str,
) {
    match name {
        "get_object_64k" => {
            assert_eq!(status, StatusCode::OK, "{label}: expected 200 OK");
            assert_eq!(body.len(), PAYLOAD_BYTES, "{label}: expected {PAYLOAD_BYTES}-byte response");
        }
        "put_object_64k" => {
            assert_eq!(status, StatusCode::OK, "{label}: expected 200 OK");
            assert_eq!(
                bytes_counter.load(Ordering::Relaxed),
                PAYLOAD_BYTES,
                "{label}: backend did not drain full payload"
            );
        }
        "list_objects_v2_100" => {
            assert_eq!(status, StatusCode::OK, "{label}: expected 200 OK");
            let xml = std::str::from_utf8(body).expect("ListObjectsV2 XML must be valid UTF-8");
            assert!(xml.contains("<ListBucketResult"), "{label}: missing ListBucketResult");
            assert!(xml.contains("<KeyCount>100</KeyCount>"), "{label}: missing KeyCount=100");
        }
        "delete_objects_100" => {
            assert_eq!(status, StatusCode::OK, "{label}: expected 200 OK");
            assert_eq!(
                deletes_counter.load(Ordering::Relaxed),
                DELETE_KEYS,
                "{label}: backend did not receive all {DELETE_KEYS} delete keys"
            );
            let xml = std::str::from_utf8(body).expect("DeleteObjects XML must be valid UTF-8");
            assert!(xml.contains("<DeleteResult"), "{label}: missing DeleteResult");
            assert!(xml.contains("<Deleted>"), "{label}: missing Deleted entries");
            assert!(
                xml.contains("photos/2026/09/000099.jpg"),
                "{label}: missing last deleted key in response XML"
            );
        }
        "post_object_64k" => {
            assert_eq!(status, StatusCode::NO_CONTENT, "{label}: expected 204 No Content");
            assert_eq!(
                bytes_counter.load(Ordering::Relaxed),
                PAYLOAD_BYTES,
                "{label}: backend did not drain full POST file"
            );
        }
        _ => unreachable!("closed benchmark table"),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let payload = sample_payload();
    let delete_body = delete_xml();
    let delete_md5 = base64_md5(&delete_body);

    let gw_backend = Arc::new(GatewayBackend::new(payload.clone())?);
    let gw_service = build_gateway(&gw_backend)?;
    let s3s_observed_bytes = Arc::new(AtomicUsize::new(0));
    let s3s_observed_deletes = Arc::new(AtomicUsize::new(0));
    let s3s_service = build_s3s(S3sBackend::new(
        payload.clone(),
        Arc::clone(&s3s_observed_bytes),
        Arc::clone(&s3s_observed_deletes),
    ));

    let empty_mode =
        PayloadMode::parse(EMPTY_PAYLOAD_SHA256_HEX, TrailerSet::None).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let templates = [
        (
            "get_object_64k",
            400_u32,
            Some(PAYLOAD_BYTES),
            signed_template(Method::GET, &format!("/{BUCKET}/{KEY}"), "", &[], empty_mode.clone(), Bytes::new())?,
        ),
        (
            "put_object_64k",
            400_u32,
            Some(PAYLOAD_BYTES),
            signed_template(Method::PUT, &format!("/{BUCKET}/{KEY}"), "", &[], PayloadMode::Unsigned, payload.clone())?,
        ),
        (
            "list_objects_v2_100",
            200_u32,
            None,
            signed_template(
                Method::GET,
                &format!("/{BUCKET}"),
                "list-type=2&max-keys=100&prefix=photos%2F2026%2F",
                &[],
                empty_mode,
                Bytes::new(),
            )?,
        ),
        (
            "delete_objects_100",
            200_u32,
            None,
            signed_template(
                Method::POST,
                &format!("/{BUCKET}"),
                "delete",
                &[("content-md5", delete_md5.as_str())],
                PayloadMode::Unsigned,
                delete_body,
            )?,
        ),
        ("post_object_64k", 200_u32, Some(PAYLOAD_BYTES), post_object_template(&payload)?),
    ];

    println!(
        "compare: rustfs-gateway vs s3s 0.17.0 (in-memory, single-threaded, payload={PAYLOAD_BYTES}B, list={LIST_KEYS}, delete={DELETE_KEYS})"
    );

    let mut summary = Vec::with_capacity(templates.len());
    for (name, iterations, payload_size, template) in &templates {
        let gw_label = format!("compare/{name}/gateway");
        let s3s_label = format!("compare/{name}/s3s");

        let gw = measure_stack(&gw_label, *iterations, *payload_size, || {
            gw_backend.observed_bytes.store(0, Ordering::Relaxed);
            gw_backend.observed_deletes.store(0, Ordering::Relaxed);
            let (status, body) = runtime.block_on(run_gateway_once(&gw_service, template))?;
            verify_case(name, status, &body, &gw_backend.observed_bytes, &gw_backend.observed_deletes, &gw_label);
            black_box(body);
            Ok(())
        })?;

        let s3s_m = measure_stack(&s3s_label, *iterations, *payload_size, || {
            s3s_observed_bytes.store(0, Ordering::Relaxed);
            s3s_observed_deletes.store(0, Ordering::Relaxed);
            let (status, body) = runtime.block_on(run_s3s_once(&s3s_service, template))?;
            verify_case(name, status, &body, &s3s_observed_bytes, &s3s_observed_deletes, &s3s_label);
            black_box(body);
            Ok(())
        })?;

        summary.push((*name, gw, s3s_m));
    }

    println!("\ncompare/summary: operation,gw_allocs,s3s_allocs,gw_bytes,s3s_bytes,gw_us,s3s_us,gw_mib_s,s3s_mib_s");
    for (name, gw, s3s_m) in summary {
        let gw_mib = gw.mib_per_s.map_or_else(|| "-".to_owned(), |v| format!("{v:.2}"));
        let s3s_mib = s3s_m.mib_per_s.map_or_else(|| "-".to_owned(), |v| format!("{v:.2}"));
        println!(
            "compare/summary/{name}: {},{},{},{},{:.3},{:.3},{gw_mib},{s3s_mib}",
            gw.blocks, s3s_m.blocks, gw.bytes, s3s_m.bytes, gw.us_per_iter, s3s_m.us_per_iter
        );
    }
    Ok(())
}
