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

//! HTTP/1.1 response head, body framing and socket-progress writes.
//!
//! Responsible for: status lines, response headers, fixed/chunked frames, trailers and truthful
//! close announcements.
//! NOT responsible for: producing status, headers or payload semantics.
//! Upstream: the managed `S3Service` response. Downstream: the accepted plaintext TCP socket.

use std::io;
use std::io::IoSlice;

use bytes::{BufMut, Bytes, BytesMut};
use http::{HeaderMap, Method, Response, StatusCode, header};
use http_body::{Body as HttpBody, SizeHint};
use http_body_util::BodyExt;
use rustfs_gateway_server::{ConnectionBody, ConnectionResponseBody, PlaintextConnection};
use rustfs_gateway_stream::Body;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::MutexGuard;

use super::body_plan::{ApplicationBodyPlan, plan_application_body};
use super::chunk::encode_chunk_prefix;
use super::metrics::{ResponseFallbackReason, ResponseTransportMetrics};
use super::request::ConnectionIo;
use crate::close::ConnectionIntent;

type ManagedResponse = Response<ConnectionBody<ConnectionResponseBody<Body>>>;

pub(super) async fn write_response(
    mut io: MutexGuard<'_, ConnectionIo>,
    response: ManagedResponse,
    request_method: &Method,
    force_close: bool,
    transport_metrics: Option<&ResponseTransportMetrics>,
) -> io::Result<bool> {
    let (mut parts, managed_body) = response.into_parts();
    let (response_body, completion) = managed_body.into_parts();
    let suppress_body = *request_method == Method::HEAD || status_forbids_body(parts.status);
    let close = force_close
        || parts
            .extensions
            .get::<ConnectionIntent>()
            .copied()
            .is_some_and(ConnectionIntent::must_close)
        || header_has_token(&parts.headers, header::CONNECTION, "close");
    let size_hint = HttpBody::size_hint(&response_body);
    let response_body = response_body.into_result();
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    if let Ok(body) = &response_body
        && let Some(end_offset) = body.file_region_end_offset()
    {
        i64::try_from(end_offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file region end exceeds sendfile range"))?;
    }
    let framing = prepare_headers(&mut parts.headers, parts.status, suppress_body, close, size_hint)?;
    let body_plan = if suppress_body {
        None
    } else {
        Some(match response_body {
            Ok(body) => Ok(plan_application_body(body)?),
            Err(body) => Err(body),
        })
    };
    let head = encode_head(parts.status, &parts.headers)?;
    write_all_progress(&mut io.stream, &head).await?;

    if suppress_body {
        completion.complete();
        return Ok(close);
    }

    match body_plan.ok_or_else(|| io::Error::other("response body plan is absent after suppression was rejected"))? {
        Ok(plan) => write_application_body(&mut io.stream, plan, framing, transport_metrics).await?,
        Err(body) => {
            record_fallback(transport_metrics, ResponseFallbackReason::NotFileBacked);
            write_body(&mut io.stream, body, framing, transport_metrics).await?;
        }
    }
    completion.complete();
    Ok(close)
}

async fn write_application_body(
    writer: &mut PlaintextConnection,
    plan: ApplicationBodyPlan,
    framing: ResponseFraming,
    transport_metrics: Option<&ResponseTransportMetrics>,
) -> io::Result<()> {
    match plan {
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        ApplicationBodyPlan::KernelFile(region) => write_file_region(writer, region, framing, transport_metrics).await,
        #[cfg(unix)]
        ApplicationBodyPlan::CopiedFile { source, fallback } => {
            record_fallback(transport_metrics, fallback);
            write_file_region_copied(writer, source, framing, transport_metrics).await
        }
        ApplicationBodyPlan::Payload { body, fallback } => {
            record_fallback(transport_metrics, fallback);
            write_non_file_body(writer, body, framing, transport_metrics).await
        }
    }
}

async fn write_non_file_body<W>(
    writer: &mut W,
    body: Body,
    framing: ResponseFraming,
    transport_metrics: Option<&ResponseTransportMetrics>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if let Some(segments) = body.try_as_vectored() {
        return write_memory_segments(writer, segments, framing, transport_metrics).await;
    }
    #[cfg(unix)]
    if body.file_region_end_offset().is_some() {
        return Err(io::Error::other("file capability was not negotiated before response writing"));
    }
    write_body(writer, body, framing, transport_metrics).await
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
async fn write_file_region(
    writer: &mut PlaintextConnection,
    region: rustfs_gateway_stream::FileRegion,
    framing: ResponseFraming,
    transport_metrics: Option<&ResponseTransportMetrics>,
) -> io::Result<()> {
    let len = region.len();
    match framing {
        ResponseFraming::Suppressed => return Ok(()),
        ResponseFraming::Fixed(expected) if expected != len => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file region length contradicts response framing",
            ));
        }
        ResponseFraming::Fixed(_) => {}
        ResponseFraming::Chunked if len != 0 => {
            let mut prefix_storage = [0_u8; 18];
            let prefix = encode_chunk_prefix(len, &mut prefix_storage)?;
            write_all_progress(writer, prefix).await?;
        }
        ResponseFraming::Chunked => {}
    }
    if len != 0 {
        let offset = region.offset();
        let mut file = region.into_fd();
        let mut sent = 0_u64;
        while sent < len {
            let (next_file, progress) = writer.send_file_owned_once(file, offset + sent, len - sent).await?;
            file = next_file;
            let written = progress.bytes();
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "file region ended before the declared response length",
                ));
            }
            let written = u64::try_from(written).map_err(io::Error::other)?;
            sent = sent
                .checked_add(written)
                .ok_or_else(|| io::Error::other("sendfile progress overflowed"))?;
            if let Some(metrics) = transport_metrics {
                metrics.record_kernel_progress(
                    written,
                    u64::try_from(progress.blocking_handoffs()).map_err(io::Error::other)?,
                    u64::try_from(progress.kernel_calls()).map_err(io::Error::other)?,
                );
            }
            tokio::task::yield_now().await;
        }
    }
    if matches!(framing, ResponseFraming::Chunked) {
        if len != 0 {
            write_all_progress(writer, b"\r\n").await?;
        }
        write_all_progress(writer, b"0\r\n\r\n").await?;
    }
    Ok(())
}

#[cfg(unix)]
async fn write_file_region_copied(
    writer: &mut PlaintextConnection,
    mut source: rustfs_gateway_stream::CopiedFileBody,
    framing: ResponseFraming,
    transport_metrics: Option<&ResponseTransportMetrics>,
) -> io::Result<()> {
    source.record_copy_adaptation();
    let mut buffer = vec![0_u8; 64 * 1024];
    while !source.is_empty() {
        let (next_source, next_buffer, read) = tokio::task::spawn_blocking(move || {
            let read = source.read_blocking(&mut buffer);
            (source, buffer, read)
        })
        .await
        .map_err(io::Error::other)?;
        source = next_source;
        buffer = next_buffer;
        let read = read?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file region ended before the declared response length",
            ));
        }
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| io::Error::other("copied file read reported impossible progress"))?;
        match framing {
            ResponseFraming::Suppressed => return Ok(()),
            ResponseFraming::Fixed(_) => write_all_payload_progress(writer, chunk, transport_metrics).await?,
            ResponseFraming::Chunked => write_chunk(writer, chunk, transport_metrics).await?,
        }
    }
    if matches!(framing, ResponseFraming::Chunked) {
        write_all_progress(writer, b"0\r\n\r\n").await?;
    }
    Ok(())
}

async fn write_memory_segments<W>(
    writer: &mut W,
    segments: &[Bytes],
    framing: ResponseFraming,
    transport_metrics: Option<&ResponseTransportMetrics>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = segments.iter().try_fold(0_u64, |total, segment| {
        total
            .checked_add(u64::try_from(segment.len()).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "response body length overflows"))
    })?;
    if matches!(framing, ResponseFraming::Suppressed) {
        return Ok(());
    }
    let chunked = matches!(framing, ResponseFraming::Chunked);
    let mut prefix_storage = [0_u8; 18];
    let prefix = if chunked && length != 0 {
        encode_chunk_prefix(length, &mut prefix_storage)?
    } else {
        &[]
    };
    let suffix = if chunked && length != 0 { &b"\r\n"[..] } else { &[] };
    let mut parts = std::iter::once(prefix)
        .chain(segments.iter().map(Bytes::as_ref))
        .chain(std::iter::once(suffix))
        .filter(|part| !part.is_empty());
    let payload_start = u64::try_from(prefix.len()).map_err(io::Error::other)?;
    let payload_end = payload_start
        .checked_add(length)
        .ok_or_else(|| io::Error::other("payload range overflowed"))?;
    let mut progress = 0_u64;
    loop {
        let mut slices = [IoSlice::new(&[]); 16];
        let mut count = 0;
        let mut batch_length = 0_u64;
        for (slice, part) in slices.iter_mut().zip(parts.by_ref()) {
            batch_length = batch_length
                .checked_add(u64::try_from(part.len()).map_err(io::Error::other)?)
                .ok_or_else(|| io::Error::other("response batch length overflowed"))?;
            *slice = IoSlice::new(part);
            count += 1;
        }
        if count == 0 {
            break;
        }
        let end = progress
            .checked_add(batch_length)
            .ok_or_else(|| io::Error::other("response progress overflowed"))?;
        let batch_payload = end.min(payload_end).saturating_sub(progress.max(payload_start));
        let batch = slices
            .get_mut(..count)
            .ok_or_else(|| io::Error::other("response batch exceeds its slice storage"))?;
        write_all_vectored_payload_progress(
            writer,
            batch,
            payload_start.saturating_sub(progress),
            batch_payload,
            transport_metrics,
        )
        .await?;
        progress = end;
    }
    if chunked {
        write_all_progress(writer, b"0\r\n\r\n").await?;
    }
    Ok(())
}

fn prepare_headers(
    headers: &mut HeaderMap,
    status: StatusCode,
    suppress_body: bool,
    close: bool,
    size_hint: SizeHint,
) -> io::Result<ResponseFraming> {
    let content_length = single_header(headers, header::CONTENT_LENGTH)?
        .map(parse_content_length)
        .transpose()?;
    let transfer_encoding = single_header(headers, header::TRANSFER_ENCODING)?;
    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response cannot contain both Content-Length and Transfer-Encoding",
        ));
    }

    if suppress_body {
        headers.remove(header::TRANSFER_ENCODING);
        if status.is_informational() || status == StatusCode::NO_CONTENT {
            headers.remove(header::CONTENT_LENGTH);
        }
        if status == StatusCode::RESET_CONTENT {
            headers.insert(header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
        }
        if close {
            headers.insert(header::CONNECTION, http::HeaderValue::from_static("close"));
        }
        return Ok(ResponseFraming::Suppressed);
    }

    let framing = if let Some(length) = content_length {
        if size_hint.exact().is_some_and(|exact| exact != length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response body size contradicts Content-Length",
            ));
        }
        ResponseFraming::Fixed(length)
    } else if let Some(value) = transfer_encoding {
        if !value
            .to_str()
            .ok()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("chunked"))
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported response Transfer-Encoding"));
        }
        ResponseFraming::Chunked
    } else if let Some(exact) = size_hint.exact() {
        headers.insert(
            header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&exact.to_string()).map_err(io::Error::other)?,
        );
        ResponseFraming::Fixed(exact)
    } else {
        headers.insert(header::TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
        ResponseFraming::Chunked
    };
    if close {
        headers.insert(header::CONNECTION, http::HeaderValue::from_static("close"));
    }
    Ok(framing)
}

fn encode_head(status: StatusCode, headers: &HeaderMap) -> io::Result<Bytes> {
    let reason = status.canonical_reason().unwrap_or("");
    let mut encoded = BytesMut::with_capacity(256);
    encoded.extend_from_slice(b"HTTP/1.1 ");
    encoded.extend_from_slice(status.as_str().as_bytes());
    encoded.put_u8(b' ');
    encoded.extend_from_slice(reason.as_bytes());
    encoded.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        encoded.extend_from_slice(name.as_str().as_bytes());
        encoded.extend_from_slice(b": ");
        encoded.extend_from_slice(value.as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    encoded.extend_from_slice(b"\r\n");
    Ok(encoded.freeze())
}

async fn write_body<W, B>(
    writer: &mut W,
    mut body: B,
    framing: ResponseFraming,
    transport_metrics: Option<&ResponseTransportMetrics>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut remaining = match framing {
        ResponseFraming::Fixed(length) => Some(length),
        ResponseFraming::Chunked => None,
        ResponseFraming::Suppressed => return Ok(()),
    };
    let mut trailers = HeaderMap::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| io::Error::other(error.into()))?;
        match frame.into_data() {
            Ok(data) => {
                if data.is_empty() {
                    continue;
                }
                if let Some(left) = &mut remaining {
                    let data_len = u64::try_from(data.len()).map_err(io::Error::other)?;
                    if data_len > *left {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "response body exceeds Content-Length"));
                    }
                    write_all_payload_progress(writer, &data, transport_metrics).await?;
                    *left -= data_len;
                } else {
                    write_chunk(writer, &data, transport_metrics).await?;
                }
            }
            Err(frame) => {
                if let Ok(frame_trailers) = frame.into_trailers() {
                    for (name, value) in frame_trailers {
                        if let Some(name) = name {
                            trailers.append(name, value);
                        }
                    }
                }
            }
        }
    }
    if let Some(left) = remaining {
        if left != 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "response body ended before Content-Length"));
        }
    } else {
        write_all_progress(writer, b"0\r\n").await?;
        for (name, value) in &trailers {
            let mut slices = [
                IoSlice::new(name.as_str().as_bytes()),
                IoSlice::new(b": "),
                IoSlice::new(value.as_bytes()),
                IoSlice::new(b"\r\n"),
            ];
            write_all_vectored_payload_progress(writer, &mut slices, 0, 0, None).await?;
        }
        write_all_progress(writer, b"\r\n").await?;
    }
    Ok(())
}

async fn write_chunk<W>(writer: &mut W, data: &[u8], transport_metrics: Option<&ResponseTransportMetrics>) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut prefix_storage = [0_u8; 18];
    let prefix = encode_chunk_prefix(u64::try_from(data.len()).map_err(io::Error::other)?, &mut prefix_storage)?;
    let mut slices = [IoSlice::new(prefix), IoSlice::new(data), IoSlice::new(b"\r\n")];
    write_all_vectored_payload_progress(
        writer,
        &mut slices,
        u64::try_from(prefix.len()).map_err(io::Error::other)?,
        u64::try_from(data.len()).map_err(io::Error::other)?,
        transport_metrics,
    )
    .await
}

pub(super) async fn write_bad_request(io: &mut ConnectionIo) -> io::Result<()> {
    write_all_progress(
        &mut io.stream,
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await
}

pub(super) async fn write_continue(io: &mut ConnectionIo) -> io::Result<()> {
    write_all_progress(&mut io.stream, b"HTTP/1.1 100 Continue\r\n\r\n").await
}

pub(super) async fn write_expectation_failed(io: &mut ConnectionIo) -> io::Result<()> {
    write_all_progress(
        &mut io.stream,
        b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await
}

async fn write_all_progress<W>(writer: &mut W, mut bytes: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while !bytes.is_empty() {
        let written = writer.write(bytes).await?;
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "HTTP/1.1 response socket wrote zero bytes"));
        }
        bytes = bytes
            .get(written..)
            .ok_or_else(|| io::Error::other("socket reported impossible write progress"))?;
    }
    Ok(())
}

async fn write_all_payload_progress<W>(
    writer: &mut W,
    mut bytes: &[u8],
    transport_metrics: Option<&ResponseTransportMetrics>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while !bytes.is_empty() {
        let written = writer.write(bytes).await?;
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "HTTP/1.1 response socket wrote zero bytes"));
        }
        record_copied_progress(transport_metrics, written)?;
        bytes = bytes
            .get(written..)
            .ok_or_else(|| io::Error::other("socket reported impossible write progress"))?;
    }
    Ok(())
}

async fn write_all_vectored_payload_progress<W>(
    writer: &mut W,
    buffers: &mut [IoSlice<'_>],
    payload_start: u64,
    payload_len: u64,
    transport_metrics: Option<&ResponseTransportMetrics>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload_end = payload_start
        .checked_add(payload_len)
        .ok_or_else(|| io::Error::other("payload byte range overflowed"))?;
    let mut progress = 0_u64;
    let mut remaining = buffers;
    while !remaining.is_empty() {
        let written = writer.write_vectored(remaining).await?;
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "HTTP/1.1 response socket wrote zero bytes"));
        }
        let next = progress
            .checked_add(u64::try_from(written).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("response write progress overflowed"))?;
        let copied = next.min(payload_end).saturating_sub(progress.max(payload_start));
        if copied != 0 {
            record_copied_progress_u64(transport_metrics, copied);
        }
        progress = next;
        IoSlice::advance_slices(&mut remaining, written);
    }
    Ok(())
}

fn record_fallback(metrics: Option<&ResponseTransportMetrics>, reason: ResponseFallbackReason) {
    if let Some(metrics) = metrics {
        metrics.record_fallback(reason);
    }
}

fn record_copied_progress(metrics: Option<&ResponseTransportMetrics>, written: usize) -> io::Result<()> {
    record_copied_progress_u64(metrics, u64::try_from(written).map_err(io::Error::other)?);
    Ok(())
}

fn record_copied_progress_u64(metrics: Option<&ResponseTransportMetrics>, written: u64) {
    if let Some(metrics) = metrics {
        metrics.record_copied_progress(written);
    }
}

fn parse_content_length(value: &http::HeaderValue) -> io::Result<u64> {
    value
        .to_str()
        .map_err(io::Error::other)?
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response Content-Length"))
}

fn single_header(headers: &HeaderMap, name: http::HeaderName) -> io::Result<Option<&http::HeaderValue>> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "response framing header must not be repeated"));
    }
    Ok(first)
}

fn header_has_token(headers: &HeaderMap, name: http::HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value
            .to_str()
            .ok()
            .is_some_and(|value| value.split(',').any(|token| token.trim().eq_ignore_ascii_case(expected)))
    })
}

fn status_forbids_body(status: StatusCode) -> bool {
    status.is_informational() || matches!(status, StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED)
}

#[derive(Clone, Copy)]
enum ResponseFraming {
    Suppressed,
    Fixed(u64),
    Chunked,
}

#[cfg(test)]
#[path = "response_tests.rs"]
mod tests;
