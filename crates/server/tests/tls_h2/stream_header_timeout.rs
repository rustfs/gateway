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

//! Per-stream HTTP/2 header read timeout after the first request.
//!
//! Responsible for: proving incomplete `HEADERS` and dribbled `CONTINUATION` frames on subsequent
//! HTTP/2 streams expire at `header_read_timeout` even when `keep_alive_idle` is long, while
//! complete headers followed by slow `DATA` frames are not cut by `header_read_timeout`.
//! NOT responsible for: initial accept-to-first-request header deadlines (`server_runtime.rs`) or
//! HTTP/2 idle timeouts (`idle.rs`).
//! Upstream: rustfs/gateway#1632. Downstream: the public server API.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tower::service_fn;

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(9 + len);
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Static HPACK block for `:method: GET`, `:scheme: http`, `:path: /`, `:authority: localhost`.
const HPACK_GET_ROOT: &[u8] = &[
    0x82, 0x86, 0x84, 0x41, 0x09, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
];
/// Static HPACK block for `:method: POST`, `:scheme: http`, `:path: /`, `:authority: localhost`.
const HPACK_POST_ROOT: &[u8] = &[
    0x83, 0x86, 0x84, 0x41, 0x09, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
];

fn start_server(header_timeout: Duration) -> RunningServer {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: header_timeout,
        keep_alive_idle: Duration::from_secs(60),
        write_progress_timeout: Duration::from_secs(10),
        ..ServerConfig::default()
    };
    let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
        let collected = request
            .into_body()
            .collect()
            .await
            .map(|body| body.to_bytes())
            .unwrap_or_default();
        Ok::<_, Infallible>(Response::new(Full::new(collected)))
    });
    Server::new(config, service).serve().expect("server starts")
}

/// Completes the HTTP/2 preface, empty client SETTINGS, and stream 1 request/response so
/// `first_request_observed` is guaranteed `true` before opening a slow second stream.
async fn complete_first_stream(stream: &mut TcpStream) {
    stream.write_all(HTTP2_PREFACE).await.expect("preface writes");
    // Empty client SETTINGS (type 0x04, flags 0x00, stream 0)
    stream
        .write_all(&h2_frame(0x04, 0x00, 0, &[]))
        .await
        .expect("settings writes");
    // Stream 1: HEADERS with END_STREAM (0x01) | END_HEADERS (0x04)
    stream
        .write_all(&h2_frame(0x01, 0x05, 1, HPACK_GET_ROOT))
        .await
        .expect("stream 1 headers write");

    // Read server frames until stream 1 receives END_STREAM, ACKing server SETTINGS along the way.
    let mut header = [0_u8; 9];
    loop {
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header))
            .await
            .expect("server responds to stream 1")
            .expect("frame header reads");
        let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | (header[2] as usize);
        let frame_type = header[3];
        let flags = header[4];
        let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
        let mut payload = vec![0_u8; len];
        if len > 0 {
            stream.read_exact(&mut payload).await.expect("frame payload reads");
        }
        if frame_type == 0x04 && (flags & 0x01) == 0 {
            // ACK server SETTINGS.
            stream
                .write_all(&h2_frame(0x04, 0x01, 0, &[]))
                .await
                .expect("settings ack writes");
        }
        if stream_id == 1 && (flags & 0x01) != 0 && (frame_type == 0x01 || frame_type == 0x00) {
            break;
        }
    }
}

/// Negative — on an established HTTP/2 connection after the first request, opening stream 3 with
/// a `HEADERS` frame missing `END_HEADERS` must time out at `header_read_timeout`, not wait for
/// `keep_alive_idle`.
#[tokio::test]
async fn n_h2_incomplete_headers_after_first_request_times_out_at_header_read_timeout() {
    let server = start_server(Duration::from_millis(120));
    let mut client = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    complete_first_stream(&mut client).await;

    // Stream 3: HEADERS without END_HEADERS (flags = 0x00), then stall.
    client
        .write_all(&h2_frame(0x01, 0x00, 3, &HPACK_GET_ROOT[..2]))
        .await
        .expect("partial stream 3 headers write");

    let mut sink = [0_u8; 256];
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match client.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "server failed to close HTTP/2 connection whose stream 3 stalled mid-HEADERS within header_read_timeout"
    );

    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(server.task.await.expect("server joins").is_ok());
}

/// Negative — dribbling `CONTINUATION` frames without `END_HEADERS` must not reset the per-stream
/// header read deadline.
#[tokio::test]
async fn n_h2_dribbled_continuation_frames_time_out_at_header_read_timeout() {
    let server = start_server(Duration::from_millis(120));
    let mut client = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    complete_first_stream(&mut client).await;

    client
        .write_all(&h2_frame(0x01, 0x00, 3, &HPACK_GET_ROOT[..1]))
        .await
        .expect("initial stream 3 HEADERS without END_HEADERS");

    // Dribble valid 1-byte CONTINUATION fragments (well below h2's continuation count limit)
    // faster than header_read_timeout; the cumulative deadline must still fire.
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        let mut buf = [0_u8; 256];
        for byte in &HPACK_GET_ROOT[1..] {
            tokio::time::sleep(Duration::from_millis(35)).await;
            if client.write_all(&h2_frame(0x09, 0x00, 3, &[*byte])).await.is_err() {
                return true;
            }
            if let Ok(Ok(0) | Err(_)) = tokio::time::timeout(Duration::from_millis(2), client.read(&mut buf)).await {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(closed, Ok(true), "dribbled HTTP/2 CONTINUATION frames must still hit header_read_timeout");

    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(server.task.await.expect("server joins").is_ok());
}

/// Positive — once stream 3's `HEADERS` complete with `END_HEADERS`, a slow `DATA` body that takes
/// longer than `header_read_timeout` is NOT cut by `header_read_timeout`.
#[tokio::test]
async fn h2_complete_headers_with_slow_data_body_outlives_header_read_timeout() {
    let server = start_server(Duration::from_millis(100));
    let mut client = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    complete_first_stream(&mut client).await;

    // Stream 3: complete HEADERS (END_HEADERS = 0x04, no END_STREAM).
    client
        .write_all(&h2_frame(0x01, 0x04, 3, HPACK_POST_ROOT))
        .await
        .expect("stream 3 complete headers write");
    // Wait longer than header_read_timeout before sending the DATA frame.
    tokio::time::sleep(Duration::from_millis(220)).await;
    client
        .write_all(&h2_frame(0x00, 0x01, 3, b"slow-body"))
        .await
        .expect("stream 3 DATA writes");

    let mut received = Vec::new();
    let mut header = [0_u8; 9];
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            client.read_exact(&mut header).await.expect("server frame header");
            let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | (header[2] as usize);
            let frame_type = header[3];
            let flags = header[4];
            let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
            let mut payload = vec![0_u8; len];
            if len > 0 {
                client.read_exact(&mut payload).await.expect("server frame payload");
            }
            if stream_id == 3 && frame_type == 0x00 {
                received.extend_from_slice(&payload);
            }
            if stream_id == 3 && (flags & 0x01) != 0 {
                break;
            }
        }
    })
    .await
    .expect("complete headers followed by slow DATA must succeed");
    assert_eq!(received, b"slow-body");

    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(server.task.await.expect("server joins").is_ok());
}

/// Negative — configuring `h2_max_local_error_reset_streams: Some(2)` forces HTTP/2 GOAWAY
/// (`ENHANCE_YOUR_CALM`) when a client repeatedly provokes local stream resets.
#[tokio::test]
async fn n_h2_local_error_reset_streams_limit_emits_goaway_on_repeated_stream_errors() {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: Duration::from_secs(2),
        keep_alive_idle: Duration::from_secs(60),
        h2_max_local_error_reset_streams: Some(2),
        ..ServerConfig::default()
    };
    let service = service_fn(|_request: Request<hyper::body::Incoming>| async {
        Ok::<_, Infallible>(Response::new(Full::new(bytes::Bytes::from_static(b"ok"))))
    });
    let server = Server::new(config, service).serve().expect("server starts");

    let mut client = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    client.write_all(HTTP2_PREFACE).await.expect("preface writes");
    client.write_all(&h2_frame(0x04, 0x00, 0, &[])).await.expect("settings write");

    // Send 4 streams carrying malformed pseudo-headers (missing `:method`) so Hyper resets each
    // stream locally and hits `h2_max_local_error_reset_streams = Some(2)` with GOAWAY ENHANCE_YOUR_CALM (0x0b).
    // HPACK for `:path: /` only (0x84) -> protocol error on the stream (not connection compression error).
    for stream_id in [1_u32, 3, 5, 7] {
        let _ = client.write_all(&h2_frame(0x01, 0x05, stream_id, &[0x84])).await;
    }

    let mut saw_enhance_your_calm = false;
    let mut header = [0_u8; 9];
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if client.read_exact(&mut header).await.is_err() {
                break;
            }
            let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | (header[2] as usize);
            let frame_type = header[3];
            let mut payload = vec![0_u8; len];
            if len > 0 && client.read_exact(&mut payload).await.is_err() {
                break;
            }
            // GOAWAY (type 0x07): last_stream_id (4B) + error_code (4B). ENHANCE_YOUR_CALM = 0x0b.
            if frame_type == 0x07 && payload.len() >= 8 {
                let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                if code == 0x0b {
                    saw_enhance_your_calm = true;
                    break;
                }
            }
        }
    })
    .await;
    assert!(
        saw_enhance_your_calm,
        "exceeding h2_max_local_error_reset_streams must terminate the connection with GOAWAY ENHANCE_YOUR_CALM"
    );

    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(server.task.await.expect("server joins").is_ok());
}
