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

//! Keep-alive control reuse and batched `DeleteObjects` cleanup tests over real loopback sockets.
//!
//! Responsible for: proving persistent HTTP/1.1 socket reuse during external fixture prepare and
//! cleanup, isolation from authored case exchanges, transparent reconnect on `Connection: close`
//! or silent idle drop, no stale retry on non-idempotent multipart initiation, >1,000-key batch
//! chunking with `Content-MD5` and XML escaping, fail-closed ownership retention on partial
//! `<Error>`, unreported keys, malformed `200` XML, and `500` responses, plus `501` and
//! control-character fallbacks to single-object `DELETE`. NOT responsible for: production server
//! behavior, versioned fixtures, or authored case verdicts. Upstream: `super`; downstream: a
//! bounded loopback HTTP/1.1 peer.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use super::super::Conn;
use crate::sut::{ExchangePlan, Profile, Sut, Transport};

// Serialize loopback peers in this module so parallel tests cannot saturate the bounded
// external-endpoint resolver queue (`RESOLVER_QUEUE_CAPACITY = 8`).
static PEERS: Mutex<()> = Mutex::new(());

#[derive(Debug)]
struct RecordedRequest {
    socket: usize,
    line: String,
    connection: Option<String>,
    content_type: Option<String>,
    content_md5: Option<String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct ServerReport {
    accepted_sockets: usize,
    requests: Vec<RecordedRequest>,
}

enum PeerReply {
    /// Send a framed HTTP/1.1 response and keep the TCP connection open unless `close` is true.
    Response { bytes: Vec<u8>, close: bool },
    /// Drop the TCP connection immediately after reading the request without sending any bytes.
    DropWithoutResponse,
}

fn keep_alive_response(status: u16, body: &str) -> PeerReply {
    let bytes = if status == 204 {
        b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()
    } else {
        format!("HTTP/1.1 {status} Response\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    };
    PeerReply::Response { bytes, close: false }
}

fn close_response(status: u16, body: &str) -> PeerReply {
    let bytes = if status == 204 {
        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec()
    } else {
        format!(
            "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    };
    PeerReply::Response { bytes, close: true }
}

fn silent_close_response(status: u16, body: &str) -> PeerReply {
    let bytes = if status == 204 {
        b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()
    } else {
        format!("HTTP/1.1 {status} Response\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    };
    // Omit `Connection: close` on the wire, then close the socket after writing the response.
    PeerReply::Response { bytes, close: true }
}

struct KeepAliveServer {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<ServerReport>>,
    _lease: MutexGuard<'static, ()>,
}

impl KeepAliveServer {
    fn start<F>(mut responder: F) -> Self
    where
        F: FnMut(&RecordedRequest) -> PeerReply + Send + 'static,
    {
        let lease = PEERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback keep-alive peer");
        listener.set_nonblocking(true).expect("nonblocking accept loop");
        let url = format!("http://{}", listener.local_addr().expect("peer address"));
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut accepted_sockets = 0_usize;
            let mut requests = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(20);
            while !stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("keep-alive peer accept failed: {error}"),
                };
                accepted_sockets += 1;
                let socket_id = accepted_sockets;
                stream.set_nonblocking(false).expect("blocking connection read");
                stream
                    .set_read_timeout(Some(Duration::from_millis(50)))
                    .expect("bounded read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .expect("bounded write timeout");
                let mut leftover = Vec::new();
                while !stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
                    let Some(request) = read_one_request(&mut stream, &mut leftover, socket_id, &stopped, deadline) else {
                        break;
                    };
                    let reply = responder(&request);
                    requests.push(request);
                    match reply {
                        PeerReply::Response { bytes, close } => {
                            if stream.write_all(&bytes).is_err() || stream.flush().is_err() {
                                break;
                            }
                            if close {
                                break;
                            }
                        }
                        PeerReply::DropWithoutResponse => break,
                    }
                }
            }
            ServerReport {
                accepted_sockets,
                requests,
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            _lease: lease,
        }
    }

    fn target(&self) -> Conn {
        Conn::external_with_fixtures(PathBuf::from("."), &self.url, None).expect("opted-in external target")
    }

    fn finish(mut self) -> ServerReport {
        self.stop.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .expect("peer worker handle")
            .join()
            .expect("peer worker exited cleanly")
    }
}

impl Drop for KeepAliveServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_one_request(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    socket: usize,
    stopped: &AtomicBool,
    deadline: Instant,
) -> Option<RecordedRequest> {
    loop {
        if let Some(head_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4) {
            let head = std::str::from_utf8(&buffer[..head_end]).expect("request head is UTF-8");
            let header = |wanted: &str| {
                head.lines().skip(1).find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case(wanted).then(|| value.trim().to_owned())
                })
            };
            let length = header("content-length")
                .map(|value| value.parse::<usize>().expect("numeric content-length"))
                .unwrap_or(0);
            if buffer.len() >= head_end + length {
                // Retain only non-credential headers.
                let line = head.lines().next().expect("request line").to_owned();
                let connection = header("connection");
                let content_type = header("content-type");
                let content_md5 = header("content-md5");
                let body = buffer[head_end..head_end + length].to_vec();
                buffer.drain(..head_end + length);
                return Some(RecordedRequest {
                    socket,
                    line,
                    connection,
                    content_type,
                    content_md5,
                    body,
                });
            }
        }
        if stopped.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return None;
        }
        let mut block = [0_u8; 4096];
        match stream.read(&mut block) {
            Ok(0) => return None,
            Ok(count) => buffer.extend_from_slice(&block[..count]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(_) => return None,
        }
    }
}

fn setup(source: &str) -> crate::value::Value {
    crate::toml::parse(source).expect("valid setup TOML")
}

/// Extracts `<Key>...</Key>` texts verbatim (XML-encoded) from a `<Delete>` request body so test
/// helpers stay independent of `quick_xml` (`scripts/check_runner_raw_bytes.sh`).
fn raw_xml_keys(body: &[u8]) -> Vec<String> {
    let text = std::str::from_utf8(body).expect("DeleteObjects body is UTF-8");
    let mut keys = Vec::new();
    let mut rest = text;
    while let Some((_, after_open)) = rest.split_once("<Key>") {
        let (key, after_close) = after_open.split_once("</Key>").expect("closing </Key>");
        keys.push(key.to_owned());
        rest = after_close;
    }
    keys
}

/// Builds a `<DeleteResult>` confirming every raw XML key from a `<Delete>` request body.
fn confirm_all_delete_result(body: &[u8]) -> String {
    let mut xml = String::from("<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    for key in raw_xml_keys(body) {
        xml.push_str("<Deleted><Key>");
        xml.push_str(&key);
        xml.push_str("</Key></Deleted>");
    }
    xml.push_str("</DeleteResult>");
    xml
}

fn default_keep_alive_responder(request: &RecordedRequest) -> PeerReply {
    if request.line.starts_with("HEAD ") {
        return keep_alive_response(404, "");
    }
    if request.line.starts_with("PUT ") {
        return keep_alive_response(200, "");
    }
    if request.line.starts_with("GET ") {
        return keep_alive_response(200, "ok");
    }
    if request.line.starts_with("POST ") && request.line.contains("?delete ") {
        return keep_alive_response(200, &confirm_all_delete_result(&request.body));
    }
    if request.line.starts_with("DELETE ") {
        return keep_alive_response(204, "");
    }
    keep_alive_response(500, "")
}

/// Positive — persistent HTTP/1.1 keep-alive control reuse uses one socket for all setup calls,
/// clears it before authored exchanges, and uses one socket for batch cleanup + bucket delete.
#[test]
fn keep_alive_control_reuses_one_socket_across_prepare_and_one_across_cleanup() {
    let server = KeepAliveServer::start(default_keep_alive_responder);
    let mut target = server.target();
    let setup = setup(
        "[[buckets]]\nname = \"ka-bucket\"\n\
         [[objects]]\nbucket = \"ka-bucket\"\nkey = \"k0\"\n\
         [[objects]]\nbucket = \"ka-bucket\"\nkey = \"k1\"\n\
         [[objects]]\nbucket = \"ka-bucket\"\nkey = \"k2\"\n\
         [[objects]]\nbucket = \"ka-bucket\"\nkey = \"k3\"\n",
    );

    target.prepare("c-ka-0001", Some(&setup)).expect("prepare succeeds");
    let plan = ExchangePlan {
        case_id: "c-ka-0001",
        index: 0,
        request: crate::toml::parse("method = \"GET\"\ntarget = \"/ka-bucket?list-type=2\"\n").expect("valid request"),
        clock: None,
        connection: None,
        timeout_ms: Some(2_000),
        deadline: None,
        transport: Transport::Conn,
        profile: Profile::Aws,
    };
    assert_eq!(target.exchange(&plan).expect("authored read succeeds").status, Some(200));
    target.finish("c-ka-0001").expect("cleanup succeeds");

    let report = server.finish();
    // 10 prepare requests (socket 1) + 1 authored GET (socket 2) + 2 cleanup requests (socket 3).
    assert_eq!(report.requests.len(), 13, "unexpected request count: {:?}", report.requests);
    assert_eq!(
        report.accepted_sockets, 3,
        "expected exactly 3 sockets (1 prepare + 1 authored + 1 cleanup), got {}",
        report.accepted_sockets
    );
    for request in &report.requests[..10] {
        assert_eq!(request.socket, 1, "prepare control did not reuse socket 1: {request:?}");
        assert_eq!(
            request.connection, None,
            "cleartext control request must omit Connection: close: {request:?}"
        );
    }
    assert_eq!(report.requests[10].line, "GET /ka-bucket?list-type=2 HTTP/1.1");
    assert_eq!(report.requests[10].socket, 2, "authored exchange must use its own socket");
    assert_eq!(report.requests[11].line, "POST /ka-bucket?delete HTTP/1.1");
    assert_eq!(report.requests[12].line, "DELETE /ka-bucket HTTP/1.1");
    assert_eq!(report.requests[11].socket, 3);
    assert_eq!(report.requests[12].socket, 3, "cleanup controls must reuse one socket");
}

/// Negative — when a peer announces `Connection: close`, the control channel drops the socket and
/// transparently opens a fresh connection for every subsequent control request.
#[test]
fn control_reconnects_transparently_when_peer_announces_connection_close() {
    let server = KeepAliveServer::start(|request| {
        if request.line.starts_with("HEAD ") {
            return close_response(404, "");
        }
        if request.line.starts_with("PUT ") {
            return close_response(200, "");
        }
        if request.line.starts_with("POST ") && request.line.contains("?delete ") {
            return close_response(200, &confirm_all_delete_result(&request.body));
        }
        if request.line.starts_with("DELETE ") {
            return close_response(204, "");
        }
        close_response(500, "")
    });
    let mut target = server.target();
    let setup = setup(
        "[[buckets]]\nname = \"close-bucket\"\n\
         [[objects]]\nbucket = \"close-bucket\"\nkey = \"a\"\n\
         [[objects]]\nbucket = \"close-bucket\"\nkey = \"b\"\n",
    );

    target
        .prepare("c-ka-n001", Some(&setup))
        .expect("prepare reconnects on close");
    target.finish("c-ka-n001").expect("cleanup reconnects on close");

    let report = server.finish();
    assert_eq!(report.requests.len(), 8);
    assert_eq!(
        report.accepted_sockets, 8,
        "every Connection: close response must open a new control socket"
    );
}

/// Negative — when a peer omits `Connection: close` but drops the idle keep-alive socket anyway,
/// the next idempotent control transparently reconnects and succeeds.
#[test]
fn control_reconnects_transparently_when_peer_drops_idle_keep_alive_socket_silently() {
    let server = KeepAliveServer::start(|request| {
        if request.line.starts_with("HEAD ") {
            return silent_close_response(404, "");
        }
        if request.line.starts_with("PUT ") {
            return silent_close_response(200, "");
        }
        if request.line.starts_with("DELETE ") {
            return silent_close_response(204, "");
        }
        silent_close_response(500, "")
    });
    let mut target = server.target();
    let setup = setup(
        "[[buckets]]\nname = \"silent-drop\"\n\
         [[objects]]\nbucket = \"silent-drop\"\nkey = \"only\"\n",
    );

    target
        .prepare("c-ka-n002", Some(&setup))
        .expect("prepare recovers from silent peer drop");
    target.finish("c-ka-n002").expect("cleanup recovers from silent peer drop");

    let report = server.finish();
    assert_eq!(report.requests.len(), 6);
    assert_eq!(report.accepted_sockets, 6);
}

/// Negative — a non-idempotent `POST ?uploads` initiation must NEVER retry when the peer drops
/// a reused keep-alive connection before answering, so remote upload ownership cannot be duplicated.
#[test]
fn non_idempotent_multipart_init_does_not_retry_when_peer_drops_connection_before_head() {
    let server = KeepAliveServer::start(|request| {
        if request.line.starts_with("HEAD ") {
            return keep_alive_response(404, "");
        }
        if request.line.starts_with("PUT ") {
            return keep_alive_response(200, "");
        }
        if request.line.starts_with("POST ") && request.line.contains("?uploads ") {
            return PeerReply::DropWithoutResponse;
        }
        keep_alive_response(204, "")
    });
    let mut target = server.target();
    let setup = setup(
        "[[buckets]]\nname = \"mpu-no-retry\"\n\
         [[multipart_uploads]]\nbucket = \"mpu-no-retry\"\nkey = \"parted\"\n",
    );

    let error = target
        .prepare("c-ka-n003", Some(&setup))
        .expect_err("dropped upload init must fail unresolved");
    assert!(error.to_string().contains("unresolved"), "{error}");

    let report = server.finish();
    let init_attempts = report
        .requests
        .iter()
        .filter(|request| request.line == "POST /mpu-no-retry/parted?uploads HTTP/1.1")
        .count();
    assert_eq!(init_attempts, 1, "non-idempotent multipart init must not be retried on a dropped socket");
}

/// Positive — more than 1,000 objects are split into <=1,000-key `DeleteObjects` batches with
/// exact `Content-MD5` and XML escaping, reusing 1 socket for prepare and 1 socket for cleanup.
#[test]
fn batch_delete_chunks_over_1000_objects_with_valid_md5_and_xml_escaping() {
    let server = KeepAliveServer::start(default_keep_alive_responder);
    let mut target = server.target();
    let mut toml = String::from("[[buckets]]\nname = \"big-batch\"\n");
    // Include XML metacharacters in key 0 and key 1001 so both batches exercise escaping.
    toml.push_str("[[objects]]\nbucket = \"big-batch\"\nkey = \"a&b<c>\\\"'0\"\n");
    for index in 1..1001 {
        toml.push_str(&format!("[[objects]]\nbucket = \"big-batch\"\nkey = \"k/{index:04}\"\n"));
    }
    toml.push_str("[[objects]]\nbucket = \"big-batch\"\nkey = \"tail&<1001>\"\n");
    let setup = setup(&toml);

    target.prepare("c-batch-0001", Some(&setup)).expect("prepare 1002 objects");
    target.finish("c-batch-0001").expect("batch cleanup of 1002 objects");

    let report = server.finish();
    // 1 socket for all 2,006 prepare requests + 1 socket for all 3 cleanup requests (2 POST + 1 DELETE).
    assert_eq!(report.accepted_sockets, 2, "expected 2 keep-alive sockets total");
    let posts: Vec<&RecordedRequest> = report
        .requests
        .iter()
        .filter(|request| request.line == "POST /big-batch?delete HTTP/1.1")
        .collect();
    assert_eq!(posts.len(), 2, "1002 objects must split into 2 DeleteObjects batches");
    assert_eq!(raw_xml_keys(&posts[0].body).len(), 1000);
    assert_eq!(raw_xml_keys(&posts[1].body).len(), 2);
    for post in &posts {
        assert_eq!(post.content_type.as_deref(), Some("application/xml"));
        let expected_md5 = crate::fixture::encode_base64(&crate::md5::digest(&post.body));
        assert_eq!(post.content_md5.as_deref(), Some(expected_md5.as_str()));
    }
    let body0 = std::str::from_utf8(&posts[0].body).expect("batch 0 UTF-8");
    let body1 = std::str::from_utf8(&posts[1].body).expect("batch 1 UTF-8");
    assert!(body0.contains("<Key>tail&amp;&lt;1001&gt;</Key>"), "{body0}");
    assert!(body1.contains("<Key>a&amp;b&lt;c&gt;&quot;&apos;0</Key>"), "{body1}");
    assert_eq!(
        report.requests.last().map(|request| request.line.as_str()),
        Some("DELETE /big-batch HTTP/1.1")
    );
}

/// Negative — a partial `<Error>` in `<DeleteResult>` retains only the failed key, blocks
/// `DELETE /{bucket}`, and allows a subsequent `finish` retry to clean up cleanly.
#[test]
fn batch_delete_partial_error_retains_failed_key_and_blocks_bucket_delete() {
    let server = KeepAliveServer::start(|request| {
        if request.line.starts_with("POST ") && request.line.contains("?delete ") {
            let body = "<DeleteResult>\
                <Deleted><Key>three</Key></Deleted>\
                <Error><Key>two</Key><Code>AccessDenied</Code><Message>denied</Message></Error>\
                <Deleted><Key>one</Key></Deleted>\
                </DeleteResult>";
            return keep_alive_response(200, body);
        }
        default_keep_alive_responder(request)
    });
    let mut target = server.target();
    let setup = setup(
        "[[buckets]]\nname = \"partial-err\"\n\
         [[objects]]\nbucket = \"partial-err\"\nkey = \"one\"\n\
         [[objects]]\nbucket = \"partial-err\"\nkey = \"two\"\n\
         [[objects]]\nbucket = \"partial-err\"\nkey = \"three\"\n",
    );

    target.prepare("c-batch-n001", Some(&setup)).expect("prepare succeeds");
    let error = target
        .finish("c-batch-n001")
        .expect_err("partial <Error> must fail cleanup and block bucket delete");
    assert!(
        error.to_string().contains("partial-err/two") && error.to_string().contains("AccessDenied"),
        "{error}"
    );
    target
        .finish("c-batch-n001")
        .expect("retry removes only retained key `two` then bucket");

    let report = server.finish();
    let cleanup: Vec<&str> = report.requests[8..].iter().map(|request| request.line.as_str()).collect();
    assert_eq!(
        cleanup,
        [
            "POST /partial-err?delete HTTP/1.1",
            "DELETE /partial-err/two HTTP/1.1",
            "DELETE /partial-err HTTP/1.1",
        ]
    );
}

/// Negative — a key omitted from `<DeleteResult>` (neither `<Deleted>` nor `<Error>`) is treated
/// as still owned, blocks `DELETE /{bucket}`, and is retried on the next `finish`.
#[test]
fn batch_delete_unreported_key_retains_ownership_and_blocks_bucket_delete() {
    let server = KeepAliveServer::start(|request| {
        if request.line.starts_with("POST ") && request.line.contains("?delete ") {
            return keep_alive_response(200, "<DeleteResult><Deleted><Key>two</Key></Deleted></DeleteResult>");
        }
        default_keep_alive_responder(request)
    });
    let mut target = server.target();
    let setup = setup(
        "[[buckets]]\nname = \"omit-key\"\n\
         [[objects]]\nbucket = \"omit-key\"\nkey = \"one\"\n\
         [[objects]]\nbucket = \"omit-key\"\nkey = \"two\"\n",
    );

    target.prepare("c-batch-n002", Some(&setup)).expect("prepare succeeds");
    let error = target.finish("c-batch-n002").expect_err("unreported key must remain owned");
    assert!(error.to_string().contains("omit-key/one"), "{error}");
    assert!(error.to_string().contains("not confirmed deleted"), "{error}");
    target.finish("c-batch-n002").expect("retry cleans remaining key and bucket");

    let report = server.finish();
    let cleanup: Vec<&str> = report.requests[6..].iter().map(|request| request.line.as_str()).collect();
    assert_eq!(
        cleanup,
        [
            "POST /omit-key?delete HTTP/1.1",
            "DELETE /omit-key/one HTTP/1.1",
            "DELETE /omit-key HTTP/1.1",
        ]
    );
}

/// Negative — a `200 OK` carrying an `<Error>` root or malformed XML retains every object in the
/// batch and blocks `DELETE /{bucket}` until a retry receives a valid `<DeleteResult>`.
#[test]
fn batch_delete_malformed_or_error_root_200_retains_all_keys_and_blocks_bucket_delete() {
    for bad_body in ["<Error><Code>InternalError</Code></Error>", "<DeleteResult><Deleted><Key>one"] {
        let mut first_post = true;
        let server = KeepAliveServer::start(move |request| {
            if request.line.starts_with("POST ") && request.line.contains("?delete ") && first_post {
                first_post = false;
                return keep_alive_response(200, bad_body);
            }
            default_keep_alive_responder(request)
        });
        let mut target = server.target();
        let setup = setup(
            "[[buckets]]\nname = \"bad-xml\"\n\
             [[objects]]\nbucket = \"bad-xml\"\nkey = \"one\"\n\
             [[objects]]\nbucket = \"bad-xml\"\nkey = \"two\"\n",
        );

        target.prepare("c-batch-n003", Some(&setup)).expect("prepare succeeds");
        let error = target
            .finish("c-batch-n003")
            .expect_err("malformed DeleteResult must fail cleanup");
        assert!(error.to_string().contains("unreadable DeleteResult"), "{bad_body}: {error}");
        target.finish("c-batch-n003").expect("retry deletes both keys and bucket");

        let report = server.finish();
        let cleanup: Vec<&str> = report.requests[6..].iter().map(|request| request.line.as_str()).collect();
        assert_eq!(
            cleanup,
            [
                "POST /bad-xml?delete HTTP/1.1",
                "POST /bad-xml?delete HTTP/1.1",
                "DELETE /bad-xml HTTP/1.1",
            ],
            "failed XML must retain both keys and never send DELETE /bad-xml before retry"
        );
        assert_eq!(raw_xml_keys(&report.requests[7].body), ["two", "one"]);
    }
}

/// Negative — when the endpoint answers `501 Not Implemented` to `POST /{bucket}?delete`, cleanup
/// falls back to single-object `DELETE` in reverse creation order before removing the bucket.
#[test]
fn batch_delete_501_falls_back_to_reverse_order_single_deletes() {
    let server = KeepAliveServer::start(|request| {
        if request.line.starts_with("POST ") && request.line.contains("?delete ") {
            return keep_alive_response(501, "<Error><Code>NotImplemented</Code></Error>");
        }
        default_keep_alive_responder(request)
    });
    let mut target = server.target();
    let setup = setup(
        "[[buckets]]\nname = \"fallback-501\"\n\
         [[objects]]\nbucket = \"fallback-501\"\nkey = \"one\"\n\
         [[objects]]\nbucket = \"fallback-501\"\nkey = \"two\"\n\
         [[objects]]\nbucket = \"fallback-501\"\nkey = \"three\"\n",
    );

    target.prepare("c-batch-n004", Some(&setup)).expect("prepare succeeds");
    target
        .finish("c-batch-n004")
        .expect("501 fallback removes all objects and bucket");

    let report = server.finish();
    let cleanup: Vec<&str> = report.requests[8..].iter().map(|request| request.line.as_str()).collect();
    assert_eq!(
        cleanup,
        [
            "POST /fallback-501?delete HTTP/1.1",
            "DELETE /fallback-501/three HTTP/1.1",
            "DELETE /fallback-501/two HTTP/1.1",
            "DELETE /fallback-501/one HTTP/1.1",
            "DELETE /fallback-501 HTTP/1.1",
        ]
    );
}

/// Negative — a `500` on `POST /{bucket}?delete` does NOT fall back to single deletes; it retains
/// all objects, blocks bucket deletion, and surfaces the status 500 error for retry.
#[test]
fn batch_delete_500_does_not_fall_back_and_retains_all_keys_for_retry() {
    let mut first_post = true;
    let server = KeepAliveServer::start(move |request| {
        if request.line.starts_with("POST ") && request.line.contains("?delete ") && first_post {
            first_post = false;
            return keep_alive_response(500, "");
        }
        default_keep_alive_responder(request)
    });
    let mut target = server.target();
    let setup = setup(
        "[[buckets]]\nname = \"batch-500\"\n\
         [[objects]]\nbucket = \"batch-500\"\nkey = \"one\"\n\
         [[objects]]\nbucket = \"batch-500\"\nkey = \"two\"\n",
    );

    target.prepare("c-batch-n005", Some(&setup)).expect("prepare succeeds");
    let error = target
        .finish("c-batch-n005")
        .expect_err("500 must fail cleanup without fallback");
    assert!(error.to_string().contains("status 500"), "{error}");
    target.finish("c-batch-n005").expect("retry cleans batch and bucket");

    let report = server.finish();
    let cleanup: Vec<&str> = report.requests[6..].iter().map(|request| request.line.as_str()).collect();
    assert_eq!(
        cleanup,
        [
            "POST /batch-500?delete HTTP/1.1",
            "POST /batch-500?delete HTTP/1.1",
            "DELETE /batch-500 HTTP/1.1",
        ]
    );
}

/// Positive — keys containing ASCII control characters (`< 0x20`) bypass XML batching via single
/// `DELETE` while XML-safe sibling keys in the same bucket still batch via `POST /{bucket}?delete`.
#[test]
fn control_key_with_xml_control_char_uses_single_delete_while_batching_safe_keys() {
    let server = KeepAliveServer::start(default_keep_alive_responder);
    let mut target = server.target();
    let setup = setup(
        "[[buckets]]\nname = \"mixed-keys\"\n\
         [[objects]]\nbucket = \"mixed-keys\"\nkey = \"safe-one\"\n\
         [[objects]]\nbucket = \"mixed-keys\"\nkey = \"tab\\tkey\"\n\
         [[objects]]\nbucket = \"mixed-keys\"\nkey = \"safe-two\"\n",
    );

    target.prepare("c-batch-0002", Some(&setup)).expect("prepare succeeds");
    target.finish("c-batch-0002").expect("cleanup succeeds");

    let report = server.finish();
    let cleanup: Vec<&str> = report.requests[8..].iter().map(|request| request.line.as_str()).collect();
    assert_eq!(
        cleanup,
        [
            "POST /mixed-keys?delete HTTP/1.1",
            "DELETE /mixed-keys/tab%09key HTTP/1.1",
            "DELETE /mixed-keys HTTP/1.1",
        ]
    );
    assert_eq!(raw_xml_keys(&report.requests[8].body), ["safe-two", "safe-one"]);
}
