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

//! Object fixture ownership and refusal controls against a real loopback socket.
//!
//! Responsible for: proving complete payload decoding, validation-before-mutation, ownership
//! transitions, and object-before-bucket cleanup. NOT responsible for: full CLI runner cleanup
//! coverage or production endpoint behavior. Upstream: `super`; downstream: a bounded fake S3
//! endpoint.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::super::Conn;
use crate::sut::{Sut, SutError};

const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const NO_CONTENT: &[u8] = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
const SERVER_ERROR: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rustfs-gateway-external-object-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create temporary corpus root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn setup(source: &str) -> crate::value::Value {
    crate::toml::parse(source).expect("valid setup TOML")
}

fn target(root: std::path::PathBuf, url: &str) -> Conn {
    Conn::external_with_fixtures(root, url, None).expect("opted-in external target")
}

fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bounded request read");
    let mut request = Vec::new();
    loop {
        let mut block = [0_u8; 1024];
        let read = stream.read(&mut block).expect("read request bytes");
        assert_ne!(read, 0, "request ended before its declared body");
        request.extend_from_slice(&block[..read]);
        let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4) else {
            continue;
        };
        let head = std::str::from_utf8(&request[..head_end]).expect("request head is UTF-8");
        let body_len = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("numeric content length"))
            })
            .unwrap_or(0);
        if request.len() >= head_end + body_len {
            return request;
        }
    }
}

fn fixture_server(responses: Vec<&'static [u8]>) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake endpoint");
    listener.set_nonblocking(true).expect("bounded accepts");
    let address = listener.local_addr().expect("fake endpoint address");
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return requests,
                    Err(error) => panic!("accept fake endpoint request: {error}"),
                }
            };
            stream.set_nonblocking(false).expect("blocking exchange");
            requests.push(read_request(&mut stream));
            stream.write_all(response).expect("write fake response");
        }
        requests
    });
    (format!("http://{address}"), server)
}

fn line(request: &[u8]) -> &str {
    let head_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
        .expect("request head terminator");
    std::str::from_utf8(&request[..head_end])
        .expect("request is UTF-8")
        .lines()
        .next()
        .expect("request line")
}

fn lines(requests: &[Vec<u8>]) -> Vec<&str> {
    requests.iter().map(|request| line(request)).collect()
}

fn error_before_connection(source: &str) -> SutError {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint probe");
    listener.set_nonblocking(true).expect("bounded endpoint probe");
    let address = listener.local_addr().expect("endpoint probe address");
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(200);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).expect("blocking probe exchange");
                    let request = read_request(&mut stream);
                    stream.write_all(SERVER_ERROR).expect("write probe response");
                    return Some(request);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return None,
                Err(error) => panic!("accept endpoint probe: {error}"),
            }
        }
    });
    let mut target = target(std::path::PathBuf::from("."), &format!("http://{address}"));
    let error = target
        .prepare("s-external-object-negative", Some(&setup(source)))
        .expect_err("setup is refused");
    assert!(server.join().expect("endpoint probe exits").is_none(), "validation sent remote bytes");
    error
}

#[test]
fn every_payload_source_reaches_the_object_put_unchanged() {
    let root = TestRoot::new();
    std::fs::write(root.path().join("payload.bin"), [0x10, 0x20, 0x30]).expect("write fixture payload");
    let cases: [(&str, &[u8]); 4] = [
        ("body = { utf8 = \"snow\" }", b"snow"),
        ("body = { file = \"payload.bin\" }", &[0x10, 0x20, 0x30]),
        ("body = { size = 5, fill = \"ab\" }", &[0xab; 5]),
        ("body = { size = 3 }", &[0x00, 0x01, 0x02]),
    ];
    for (index, (payload, expected)) in cases.into_iter().enumerate() {
        let bucket = format!("fixture-payload-{index}");
        let (url, server) = fixture_server(vec![NOT_FOUND, OK, NOT_FOUND, OK, NO_CONTENT, NO_CONTENT]);
        let mut target = target(root.path().to_path_buf(), &url);
        let source =
            format!("[[buckets]]\nname = \"{bucket}\"\n\n[[objects]]\nbucket = \"{bucket}\"\nkey = \"fixture-key\"\n{payload}\n");

        target
            .prepare("s-external-object-payload", Some(&setup(&source)))
            .expect("prepare object");
        target.finish("s-external-object-payload").expect("clean object and bucket");

        let requests = server.join().expect("fake server exits");
        assert_eq!(
            lines(&requests)[2..],
            [
                format!("HEAD /{bucket}/fixture-key HTTP/1.1"),
                format!("PUT /{bucket}/fixture-key HTTP/1.1"),
                format!("DELETE /{bucket}/fixture-key HTTP/1.1"),
                format!("DELETE /{bucket} HTTP/1.1"),
            ]
        );
        assert!(requests[3].ends_with(expected), "payload source {index} changed bytes");
    }
}

#[test]
fn an_object_must_reference_a_bucket_owned_by_this_setup() {
    for source in [
        "[[buckets]]\nname = \"fixture-owned\"\n[[objects]]\nbucket = \"fixture-foreign\"\nkey = \"key\"\n",
        "[[buckets]]\nname = \"fixture-absent\"\nabsent = true\n[[objects]]\nbucket = \"fixture-absent\"\nkey = \"key\"\n",
    ] {
        let error = error_before_connection(source);
        assert!(error.to_string().contains("owned"), "{error}");
    }
}

#[test]
fn versioned_or_locked_object_buckets_are_refused_before_mutation() {
    for bucket_option in ["versioning = \"enabled\"", "versioning = \"suspended\"", "object_lock = true"] {
        let source = format!(
            "[[buckets]]\nname = \"fixture-bucket\"\n{bucket_option}\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"key\"\n"
        );
        let error = error_before_connection(&source);
        assert!(error.to_string().contains("unversioned and unlocked"), "{error}");
    }
}

#[test]
fn invalid_payload_or_header_is_refused_before_remote_mutation() {
    for object in [
        "body = {}",
        "body = { hex = \"0g\" }",
        "content_type = \"text/plain\\nforged: value\"",
        "storage_class = \"STANDARD\\nforged: value\"",
        "metadata = { \"bad name\" = \"value\" }",
        "metadata = { owner = \"value\\nforged: yes\" }",
    ] {
        let source = format!(
            "[[buckets]]\nname = \"fixture-bucket\"\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"key\"\n{object}\n"
        );
        let error = error_before_connection(&source);
        assert!(
            error.to_string().contains("payload") || error.to_string().contains("header"),
            "{object}: {error}"
        );
    }
}

#[test]
fn duplicate_object_declarations_are_refused_before_mutation() {
    let error = error_before_connection(
        "[[buckets]]\nname = \"fixture-bucket\"\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"same\"\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"same\"\n",
    );
    assert!(error.to_string().contains("more than once"), "{error}");
}

#[test]
fn a_pre_existing_object_is_never_owned_put_or_deleted() {
    let (url, server) = fixture_server(vec![NOT_FOUND, OK, OK, NO_CONTENT]);
    let mut target = target(std::path::PathBuf::from("."), &url);
    let setup = setup("[[buckets]]\nname = \"fixture-bucket\"\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"existing\"\n");

    let error = target
        .prepare("s-external-object-pre-existing", Some(&setup))
        .expect_err("existing object is refused");

    let requests = server.join().expect("fake server exits");
    assert!(error.to_string().contains("already exists"), "{error}");
    assert_eq!(
        lines(&requests),
        [
            "HEAD /fixture-bucket HTTP/1.1",
            "PUT /fixture-bucket HTTP/1.1",
            "HEAD /fixture-bucket/existing HTTP/1.1",
            "DELETE /fixture-bucket HTTP/1.1",
        ]
    );
}

#[test]
fn a_failed_object_put_is_not_owned() {
    let (url, server) = fixture_server(vec![NOT_FOUND, OK, NOT_FOUND, SERVER_ERROR, NO_CONTENT]);
    let mut target = target(std::path::PathBuf::from("."), &url);
    let setup = setup(
        "[[buckets]]\nname = \"fixture-bucket\"\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"failed\"\nbody = { utf8 = \"bytes\" }\n",
    );

    let error = target
        .prepare("s-external-object-put-failure", Some(&setup))
        .expect_err("failed PUT aborts prepare");

    let requests = server.join().expect("fake server exits");
    assert!(error.to_string().contains("status 500"), "{error}");
    assert_eq!(
        lines(&requests),
        [
            "HEAD /fixture-bucket HTTP/1.1",
            "PUT /fixture-bucket HTTP/1.1",
            "HEAD /fixture-bucket/failed HTTP/1.1",
            "PUT /fixture-bucket/failed HTTP/1.1",
            "DELETE /fixture-bucket HTTP/1.1",
        ]
    );
}

#[test]
fn a_partial_multi_object_prepare_cleans_only_owned_objects_in_reverse_order() {
    let (url, server) = fixture_server(vec![
        NOT_FOUND,
        OK,
        NOT_FOUND,
        OK,
        NOT_FOUND,
        OK,
        NOT_FOUND,
        SERVER_ERROR,
        NO_CONTENT,
        NO_CONTENT,
        NO_CONTENT,
    ]);
    let mut target = target(std::path::PathBuf::from("."), &url);
    let setup = setup(
        "[[buckets]]\nname = \"fixture-bucket\"\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"one\"\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"two\"\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"three\"\n",
    );

    target
        .prepare("s-external-object-partial", Some(&setup))
        .expect_err("third PUT aborts prepare");

    let requests = server.join().expect("fake server exits");
    assert_eq!(
        &lines(&requests)[7..],
        [
            "PUT /fixture-bucket/three HTTP/1.1",
            "DELETE /fixture-bucket/two HTTP/1.1",
            "DELETE /fixture-bucket/one HTTP/1.1",
            "DELETE /fixture-bucket HTTP/1.1",
        ]
    );
}

#[test]
fn an_absent_object_is_checked_but_never_owned_created_or_deleted() {
    let (url, server) = fixture_server(vec![NOT_FOUND, OK, NOT_FOUND, NO_CONTENT]);
    let mut target = target(std::path::PathBuf::from("."), &url);
    let setup = setup(
        "[[buckets]]\nname = \"fixture-bucket\"\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"absent\"\nabsent = true\n",
    );

    target
        .prepare("s-external-object-absent", Some(&setup))
        .expect("absence is proved");
    target.finish("s-external-object-absent").expect("only the bucket is cleaned");

    let requests = server.join().expect("fake server exits");
    assert_eq!(
        lines(&requests),
        [
            "HEAD /fixture-bucket HTTP/1.1",
            "PUT /fixture-bucket HTTP/1.1",
            "HEAD /fixture-bucket/absent HTTP/1.1",
            "DELETE /fixture-bucket HTTP/1.1",
        ]
    );
}

#[test]
fn an_object_delete_failure_retains_object_and_bucket_ownership_for_retry() {
    let (url, server) = fixture_server(vec![NOT_FOUND, OK, NOT_FOUND, OK, SERVER_ERROR, NO_CONTENT, NO_CONTENT]);
    let mut target = target(std::path::PathBuf::from("."), &url);
    let setup = setup("[[buckets]]\nname = \"fixture-bucket\"\n[[objects]]\nbucket = \"fixture-bucket\"\nkey = \"owned\"\n");
    target
        .prepare("s-external-object-delete-failure", Some(&setup))
        .expect("prepare fixture");

    let error = target
        .finish("s-external-object-delete-failure")
        .expect_err("object delete failure is surfaced");
    target
        .finish("s-external-object-delete-failure")
        .expect("retained ownership can be retried");

    let requests = server.join().expect("fake server exits");
    assert!(
        error.to_string().contains("cleanup") && error.to_string().contains("status 500"),
        "{error}"
    );
    assert_eq!(
        &lines(&requests)[4..],
        [
            "DELETE /fixture-bucket/owned HTTP/1.1",
            "DELETE /fixture-bucket/owned HTTP/1.1",
            "DELETE /fixture-bucket HTTP/1.1",
        ]
    );
}
