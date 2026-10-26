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

//! External empty-upload ownership controls against a bounded recording peer.
//!
//! Responsible for: returned upload identities, preflight refusals and abort/rollback ordering.
//! NOT responsible for: uploaded parts, versioned or locked objects, or target protocol behavior.
//! Upstream: external fixture preparation and cleanup. Downstream: a real loopback HTTP peer.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::super::Conn;
use crate::sut::{Sut, SutError};

const CASE: &str = "s-external-empty-multipart";
const BUCKET: &str = "[[buckets]]\nname = \"fixture-multipart\"\n";
const ONE_UPLOAD: &str =
    "[[multipart_uploads]]\nbucket = \"fixture-multipart\"\nkey = \"one\"\ncapture_upload_id_as = \"remote_upload\"\n";

// One fixture owns the bounded resolver while its sequence of control requests is active.
static PEERS: Mutex<()> = Mutex::new(());

struct Peer {
    url: String,
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<Vec<String>>>,
    _lease: MutexGuard<'static, ()>,
}

impl Peer {
    fn new(responses: Vec<Vec<u8>>) -> Self {
        let lease = PEERS.lock().expect("previous fixture released its lease");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind recording peer");
        listener.set_nonblocking(true).expect("bound accept wait");
        let url = format!("http://{}", listener.local_addr().expect("bound peer address"));
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut stream = loop {
                    if stopped.try_recv().is_ok() {
                        return requests;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return requests,
                        Err(_) => panic!("recording peer accept failed"),
                    }
                };
                stream.set_nonblocking(false).expect("blocking peer request");
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .expect("bound peer write");
                requests.push(request_line(&mut stream));
                stream.write_all(&response).expect("write fixture response");
            }
            requests
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            _lease: lease,
        }
    }

    fn target(&self) -> Conn {
        Conn::external_with_fixtures(".".into(), &self.url, None).expect("opted-in external target")
    }

    fn finish(mut self) -> Vec<String> {
        let _ = self.stop.send(());
        self.worker
            .take()
            .expect("recording worker exists")
            .join()
            .expect("recording worker exits")
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn request_line(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound peer read");
    let mut bytes = Vec::new();
    loop {
        let mut block = [0_u8; 1024];
        let count = stream.read(&mut block).expect("read fixture request");
        assert_ne!(count, 0, "fixture request ended early");
        bytes.extend_from_slice(&block[..count]);
        let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4) else {
            continue;
        };
        let head = std::str::from_utf8(&bytes[..end]).expect("fixture request head is text");
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("numeric length"))
            })
            .unwrap_or(0);
        if bytes.len() >= end + length {
            // Retain only the control request line; never retain or print signing headers.
            return head.lines().next().expect("fixture request line").to_owned();
        }
    }
}

fn response(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn initiated(id: &str) -> Vec<u8> {
    response(
        200,
        &format!(
            "<InitiateMultipartUploadResult><Bucket>fixture-multipart</Bucket><Key>one</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>"
        ),
    )
}

fn setup(tail: &str) -> crate::value::Value {
    crate::toml::parse(&format!("{BUCKET}{tail}")).expect("fixture setup TOML")
}

fn preflight_refusal(source: &str) {
    let peer = Peer::new(vec![response(500, "")]);
    let mut target = peer.target();
    let result = target.prepare(CASE, Some(&crate::toml::parse(source).expect("fixture setup TOML")));
    let requests = peer.finish();
    assert!(
        matches!(result, Err(SutError::Environment(_))),
        "invalid plan must be an environment refusal"
    );
    assert!(requests.is_empty(), "preflight refusal sent remote control requests: {requests:?}");
}

#[test]
fn returned_upload_id_is_captured_and_encoded_for_abort_before_bucket_deletion() {
    let peer = Peer::new(vec![
        response(404, ""),
        response(200, ""),
        initiated("remote/+ &amp;?"),
        response(204, ""),
        response(204, ""),
    ]);
    let mut target = peer.target();
    let prepared = target.prepare(CASE, Some(&setup(ONE_UPLOAD)));
    let finished = target.finish(CASE);
    let requests = peer.finish();
    let captures = prepared.expect("empty upload preparation must succeed");
    assert_eq!(captures.get("remote_upload").map(String::as_str), Some("remote/+ &?"));
    assert!(finished.is_ok(), "owned upload and bucket must be removed");
    assert_eq!(
        requests,
        [
            "HEAD /fixture-multipart HTTP/1.1",
            "PUT /fixture-multipart HTTP/1.1",
            "POST /fixture-multipart/one?uploads HTTP/1.1",
            "DELETE /fixture-multipart/one?uploadId=remote%2F%2B%20%26%3F HTTP/1.1",
            "DELETE /fixture-multipart HTTP/1.1",
        ]
    );
}

#[test]
fn an_empty_upload_array_needs_no_initiation_or_abort() {
    let peer = Peer::new(vec![response(404, ""), response(200, ""), response(204, "")]);
    let mut target = peer.target();
    let source = crate::toml::parse(&format!("multipart_uploads = []\n{BUCKET}")).expect("empty upload array setup");
    let prepared = target.prepare(CASE, Some(&source));
    let finished = target.finish(CASE);
    let requests = peer.finish();
    assert!(prepared.is_ok(), "an empty array adds no unsupported fixture state");
    assert!(finished.is_ok(), "only the owned bucket needs cleanup");
    assert_eq!(
        requests,
        [
            "HEAD /fixture-multipart HTTP/1.1",
            "PUT /fixture-multipart HTTP/1.1",
            "DELETE /fixture-multipart HTTP/1.1",
        ]
    );
}

#[test]
fn foreign_upload_bucket_is_rejected_before_contact() {
    preflight_refusal(&format!(
        "{BUCKET}{ONE_UPLOAD}[[multipart_uploads]]\nbucket = \"foreign-bucket\"\nkey = \"two\"\n"
    ));
}

#[test]
fn absent_upload_bucket_is_rejected_before_contact() {
    preflight_refusal(&format!("{BUCKET}absent = true\n{ONE_UPLOAD}"));
}

#[test]
fn uploaded_parts_are_rejected_before_any_bucket_is_created() {
    preflight_refusal(&format!(
        "{BUCKET}{ONE_UPLOAD}parts = [{{ part_number = 1, body = {{ utf8 = \"part\" }} }}]\n"
    ));
}

#[test]
fn missing_upload_key_is_rejected_before_contact() {
    preflight_refusal(&format!("{BUCKET}[[multipart_uploads]]\nbucket = \"fixture-multipart\"\n"));
}

#[test]
fn duplicate_capture_names_are_rejected_before_any_upload_is_created() {
    preflight_refusal(&format!(
        "{BUCKET}{ONE_UPLOAD}[[multipart_uploads]]\nbucket = \"fixture-multipart\"\nkey = \"two\"\ncapture_upload_id_as = \"remote_upload\"\n"
    ));
}

#[test]
fn a_failed_initiation_is_not_aborted_as_an_owned_upload() {
    let peer = Peer::new(vec![response(404, ""), response(200, ""), response(500, ""), response(204, "")]);
    let mut target = peer.target();
    let result = target.prepare(CASE, Some(&setup(ONE_UPLOAD)));
    let requests = peer.finish();
    assert!(matches!(result, Err(SutError::Environment(_))), "failed initiation must fail preparation");
    assert_eq!(
        requests,
        [
            "HEAD /fixture-multipart HTTP/1.1",
            "PUT /fixture-multipart HTTP/1.1",
            "POST /fixture-multipart/one?uploads HTTP/1.1",
            "DELETE /fixture-multipart HTTP/1.1",
        ]
    );
}

fn ambiguous_initiation(body: &str) {
    ambiguous_initiation_response(response(200, body));
}

fn ambiguous_initiation_response(initiation: Vec<u8>) {
    let peer = Peer::new(vec![response(404, ""), response(200, ""), initiation, response(500, "")]);
    let mut target = peer.target();
    let prepared = target.prepare(CASE, Some(&setup(ONE_UPLOAD)));
    let finished = target.finish(CASE);
    let next = target.prepare("s-next-fixture", Some(&setup("")));
    let requests = peer.finish();
    let error = prepared.expect_err("ambiguous initiation must fail preparation");
    assert!(matches!(error, SutError::Environment(_)), "invalid initiation is an environment refusal");
    assert!(
        error.to_string().contains("UploadId"),
        "refusal must identify the returned UploadId rather than an unsupported setup shape"
    );
    assert!(
        matches!(finished, Err(SutError::Environment(_))),
        "unresolved ownership must make cleanup fail"
    );
    assert!(
        matches!(next, Err(SutError::Environment(_))),
        "unresolved ownership must block the next setup"
    );
    assert_eq!(
        requests,
        [
            "HEAD /fixture-multipart HTTP/1.1",
            "PUT /fixture-multipart HTTP/1.1",
            "POST /fixture-multipart/one?uploads HTTP/1.1",
        ],
        "ambiguous initiation must not invent an abort target or delete its bucket"
    );
}

#[test]
fn missing_upload_id_retains_unresolved_bucket_ownership() {
    ambiguous_initiation(
        "<InitiateMultipartUploadResult><Bucket>fixture-multipart</Bucket><Key>one</Key></InitiateMultipartUploadResult>",
    );
}

#[test]
fn empty_upload_id_retains_unresolved_bucket_ownership() {
    ambiguous_initiation("<InitiateMultipartUploadResult><UploadId></UploadId></InitiateMultipartUploadResult>");
}

#[test]
fn duplicate_upload_ids_retain_unresolved_bucket_ownership() {
    ambiguous_initiation(
        "<InitiateMultipartUploadResult><UploadId>first</UploadId><UploadId>second</UploadId></InitiateMultipartUploadResult>",
    );
}

#[test]
fn malformed_initiation_xml_retains_unresolved_bucket_ownership() {
    ambiguous_initiation("<InitiateMultipartUploadResult><UploadId>unterminated");
}

#[test]
fn an_interrupted_initiation_response_retains_unresolved_bucket_ownership() {
    ambiguous_initiation_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n<InitiateMultipartUploadResult>".to_vec(),
    );
}

#[test]
fn nested_upload_id_does_not_supply_an_owned_identity() {
    ambiguous_initiation(
        "<InitiateMultipartUploadResult><Other><UploadId>nested</UploadId></Other></InitiateMultipartUploadResult>",
    );
}

#[test]
fn a_document_type_cannot_define_the_owned_upload_identity() {
    ambiguous_initiation(
        "<!DOCTYPE InitiateMultipartUploadResult [<!ENTITY upload 'invented'>]><InitiateMultipartUploadResult><UploadId>&upload;</UploadId></InitiateMultipartUploadResult>",
    );
}

#[test]
fn an_unknown_entity_does_not_become_a_literal_upload_identity() {
    ambiguous_initiation("<InitiateMultipartUploadResult><UploadId>&unknown;</UploadId></InitiateMultipartUploadResult>");
}

#[test]
fn multiple_document_roots_do_not_supply_an_owned_identity() {
    ambiguous_initiation(
        "<Other/><InitiateMultipartUploadResult><UploadId>second-root</UploadId></InitiateMultipartUploadResult>",
    );
}

#[test]
fn malformed_root_attribute_does_not_supply_an_owned_identity() {
    ambiguous_initiation("<InitiateMultipartUploadResult broken=><UploadId>id</UploadId></InitiateMultipartUploadResult>");
}

#[test]
fn duplicate_root_attributes_do_not_supply_an_owned_identity() {
    ambiguous_initiation(
        "<InitiateMultipartUploadResult marker=\"one\" marker=\"two\"><UploadId>id</UploadId></InitiateMultipartUploadResult>",
    );
}

#[test]
fn a_malformed_xml_comment_does_not_supply_an_owned_identity() {
    ambiguous_initiation(
        "<InitiateMultipartUploadResult><!-- invalid -- comment --><UploadId>id</UploadId></InitiateMultipartUploadResult>",
    );
}

#[test]
fn abort_failure_retains_upload_and_bucket_until_retry_succeeds() {
    let peer = Peer::new(vec![
        response(404, ""),
        response(200, ""),
        initiated("owned-id"),
        response(500, ""),
        response(204, ""),
        response(204, ""),
    ]);
    let mut target = peer.target();
    let prepared = target.prepare(CASE, Some(&setup(ONE_UPLOAD)));
    let first = target.finish(CASE);
    let blocked = target.prepare("s-next-fixture", Some(&setup("")));
    let retried = target.finish(CASE);
    let requests = peer.finish();
    assert!(prepared.is_ok(), "known upload must be owned");
    assert!(matches!(first, Err(SutError::Environment(_))), "failed abort must fail cleanup");
    assert!(matches!(blocked, Err(SutError::Environment(_))), "failed abort must block another setup");
    assert!(retried.is_ok(), "retained upload ownership must permit retry");
    assert_eq!(
        requests,
        [
            "HEAD /fixture-multipart HTTP/1.1",
            "PUT /fixture-multipart HTTP/1.1",
            "POST /fixture-multipart/one?uploads HTTP/1.1",
            "DELETE /fixture-multipart/one?uploadId=owned-id HTTP/1.1",
            "DELETE /fixture-multipart/one?uploadId=owned-id HTTP/1.1",
            "DELETE /fixture-multipart HTTP/1.1",
        ]
    );
}

#[test]
fn partial_initiation_failure_aborts_known_uploads_in_reverse_order() {
    let peer = Peer::new(vec![
        response(404, ""),
        response(200, ""),
        initiated("first-id"),
        initiated("second-id"),
        response(500, ""),
        response(204, ""),
        response(204, ""),
        response(204, ""),
    ]);
    let mut target = peer.target();
    let source = format!(
        "{ONE_UPLOAD}[[multipart_uploads]]\nbucket = \"fixture-multipart\"\nkey = \"two\"\n[[multipart_uploads]]\nbucket = \"fixture-multipart\"\nkey = \"three\"\n"
    );
    let result = target.prepare(CASE, Some(&setup(&source)));
    let requests = peer.finish();
    assert!(matches!(result, Err(SutError::Environment(_))), "third initiation must fail preparation");
    assert_eq!(
        requests,
        [
            "HEAD /fixture-multipart HTTP/1.1",
            "PUT /fixture-multipart HTTP/1.1",
            "POST /fixture-multipart/one?uploads HTTP/1.1",
            "POST /fixture-multipart/two?uploads HTTP/1.1",
            "POST /fixture-multipart/three?uploads HTTP/1.1",
            "DELETE /fixture-multipart/two?uploadId=second-id HTTP/1.1",
            "DELETE /fixture-multipart/one?uploadId=first-id HTTP/1.1",
            "DELETE /fixture-multipart HTTP/1.1",
        ]
    );
}

#[test]
fn ambiguous_later_initiation_still_aborts_known_uploads_without_deleting_the_bucket() {
    let peer = Peer::new(vec![
        response(404, ""),
        response(200, ""),
        initiated("first-id"),
        response(200, "<InitiateMultipartUploadResult/>"),
        response(204, ""),
        response(500, ""),
    ]);
    let mut target = peer.target();
    let source = format!("{ONE_UPLOAD}[[multipart_uploads]]\nbucket = \"fixture-multipart\"\nkey = \"two\"\n");
    let prepared = target.prepare(CASE, Some(&setup(&source)));
    let finished = target.finish(CASE);
    let requests = peer.finish();
    assert!(
        matches!(prepared, Err(SutError::Environment(_))),
        "ambiguous second initiation must fail preparation"
    );
    assert!(
        matches!(finished, Err(SutError::Environment(_))),
        "unknown second upload must remain unresolved"
    );
    assert_eq!(
        requests,
        [
            "HEAD /fixture-multipart HTTP/1.1",
            "PUT /fixture-multipart HTTP/1.1",
            "POST /fixture-multipart/one?uploads HTTP/1.1",
            "POST /fixture-multipart/two?uploads HTTP/1.1",
            "DELETE /fixture-multipart/one?uploadId=first-id HTTP/1.1",
        ]
    );
}

#[test]
fn ambiguous_upload_does_not_prevent_cleanup_of_an_unrelated_owned_bucket() {
    let peer = Peer::new(vec![
        response(404, ""),
        response(200, ""),
        response(404, ""),
        response(200, ""),
        response(200, "<InitiateMultipartUploadResult/>"),
        response(204, ""),
        response(500, ""),
    ]);
    let mut target = peer.target();
    let source = format!("[[buckets]]\nname = \"fixture-unrelated\"\n{ONE_UPLOAD}");
    let prepared = target.prepare(CASE, Some(&setup(&source)));
    let finished = target.finish(CASE);
    let requests = peer.finish();
    assert!(
        matches!(prepared, Err(SutError::Environment(_))),
        "ambiguous initiation must fail preparation"
    );
    assert!(matches!(finished, Err(SutError::Environment(_))), "affected bucket remains unresolved");
    assert_eq!(
        requests,
        [
            "HEAD /fixture-multipart HTTP/1.1",
            "PUT /fixture-multipart HTTP/1.1",
            "HEAD /fixture-unrelated HTTP/1.1",
            "PUT /fixture-unrelated HTTP/1.1",
            "POST /fixture-multipart/one?uploads HTTP/1.1",
            "DELETE /fixture-unrelated HTTP/1.1",
        ]
    );
}
