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

//! External Object Lock fixture ownership, verification, preflight, and cleanup controls.
//!
//! Responsible for: observing wire control traffic on a recording loopback peer for Object Lock
//! bucket creation, readback proofs, read-only exact version cleanup, `--allow-external-writes`
//! GOVERNANCE bypass and Legal Hold lifting, and preflight COMPLIANCE refusal.
//! NOT responsible for: target backend persistence or case verdict semantics. Upstream: `Conn` and
//! `Sut`; downstream: bounded loopback TCP sockets.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::super::Conn;
use crate::sut::{ExchangePlan, Profile, Sut, SutError, Transport};

const CASE: &str = "s-external-object-lock";
const BUCKET: &str = "[[buckets]]\nname = \"fixture-lock\"\nobject_lock = true\n";
const LOCK_ENABLED: &str = "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
const VERSIONING_ENABLED: &str = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>";
const EMPTY_UPLOADS: &str = "<ListMultipartUploadsResult></ListMultipartUploadsResult>";
const EMPTY_VERSIONS: &str = "<ListVersionsResult></ListVersionsResult>";
static PEERS: Mutex<()> = Mutex::new(());

#[derive(Debug)]
struct Request {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, wanted: &str) -> Option<&str> {
        self.headers
            .iter()
            .find_map(|(name, value)| name.eq_ignore_ascii_case(wanted).then_some(value.as_str()))
    }
}

struct Peer {
    url: String,
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<Vec<Request>>>,
    _lease: MutexGuard<'static, ()>,
}

impl Peer {
    fn new(responses: Vec<Option<Vec<u8>>>) -> Self {
        let lease = PEERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind recording peer");
        listener.set_nonblocking(true).expect("bound accept wait");
        let url = format!("http://{}", listener.local_addr().expect("bound peer address"));
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut responses = VecDeque::from(responses);
            let mut requests = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if stopped.try_recv().is_ok() {
                    return requests;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking peer request");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .expect("bound peer write");
                        requests.push(read_request(&mut stream));
                        if let Some(reply) = responses.pop_front().unwrap_or_else(|| response(500, "", "")) {
                            stream.write_all(&reply).expect("write fixture response");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return requests,
                    Err(_) => panic!("recording peer accept failed"),
                }
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
        Conn::external_with_fixtures(".".into(), &self.url, None).expect("opted-in external target")
    }

    fn writable_target(&self) -> Conn {
        let mut target = self.target();
        target.allow_external_writes();
        target
    }

    fn finish(mut self) -> Vec<Request> {
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

fn read_request(stream: &mut TcpStream) -> Request {
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
        let mut lines = head.lines();
        let line = lines.next().expect("fixture request line").to_owned();
        let headers: Vec<(String, String)> = lines
            .filter_map(|row| {
                let (name, value) = row.split_once(':')?;
                // Drop signing material so assertion failures never print credentials or signatures.
                if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("x-amz-security-token") {
                    return None;
                }
                Some((name.to_owned(), value.trim().to_owned()))
            })
            .collect();
        let length = headers
            .iter()
            .find_map(|(name, value)| name.eq_ignore_ascii_case("content-length").then_some(value.as_str()))
            .map(|value| value.parse::<usize>().expect("numeric length"))
            .unwrap_or(0);
        if bytes.len() >= end + length {
            return Request {
                line,
                headers,
                body: bytes[end..end + length].to_vec(),
            };
        }
    }
}

fn response(status: u16, headers: &str, body: &str) -> Option<Vec<u8>> {
    Some(
        format!(
            "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        )
        .into_bytes(),
    )
}

fn version(status: u16, id: &str) -> Option<Vec<u8>> {
    response(status, &format!("x-amz-version-id: {id}\r\n"), "")
}

fn created_lock_bucket() -> Vec<Option<Vec<u8>>> {
    vec![
        response(404, "", ""),
        response(200, "", ""),
        response(200, "", LOCK_ENABLED),
        response(200, "", VERSIONING_ENABLED),
    ]
}

fn toml(source: &str) -> crate::value::Value {
    crate::toml::parse(source).expect("valid test TOML")
}

fn plan(source: &str) -> ExchangePlan<'static> {
    ExchangePlan {
        case_id: CASE,
        index: 0,
        request: toml(source),
        clock: None,
        connection: None,
        timeout_ms: Some(2_000),
        deadline: None,
        transport: Transport::Conn,
        profile: Profile::Aws,
    }
}

fn lines(requests: &[Request]) -> Vec<&str> {
    requests.iter().map(|request| request.line.as_str()).collect()
}

/// Positive — read-only Object Lock setup sends `x-amz-bucket-object-lock-enabled: true` on
/// CreateBucket (alongside region XML when non-default), proves both `?object-lock` and
/// `?versioning` readback, tracks the setup object's exact version ID, runs a read-only exchange,
/// and cleans up by encoded version ID without sending governance bypass.
#[test]
fn read_only_object_lock_setup_proves_lock_and_versioning_and_cleans_exact_version() {
    let mut replies = created_lock_bucket();
    replies.extend([
        response(404, "", ""),
        version(200, "v-lock/+ &?"),
        response(404, "", "<Error><Code>NoSuchObjectLockConfiguration</Code></Error>"),
        response(204, "", ""),
        response(204, "", ""),
    ]);
    let peer = Peer::new(replies);
    let mut target = peer.target();
    let setup = toml(
        "[[buckets]]\nname = \"fixture-lock\"\nregion = \"us-west-2\"\nobject_lock = true\n\
         [[objects]]\nbucket = \"fixture-lock\"\nkey = \"doc.txt\"\nbody = { utf8 = \"payload\" }\n",
    );
    let read_req = toml("method = \"GET\"\ntarget = \"/fixture-lock/doc.txt?retention\"\n");
    target
        .validate_requests(CASE, Some(&setup), &[&read_req])
        .expect("read-only Object Lock case must pass preflight without external writes");
    target
        .prepare(CASE, Some(&setup))
        .expect("Object Lock fixture setup must succeed");
    let observed = target
        .exchange(&plan("method = \"GET\"\ntarget = \"/fixture-lock/doc.txt?retention\"\n"))
        .expect("read-only retention GET must succeed");
    assert_eq!(observed.status, Some(404));
    target
        .finish(CASE)
        .expect("read-only Object Lock fixture cleanup must succeed");
    let requests = peer.finish();
    assert_eq!(
        lines(&requests),
        [
            "HEAD /fixture-lock HTTP/1.1",
            "PUT /fixture-lock HTTP/1.1",
            "GET /fixture-lock?object-lock HTTP/1.1",
            "GET /fixture-lock?versioning HTTP/1.1",
            "HEAD /fixture-lock/doc.txt HTTP/1.1",
            "PUT /fixture-lock/doc.txt HTTP/1.1",
            "GET /fixture-lock/doc.txt?retention HTTP/1.1",
            "DELETE /fixture-lock/doc.txt?versionId=v-lock%2F%2B%20%26%3F HTTP/1.1",
            "DELETE /fixture-lock HTTP/1.1",
        ]
    );
    assert_eq!(
        requests[1].header("x-amz-bucket-object-lock-enabled"),
        Some("true"),
        "CreateBucket must request Object Lock enablement"
    );
    assert_eq!(
        requests[1].header("content-type"),
        Some("application/xml"),
        "non-default region CreateBucket must keep its XML content-type"
    );
    assert!(
        requests[7].header("x-amz-bypass-governance-retention").is_none(),
        "read-only exact version cleanup must not send governance bypass"
    );
}

/// Positive — with `--allow-external-writes`, cleanup deletes owned setup versions and listed
/// versions with `x-amz-bypass-governance-retention: true`, lifts legal holds (`Status=OFF` with
/// Content-MD5) when a version answers 403, retries deletion with bypass, deletes delete markers,
/// and removes the bucket.
#[test]
fn external_writes_cleanup_bypasses_governance_lifts_legal_hold_and_removes_delete_markers() {
    let mut replies = created_lock_bucket();
    let listed_versions = "<ListVersionsResult>\
        <Version><Key>extra/gov.txt</Key><VersionId>v-gov</VersionId></Version>\
        <Version><Key>extra/held.txt</Key><VersionId>v-hold/1</VersionId></Version>\
        <DeleteMarker><Key>extra/gone.txt</Key><VersionId>v-dm</VersionId></DeleteMarker>\
        </ListVersionsResult>";
    replies.extend([
        // setup object HEAD + PUT
        response(404, "", ""),
        version(200, "v-setup"),
        // authored write (simulated retention + legal hold)
        response(200, "", ""),
        // owned_versions cleanup for v-setup: 403 (held) -> PUT legal-hold OFF (200) -> DELETE bypass (204)
        response(403, "", ""),
        response(200, "", ""),
        response(204, "", ""),
        // empty_fixture_bucket round 1: uploads (empty), versions (v-gov, v-hold/1, v-dm)
        response(200, "", EMPTY_UPLOADS),
        response(200, "", listed_versions),
        // v-gov deleted directly with bypass
        response(204, "", ""),
        // v-hold/1 gets 403 -> PUT legal-hold OFF (200) -> DELETE bypass (204)
        response(403, "", ""),
        response(200, "", ""),
        response(204, "", ""),
        // v-dm delete marker deleted directly
        response(204, "", ""),
        // empty_fixture_bucket round 2: empty uploads & versions
        response(200, "", EMPTY_UPLOADS),
        response(200, "", EMPTY_VERSIONS),
        // DELETE bucket
        response(204, "", ""),
    ]);
    let peer = Peer::new(replies);
    let mut target = peer.writable_target();
    let setup = toml(&format!(
        "{BUCKET}[[objects]]\nbucket = \"fixture-lock\"\nkey = \"doc.txt\"\nbody = {{ utf8 = \"payload\" }}\n"
    ));
    target.prepare(CASE, Some(&setup)).expect("prepare Object Lock setup");
    target
        .exchange(&plan(
            "method = \"PUT\"\ntarget = \"/fixture-lock/doc.txt?legal-hold\"\n\
             body = { utf8 = '<LegalHold><Status>ON</Status></LegalHold>' }\n",
        ))
        .expect("authored legal-hold PUT");
    target
        .finish(CASE)
        .expect("cleanup must bypass governance, lift legal holds, and remove the bucket");
    let requests = peer.finish();
    assert_eq!(
        lines(&requests)[7..],
        [
            "DELETE /fixture-lock/doc.txt?versionId=v-setup HTTP/1.1",
            "PUT /fixture-lock/doc.txt?legal-hold&versionId=v-setup HTTP/1.1",
            "DELETE /fixture-lock/doc.txt?versionId=v-setup HTTP/1.1",
            "GET /fixture-lock?uploads HTTP/1.1",
            "GET /fixture-lock?versions HTTP/1.1",
            "DELETE /fixture-lock/extra/gov.txt?versionId=v-gov HTTP/1.1",
            "DELETE /fixture-lock/extra/held.txt?versionId=v-hold%2F1 HTTP/1.1",
            "PUT /fixture-lock/extra/held.txt?legal-hold&versionId=v-hold%2F1 HTTP/1.1",
            "DELETE /fixture-lock/extra/held.txt?versionId=v-hold%2F1 HTTP/1.1",
            "DELETE /fixture-lock/extra/gone.txt?versionId=v-dm HTTP/1.1",
            "GET /fixture-lock?uploads HTTP/1.1",
            "GET /fixture-lock?versions HTTP/1.1",
            "DELETE /fixture-lock HTTP/1.1",
        ]
    );
    for index in [7, 9, 12, 13, 15, 16] {
        assert_eq!(
            requests[index].header("x-amz-bypass-governance-retention"),
            Some("true"),
            "locked version delete at {index} ({}) must carry governance bypass",
            requests[index].line
        );
    }
    for index in [8, 14] {
        let xml = std::str::from_utf8(&requests[index].body).expect("legal-hold XML is UTF-8");
        assert!(xml.contains("<Status>OFF</Status>"), "legal-hold lift must set OFF: {xml}");
        assert_eq!(
            requests[index].header("content-md5"),
            Some(crate::fixture::encode_base64(&crate::md5::digest(&requests[index].body)).as_str()),
            "legal-hold lift must carry valid Content-MD5"
        );
    }
}

/// Positive (two-directional control) — configuring bucket-level COMPLIANCE DefaultRetention
/// without writing any object does not lock any object version and stays admitted under writes.
#[test]
fn compliance_bucket_default_retention_without_object_write_is_allowed() {
    let peer = Peer::new(Vec::new());
    let target = peer.writable_target();
    let setup = toml("[[buckets]]\nname = \"fixture-lock\"\n");
    let put_cfg = toml(
        "method = \"PUT\"\ntarget = \"/fixture-lock?object-lock\"\n\
         body = { utf8 = '<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>\
         <Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>' }\n",
    );
    let get_cfg = toml("method = \"GET\"\ntarget = \"/fixture-lock?object-lock\"\n");
    let admitted = target.validate_requests(CASE, Some(&setup), &[&put_cfg, &get_cfg]);
    let requests = peer.finish();
    assert!(
        admitted.is_ok(),
        "bucket DefaultRetention without object writes must remain runnable: {admitted:?}"
    );
    assert!(requests.is_empty());
}

/// Negative — invalid Object Lock bucket declarations are rejected before any socket connect.
#[test]
fn object_lock_with_disabled_versioning_or_absent_or_non_bool_is_rejected_before_connecting() {
    for invalid in [
        "[[buckets]]\nname = \"fixture-lock\"\nversioning = \"disabled\"\nobject_lock = true\n",
        "[[buckets]]\nname = \"fixture-lock\"\nabsent = true\nobject_lock = true\n",
        "[[buckets]]\nname = \"fixture-lock\"\nobject_lock = \"true\"\n",
    ] {
        let peer = Peer::new(Vec::new());
        let mut target = peer.target();
        let error = target
            .prepare(CASE, Some(&toml(invalid)))
            .expect_err("contradictory or mistyped object_lock must be rejected");
        let requests = peer.finish();
        assert!(matches!(error, SutError::Environment(_)), "{invalid}: {error}");
        assert!(requests.is_empty(), "invalid setup contacted endpoint: {invalid}");
    }
}

/// Negative — a pre-existing bucket or failed Object Lock create is never owned or deleted.
#[test]
fn pre_existing_or_failed_object_lock_create_is_never_owned_or_deleted() {
    for (replies, expected_lines) in [
        (vec![response(200, "", "")], vec!["HEAD /fixture-lock HTTP/1.1"]),
        (
            vec![response(404, "", ""), response(409, "", "")],
            vec!["HEAD /fixture-lock HTTP/1.1", "PUT /fixture-lock HTTP/1.1"],
        ),
    ] {
        let peer = Peer::new(replies);
        let mut target = peer.target();
        let error = target
            .prepare(CASE, Some(&toml(BUCKET)))
            .expect_err("existing or failed create must abort");
        assert!(matches!(error, SutError::Environment(_) | SutError::Refused(_)), "{error}");
        let requests = peer.finish();
        assert_eq!(lines(&requests), expected_lines);
    }
}

/// Negative — any `?object-lock` readback that fails to strictly prove `Enabled` returns
/// `SutError::Refused` and rolls back the created bucket.
#[test]
fn unproved_object_lock_readback_refuses_and_rolls_back_the_bucket() {
    for bad_reply in [
        response(404, "", ""),
        response(500, "", ""),
        response(
            200,
            "",
            "<ObjectLockConfiguration><ObjectLockEnabled>Disabled</ObjectLockEnabled></ObjectLockConfiguration>",
        ),
        response(200, "", "<ObjectLockConfiguration></ObjectLockConfiguration>"),
        response(
            200,
            "",
            "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Extra>x</Extra></ObjectLockConfiguration>",
        ),
        response(200, "", "<ObjectLockConfiguration><ObjectLockEnabled>Enabled"),
    ] {
        let peer = Peer::new(vec![response(404, "", ""), response(200, "", ""), bad_reply, response(204, "", "")]);
        let mut target = peer.target();
        let error = target
            .prepare(CASE, Some(&toml(BUCKET)))
            .expect_err("unproved object-lock readback must fail");
        let requests = peer.finish();
        assert!(matches!(error, SutError::Refused(_)), "expected Refused, got {error:?}");
        assert_eq!(
            lines(&requests),
            [
                "HEAD /fixture-lock HTTP/1.1",
                "PUT /fixture-lock HTTP/1.1",
                "GET /fixture-lock?object-lock HTTP/1.1",
                "DELETE /fixture-lock HTTP/1.1",
            ]
        );
    }
}

/// Negative — if `?object-lock` proves `Enabled` but `?versioning` does not prove `Enabled`,
/// preparation returns `SutError::Refused` and rolls back the created bucket.
#[test]
fn unproved_versioning_readback_after_object_lock_refuses_and_rolls_back_the_bucket() {
    for bad_versioning in [
        response(500, "", ""),
        response(200, "", "<VersioningConfiguration/>"),
        response(200, "", "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>"),
    ] {
        let peer = Peer::new(vec![
            response(404, "", ""),
            response(200, "", ""),
            response(200, "", LOCK_ENABLED),
            bad_versioning,
            response(204, "", ""),
        ]);
        let mut target = peer.target();
        let error = target
            .prepare(CASE, Some(&toml(BUCKET)))
            .expect_err("unproved versioning readback must fail");
        let requests = peer.finish();
        assert!(matches!(error, SutError::Refused(_)), "expected Refused, got {error:?}");
        assert_eq!(
            lines(&requests),
            [
                "HEAD /fixture-lock HTTP/1.1",
                "PUT /fixture-lock HTTP/1.1",
                "GET /fixture-lock?object-lock HTTP/1.1",
                "GET /fixture-lock?versioning HTTP/1.1",
                "DELETE /fixture-lock HTTP/1.1",
            ]
        );
    }
}

/// Negative — a setup PUT inside an Object Lock bucket whose response omits `x-amz-version-id`
/// (or returns `null`) retains unresolved ownership, blocks bucket deletion, and blocks the next case.
#[test]
fn setup_object_missing_version_id_in_object_lock_bucket_blocks_bucket_delete_and_next_case() {
    for bad_put in [response(200, "", ""), version(200, "null")] {
        let mut replies = created_lock_bucket();
        replies.extend([response(404, "", ""), bad_put]);
        let peer = Peer::new(replies);
        let mut target = peer.target();
        let setup = toml(&format!(
            "{BUCKET}[[objects]]\nbucket = \"fixture-lock\"\nkey = \"doc.txt\"\nbody = {{ utf8 = \"payload\" }}\n"
        ));
        let prepared = target.prepare(CASE, Some(&setup));
        let next = target.prepare("s-next", None);
        let requests = peer.finish();
        assert!(matches!(prepared, Err(SutError::Environment(_))), "{prepared:?}");
        assert!(matches!(next, Err(SutError::Environment(_))), "{next:?}");
        assert!(
            !requests.iter().any(|req| req.line.starts_with("DELETE ")),
            "unresolved setup object must block bucket deletion: {requests:?}"
        );
    }
}

/// Negative — without `--allow-external-writes`, authored writes against an Object Lock bucket
/// (even when `versioning = "enabled"` is also declared) are refused at preflight before any traffic,
/// and also refused at exchange time as defense in depth.
#[test]
fn authored_writes_on_object_lock_bucket_are_refused_without_allow_external_writes() {
    let locked_and_versioned = "[[buckets]]\nname = \"fixture-lock\"\nversioning = \"enabled\"\nobject_lock = true\n";
    for bucket_toml in [BUCKET, locked_and_versioned] {
        let setup = toml(bucket_toml);
        for req_toml in [
            "method = \"PUT\"\ntarget = \"/fixture-lock/doc.txt\"\nbody = { utf8 = \"x\" }\n",
            "method = \"PUT\"\ntarget = \"/fixture-lock/doc.txt?retention\"\nbody = { utf8 = '<Retention/>' }\n",
            "method = \"DELETE\"\ntarget = \"/fixture-lock/doc.txt\"\n",
        ] {
            let peer = Peer::new(Vec::new());
            let target = peer.target();
            let req = toml(req_toml);
            let error = target
                .validate_requests(CASE, Some(&setup), &[&req])
                .expect_err("write to Object Lock bucket must require --allow-external-writes");
            let requests = peer.finish();
            assert!(
                matches!(error, SutError::Environment(_)) && error.to_string().contains("--allow-external-writes"),
                "{error}"
            );
            assert!(requests.is_empty(), "preflight refusal must send nothing");
        }
    }

    // Defense in depth: even if a caller skips validate_requests and calls exchange directly on a
    // prepared versioned+object_lock bucket without --allow-external-writes, the write is refused.
    let mut replies = created_lock_bucket();
    replies.push(response(204, "", ""));
    let peer = Peer::new(replies);
    let mut target = peer.target();
    target
        .prepare(CASE, Some(&toml(locked_and_versioned)))
        .expect("prepare versioned+object_lock bucket");
    let refused = target.exchange(&plan("method = \"PUT\"\ntarget = \"/fixture-lock/doc.txt\"\nbody = { utf8 = \"x\" }\n"));
    target.finish(CASE).expect("clean up untouched bucket");
    let requests = peer.finish();
    assert!(matches!(refused, Err(SutError::Environment(_))), "{refused:?}");
    assert_eq!(
        lines(&requests),
        [
            "HEAD /fixture-lock HTTP/1.1",
            "PUT /fixture-lock HTTP/1.1",
            "GET /fixture-lock?object-lock HTTP/1.1",
            "GET /fixture-lock?versioning HTTP/1.1",
            "DELETE /fixture-lock HTTP/1.1",
        ]
    );
}

/// Negative — even with `--allow-external-writes`, any authored write that applies irremovable
/// COMPLIANCE object retention (retention XML, object write header, POST form field, or bucket
/// COMPLIANCE DefaultRetention followed by an object write) is refused at preflight before traffic.
#[test]
fn compliance_object_retention_writes_are_refused_at_preflight_before_contact() {
    let cases: &[(&str, &[&str])] = &[
        (
            BUCKET,
            &["method = \"PUT\"\ntarget = \"/fixture-lock/doc.txt?retention\"\n\
               body = { utf8 = '<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2030-06-01T12:30:45.000Z</RetainUntilDate></Retention>' }\n"],
        ),
        (
            BUCKET,
            &["method = \"PUT\"\ntarget = \"/fixture-lock/doc.txt\"\n\
               headers = { \"x-amz-object-lock-mode\" = \"COMPLIANCE\", \"x-amz-object-lock-retain-until-date\" = \"2030-01-01T00:00:00Z\" }\n\
               body = { utf8 = \"payload\" }\n"],
        ),
        (
            BUCKET,
            &["method = \"POST\"\ntarget = \"/fixture-lock\"\n\
               headers = { \"content-type\" = \"multipart/form-data; boundary=b\" }\n\
               body = { utf8 = \"--b\\r\\nContent-Disposition: form-data; name=\\\"x-amz-object-lock-mode\\\"\\r\\n\\r\\nCOMPLIANCE\\r\\n--b--\\r\\n\" }\n"],
        ),
        (
            "[[buckets]]\nname = \"fixture-lock\"\n",
            &[
                "method = \"PUT\"\ntarget = \"/fixture-lock?object-lock\"\n\
                 body = { utf8 = '<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>\
                 <Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>' }\n",
                "method = \"PUT\"\ntarget = \"/fixture-lock/doc.txt\"\nbody = { utf8 = \"payload\" }\n",
            ],
        ),
    ];
    for (setup_toml, req_tomls) in cases {
        let peer = Peer::new(Vec::new());
        let target = peer.writable_target();
        let setup = toml(setup_toml);
        let parsed: Vec<_> = req_tomls.iter().map(|src| toml(src)).collect();
        let refs: Vec<_> = parsed.iter().collect();
        let error = target
            .validate_requests(CASE, Some(&setup), &refs)
            .expect_err("irremovable COMPLIANCE object retention must be refused at preflight");
        let requests = peer.finish();
        assert!(
            matches!(error, SutError::Environment(_)) && error.to_string().contains("COMPLIANCE"),
            "{error}"
        );
        assert!(requests.is_empty(), "COMPLIANCE preflight refusal must send zero traffic");
    }
}

/// Negative — an Object Lock bucket counts as a versioned object target so a stale keep-alive
/// control socket never retries a setup `PUT` and creates an orphaned duplicate version.
#[test]
fn stale_control_socket_does_not_retry_put_to_object_lock_object_target() {
    let mut replies = created_lock_bucket();
    replies.push(response(204, "", ""));
    let peer = Peer::new(replies);
    let mut target = peer.target();
    target.prepare(CASE, Some(&toml(BUCKET))).expect("prepare lock bucket");
    assert!(
        target.external_fixtures.is_versioned_object_target("/fixture-lock/doc.txt"),
        "Object Lock bucket object targets must be treated as versioned to prevent stale PUT retry"
    );
    target.finish(CASE).expect("clean up lock bucket");
    let _ = peer.finish();
}

/// Negative — when lifting a legal hold fails, or when DELETE after lifting a legal hold still
/// answers 403 (such as unexpected COMPLIANCE retention), cleanup fails closed without deleting
/// the bucket and blocks the next case.
#[test]
fn failed_legal_hold_clear_or_still_forbidden_delete_retains_bucket_ownership() {
    let listed = "<ListVersionsResult><Version><Key>doc.txt</Key><VersionId>v-stuck</VersionId></Version></ListVersionsResult>";
    // Case A: PUT ?legal-hold answers 500 -> must NOT retry DELETE or send DELETE /fixture-lock.
    {
        let mut replies = created_lock_bucket();
        replies.extend([
            response(200, "", EMPTY_UPLOADS),
            response(200, "", listed),
            response(403, "", ""),
            response(500, "", ""),
        ]);
        let peer = Peer::new(replies);
        let mut target = peer.writable_target();
        target.prepare(CASE, Some(&toml(BUCKET))).expect("prepare lock bucket");
        let finished = target.finish(CASE);
        let next = target.prepare("s-next", None);
        let requests = peer.finish();
        assert!(matches!(finished, Err(SutError::Environment(_))), "{finished:?}");
        assert!(matches!(next, Err(SutError::Environment(_))), "{next:?}");
        assert_eq!(
            lines(&requests)[4..],
            [
                "GET /fixture-lock?uploads HTTP/1.1",
                "GET /fixture-lock?versions HTTP/1.1",
                "DELETE /fixture-lock/doc.txt?versionId=v-stuck HTTP/1.1",
                "PUT /fixture-lock/doc.txt?legal-hold&versionId=v-stuck HTTP/1.1",
            ]
        );
    }

    // Case B: PUT ?legal-hold answers 200, retry DELETE still answers 403 -> must NOT delete bucket.
    {
        let mut replies = created_lock_bucket();
        replies.extend([
            response(200, "", EMPTY_UPLOADS),
            response(200, "", listed),
            response(403, "", ""),
            response(200, "", ""),
            response(403, "", ""),
        ]);
        let peer = Peer::new(replies);
        let mut target = peer.writable_target();
        target.prepare(CASE, Some(&toml(BUCKET))).expect("prepare lock bucket");
        let finished = target.finish(CASE);
        let next = target.prepare("s-next", None);
        let requests = peer.finish();
        assert!(matches!(finished, Err(SutError::Environment(_))), "{finished:?}");
        assert!(matches!(next, Err(SutError::Environment(_))), "{next:?}");
        assert_eq!(
            lines(&requests)[4..],
            [
                "GET /fixture-lock?uploads HTTP/1.1",
                "GET /fixture-lock?versions HTTP/1.1",
                "DELETE /fixture-lock/doc.txt?versionId=v-stuck HTTP/1.1",
                "PUT /fixture-lock/doc.txt?legal-hold&versionId=v-stuck HTTP/1.1",
                "DELETE /fixture-lock/doc.txt?versionId=v-stuck HTTP/1.1",
            ]
        );
    }
}

/// Negative — when a listed DeleteMarker answers 403 during emptying of an Object Lock bucket,
/// cleanup never attempts `PUT ?legal-hold` on the delete marker and retains bucket ownership.
#[test]
fn delete_marker_403_does_not_attempt_legal_hold_clear_and_retains_bucket_ownership() {
    let listed =
        "<ListVersionsResult><DeleteMarker><Key>gone.txt</Key><VersionId>v-dm</VersionId></DeleteMarker></ListVersionsResult>";
    let mut replies = created_lock_bucket();
    replies.extend([
        response(200, "", EMPTY_UPLOADS),
        response(200, "", listed),
        response(403, "", ""),
    ]);
    let peer = Peer::new(replies);
    let mut target = peer.writable_target();
    target.prepare(CASE, Some(&toml(BUCKET))).expect("prepare lock bucket");
    let finished = target.finish(CASE);
    let next = target.prepare("s-next", None);
    let requests = peer.finish();
    assert!(matches!(finished, Err(SutError::Environment(_))), "{finished:?}");
    assert!(matches!(next, Err(SutError::Environment(_))), "{next:?}");
    assert_eq!(
        lines(&requests)[4..],
        [
            "GET /fixture-lock?uploads HTTP/1.1",
            "GET /fixture-lock?versions HTTP/1.1",
            "DELETE /fixture-lock/gone.txt?versionId=v-dm HTTP/1.1",
        ]
    );
}
