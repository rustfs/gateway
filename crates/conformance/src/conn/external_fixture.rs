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

//! Opt-in owned bucket and object fixtures for an external conformance endpoint.
//!
//! Responsible for: validating the narrow remote-setup subset, refusing authored mutations while
//! ownership is active, and holding ownership state for successful unversioned creates.
//! NOT responsible for: versioned, locked, multipart, or fault fixtures; endpoint resolution; authored
//! exchange pacing; or response judgement. Upstream: `external`; downstream: the endpoint selected
//! by `crate::cli`.

use std::collections::BTreeSet;

use crate::inprocess::Wire;
use crate::sut::SutError;
use crate::value::Value;

mod clock;
mod lifecycle;
mod object;
#[cfg(test)]
mod object_tests;
mod region;
#[cfg(test)]
mod runner_tests;

#[derive(Debug)]
pub(super) struct ExternalFixtures {
    enabled: bool,
    active_case: Option<String>,
    owned_buckets: Vec<OwnedBucket>,
    owned_objects: Vec<object::OwnedObject>,
}

#[derive(Debug)]
struct BucketPlan {
    name: String,
    absent: bool,
    region: region::FixtureRegion,
}

#[derive(Debug)]
struct FixturePlan {
    buckets: Vec<BucketPlan>,
    objects: Vec<object::ObjectPlan>,
}

#[derive(Debug)]
struct OwnedBucket {
    name: String,
    region: region::FixtureRegion,
}

impl ExternalFixtures {
    pub(super) const fn disabled() -> Self {
        Self::new(false)
    }

    pub(super) const fn new(enabled: bool) -> Self {
        Self {
            enabled,
            active_case: None,
            owned_buckets: Vec::new(),
            owned_objects: Vec::new(),
        }
    }

    fn plan(&self, setup: &Value, decoder: &crate::inprocess::InProcess) -> Result<FixturePlan, SutError> {
        if !self.enabled {
            return Err(SutError::Environment(
                "external fixture setup is disabled; explicitly opt in with `--allow-external-fixtures` only for an isolated test target"
                    .to_owned(),
            ));
        }
        if self.active_case.is_some() || !self.owned_buckets.is_empty() || !self.owned_objects.is_empty() {
            return Err(SutError::Environment(
                "external fixture setup cannot start because cleanup from the previous case is incomplete".to_owned(),
            ));
        }
        only_keys(setup, &["cleanup", "buckets", "objects"], "setup")?;
        if setup
            .read("setup.cleanup")
            .and_then(Value::as_str)
            .is_some_and(|cleanup| cleanup != "auto")
        {
            return Err(SutError::Environment(
                "external fixture setup rejects an explicit cleanup mode other than `auto`; remote state may never outlive its case"
                    .to_owned(),
            ));
        }
        let Some(buckets) = setup.read("setup.buckets").and_then(Value::as_array) else {
            return Err(SutError::Environment(
                "external fixture setup requires an array of owned `setup.buckets` declarations".to_owned(),
            ));
        };
        let mut seen = BTreeSet::new();
        let mut plan = Vec::with_capacity(buckets.len());
        for bucket in buckets {
            only_keys(bucket, &["name", "absent", "region", "versioning", "object_lock"], "setup.buckets[]")?;
            let name = bucket
                .read("setup.buckets[].name")
                .and_then(Value::as_str)
                .ok_or_else(|| SutError::Environment("an external fixture bucket has no name".to_owned()))?;
            validate_bucket_name(name)?;
            if !seen.insert(name.to_owned()) {
                return Err(SutError::Environment(format!(
                    "external fixture bucket `{name}` is declared more than once"
                )));
            }
            if !matches!(bucket.read("setup.buckets[].versioning").and_then(Value::as_str), None | Some("disabled"))
                || bucket.read("setup.buckets[].object_lock").and_then(Value::as_bool) == Some(true)
            {
                return Err(SutError::Environment(format!(
                    "external bucket state for `{name}` is not supported; object fixtures require an owned, non-absent, unversioned and unlocked bucket"
                )));
            }
            plan.push(BucketPlan {
                name: name.to_owned(),
                absent: bucket
                    .read("setup.buckets[].absent")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                region: region::FixtureRegion::parse(bucket.read("setup.buckets[].region").and_then(Value::as_str))?,
            });
        }
        let objects = object::plans(setup, &plan, decoder)?;
        Ok(FixturePlan { buckets: plan, objects })
    }

    pub(super) fn ensure_read_only(&self, case_id: &str, wire: &Wire) -> Result<(), SutError> {
        let Some(active_case) = self.active_case.as_deref() else {
            return Ok(());
        };
        if active_case != case_id {
            return Err(SutError::Environment(format!(
                "external fixtures owned by `{active_case}` are still active; refusing to run `{case_id}`"
            )));
        }
        if matches!(wire.method.as_str(), "GET" | "HEAD" | "OPTIONS") && wire.raw_head.is_none() {
            return Ok(());
        }
        let method = if wire.raw_head.is_some() {
            "an unclassified raw request"
        } else {
            wire.method.as_str()
        };
        Err(SutError::Environment(format!(
            "external fixtures are active for `{case_id}`; only read-only GET, HEAD, and OPTIONS case exchanges are allowed, not {method}"
        )))
    }
}

fn only_keys(value: &Value, allowed: &[&str], context: &str) -> Result<(), SutError> {
    let Value::Table(entries) = value else {
        return Err(SutError::Environment(format!("external fixture `{context}` is not a table")));
    };
    if let Some(key) = entries
        .iter()
        .map(|(key, _)| key)
        .find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(SutError::Environment(format!(
            "`{context}.{key}` is not supported by external owned bucket/object fixtures"
        )));
    }
    Ok(())
}

fn validate_bucket_name(name: &str) -> Result<(), SutError> {
    let valid = (3..=63).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-'))
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && name
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if valid {
        return Ok(());
    }
    Err(SutError::Environment(format!(
        "external fixture bucket name `{name}` is not safe for an S3 path-style control request"
    )))
}

#[cfg(test)]
mod tests {
    use super::super::Conn;
    use crate::sut::{ExchangePlan, Profile, Sut, Transport};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn request_block(source: &str) -> crate::value::Value {
        crate::toml::parse(source).expect("valid request TOML")
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound request read");
        let mut bytes = Vec::new();
        loop {
            let mut block = [0_u8; 1024];
            let read = stream.read(&mut block).expect("read complete request");
            assert_ne!(read, 0, "request ended before its head completed");
            bytes.extend_from_slice(&block[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                return bytes;
            }
        }
    }

    fn fixture_server(responses: Vec<&'static [u8]>) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture endpoint");
        listener.set_nonblocking(true).expect("bound fixture accepts");
        let address = listener.local_addr().expect("fixture endpoint address");
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
                        Err(error) => panic!("accept fixture request: {error}"),
                    }
                };
                stream.set_nonblocking(false).expect("blocking fixture exchange");
                requests.push(read_request(&mut stream));
                stream.write_all(response).expect("write fixture response");
            }
            requests
        });
        (format!("http://{address}"), server)
    }

    fn line(request: &[u8]) -> &str {
        std::str::from_utf8(request)
            .expect("request is UTF-8")
            .lines()
            .next()
            .expect("request line")
    }

    fn header<'a>(request: &'a [u8], wanted: &str) -> &'a str {
        std::str::from_utf8(request)
            .expect("request is UTF-8")
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case(wanted).then_some(value.trim())
            })
            .expect("header is present")
    }

    fn current_unix_second() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("current time follows the Unix epoch")
                .as_secs(),
        )
        .expect("current time fits i64")
    }

    fn parse_amz_second(stamp: &str) -> i64 {
        assert_eq!(stamp.len(), 16, "x-amz-date has the basic ISO shape");
        let rfc3339 = format!(
            "{}-{}-{}T{}:{}:{}Z",
            &stamp[0..4],
            &stamp[4..6],
            &stamp[6..8],
            &stamp[9..11],
            &stamp[11..13],
            &stamp[13..15]
        );
        crate::time::parse_rfc3339(&rfc3339)
            .expect("captured x-amz-date is a valid UTC instant")
            .unix_seconds
    }

    fn assert_no_connection(listener: &TcpListener) {
        listener.set_nonblocking(true).expect("make absence observable");
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("unexpected accept error: {error}"),
            Ok(_) => panic!("the endpoint was contacted before setup was accepted"),
        }
    }

    #[test]
    fn opted_in_empty_bucket_wraps_one_read_only_exchange_in_signed_create_and_delete() {
        let before = current_unix_second();
        let responses = vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" as &[u8],
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        ];
        let (url, server) = fixture_server(responses);
        let mut target =
            Conn::external_with_fixtures(std::path::PathBuf::from("."), &url, None).expect("opted-in external target");
        let setup = request_block("cleanup = \"auto\"\n[[buckets]]\nname = \"fixture-one\"\nregion = \"us-west-2\"\n");
        target
            .prepare("s-external-fixture-0001", Some(&setup))
            .expect("create fixture");
        let plan = ExchangePlan {
            case_id: "s-external-fixture-0001",
            index: 0,
            request: request_block("method = \"GET\"\ntarget = \"/fixture-one\"\n"),
            clock: None,
            connection: None,
            timeout_ms: Some(2_000),
            transport: Transport::Conn,
            profile: Profile::Aws,
        };
        assert_eq!(target.exchange(&plan).expect("read-only exchange").status, Some(204));
        target.finish("s-external-fixture-0001").expect("delete fixture");

        let requests = server.join().expect("fixture server exits");
        let after = current_unix_second();
        assert_eq!(line(&requests[0]), "HEAD /fixture-one HTTP/1.1");
        assert_eq!(line(&requests[1]), "PUT /fixture-one HTTP/1.1");
        assert_eq!(line(&requests[2]), "GET /fixture-one HTTP/1.1");
        assert_eq!(line(&requests[3]), "DELETE /fixture-one HTTP/1.1");
        for request in [&requests[0], &requests[1], &requests[3]] {
            let text = std::str::from_utf8(request).expect("control request is UTF-8");
            assert!(
                text.lines()
                    .any(|header| header.to_ascii_lowercase().starts_with("authorization: aws4-hmac-sha256 "))
            );
            assert!(
                text.lines()
                    .any(|header| header.to_ascii_lowercase().starts_with("x-amz-date: "))
            );
            assert!(header(request, "authorization").contains("Credential=AKIAIOSFODNN7EXAMPLE/"));
            assert!(header(request, "authorization").contains("/us-west-2/s3/aws4_request"));
            let signed_at = parse_amz_second(header(request, "x-amz-date"));
            assert!(
                (before..=after).contains(&signed_at),
                "control request was not signed at the current time"
            );
        }
    }

    #[test]
    fn setup_without_the_explicit_fixture_opt_in_is_rejected_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint probe");
        let address = listener.local_addr().expect("endpoint probe address");
        let mut target =
            Conn::external(std::path::PathBuf::from("."), &format!("http://{address}")).expect("ordinary external target");
        let setup = request_block("cleanup = \"auto\"\n[[buckets]]\nname = \"fixture-one\"\n");

        let error = target
            .prepare("s-external-fixture-n001", Some(&setup))
            .expect_err("remote setup requires opt-in");

        assert!(error.to_string().contains("opt in"));
        assert_no_connection(&listener);
    }

    #[test]
    fn explicit_non_auto_cleanup_is_rejected_before_connecting() {
        for cleanup in ["none", "manual"] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint probe");
            let address = listener.local_addr().expect("endpoint probe address");
            let mut target = Conn::external_with_fixtures(std::path::PathBuf::from("."), &format!("http://{address}"), None)
                .expect("opted-in target");
            let source = format!("cleanup = \"{cleanup}\"\n[[buckets]]\nname = \"fixture-one\"\n");
            let setup = request_block(&source);

            let error = target
                .prepare("s-external-fixture-n002", Some(&setup))
                .expect_err("cleanup must be automatic");

            assert!(error.to_string().contains("cleanup"));
            assert_no_connection(&listener);
        }
    }

    #[test]
    fn every_setup_shape_outside_owned_bucket_and_object_state_is_rejected_before_mutation() {
        for unsupported in [
            "unknown = true\n",
            "multipart_uploads = []\n",
            "fault = { operation = \"PutObject\", at = \"after_commit\", code = \"InternalError\" }\n",
            "[[buckets]]\nname = \"fixture-one\"\nversioning = \"enabled\"\n",
            "[[buckets]]\nname = \"fixture-one\"\nobject_lock = true\n",
            "[[buckets]]\nname = \"fixture-one\"\nregion = \"../us-west-2\"\n",
            "[[buckets]]\nname = \"../escape\"\n",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint probe");
            let address = listener.local_addr().expect("endpoint probe address");
            let mut target = Conn::external_with_fixtures(std::path::PathBuf::from("."), &format!("http://{address}"), None)
                .expect("opted-in target");
            let setup = request_block(&format!("cleanup = \"auto\"\n{unsupported}"));

            let error = target
                .prepare("s-external-fixture-n003", Some(&setup))
                .expect_err("unsupported setup is not approximated");

            assert!(
                error.to_string().contains("not supported") || error.to_string().contains("not safe"),
                "{unsupported}: {error}"
            );
            assert_no_connection(&listener);
        }
    }

    #[test]
    fn an_invalid_later_bucket_is_rejected_before_an_earlier_bucket_is_created() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint probe");
        let address = listener.local_addr().expect("endpoint probe address");
        let mut target = Conn::external_with_fixtures(std::path::PathBuf::from("."), &format!("http://{address}"), None)
            .expect("opted-in target");
        let setup = request_block(
            "cleanup = \"auto\"\n[[buckets]]\nname = \"fixture-one\"\n[[buckets]]\nname = \"fixture-two\"\nversioning = \"enabled\"\n",
        );

        target
            .prepare("s-external-fixture-n004", Some(&setup))
            .expect_err("all setup is validated before mutation");

        assert_no_connection(&listener);
    }

    #[test]
    fn a_pre_existing_or_unprovably_absent_bucket_is_never_owned_or_deleted() {
        for (response, message) in [
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" as &[u8],
                "already exists",
            ),
            (
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" as &[u8],
                "prove bucket",
            ),
        ] {
            let (url, server) = fixture_server(vec![response]);
            let mut target = Conn::external_with_fixtures(std::path::PathBuf::from("."), &url, None).expect("opted-in target");
            let setup = request_block("cleanup = \"auto\"\n[[buckets]]\nname = \"fixture-owned-elsewhere\"\n");

            let error = target
                .prepare("s-external-fixture-n005", Some(&setup))
                .expect_err("absence must be proved before ownership");

            assert!(error.to_string().contains(message), "{error}");
            let requests = server.join().expect("fixture server exits");
            assert_eq!(requests.len(), 1);
            assert_eq!(line(&requests[0]), "HEAD /fixture-owned-elsewhere HTTP/1.1");
        }
    }

    #[test]
    fn a_failed_create_is_not_owned_while_earlier_successes_are_rolled_back() {
        let (url, server) = fixture_server(vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        ]);
        let mut target = Conn::external_with_fixtures(std::path::PathBuf::from("."), &url, None).expect("opted-in target");
        let setup =
            request_block("cleanup = \"auto\"\n[[buckets]]\nname = \"fixture-one\"\n[[buckets]]\nname = \"fixture-two\"\n");

        let error = target
            .prepare("s-external-fixture-n006", Some(&setup))
            .expect_err("failed create aborts setup");

        assert!(error.to_string().contains("status 500"));
        let requests = server.join().expect("fixture server exits");
        let lines: Vec<&str> = requests.iter().map(|request| line(request)).collect();
        assert_eq!(
            lines,
            vec![
                "HEAD /fixture-one HTTP/1.1",
                "PUT /fixture-one HTTP/1.1",
                "HEAD /fixture-two HTTP/1.1",
                "PUT /fixture-two HTTP/1.1",
                "DELETE /fixture-one HTTP/1.1",
            ]
        );
    }

    #[test]
    fn an_absent_bucket_is_checked_but_never_created_or_deleted() {
        let (url, server) = fixture_server(vec![b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"]);
        let mut target = Conn::external_with_fixtures(std::path::PathBuf::from("."), &url, None).expect("opted-in target");
        let setup = request_block("cleanup = \"auto\"\n[[buckets]]\nname = \"fixture-absent\"\nabsent = true\n");

        target
            .prepare("s-external-fixture-0002", Some(&setup))
            .expect("absence confirmed");
        target.finish("s-external-fixture-0002").expect("nothing to delete");

        let requests = server.join().expect("fixture server exits");
        assert_eq!(requests.len(), 1);
        assert_eq!(line(&requests[0]), "HEAD /fixture-absent HTTP/1.1");
    }

    #[test]
    fn a_mutating_case_exchange_is_refused_before_bytes_while_a_fixture_is_active() {
        let (url, server) = fixture_server(vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        ]);
        let mut target = Conn::external_with_fixtures(std::path::PathBuf::from("."), &url, None).expect("opted-in target");
        let setup = request_block("cleanup = \"auto\"\n[[buckets]]\nname = \"fixture-one\"\n");
        target
            .prepare("s-external-fixture-n007", Some(&setup))
            .expect("create fixture");
        let plan = ExchangePlan {
            case_id: "s-external-fixture-n007",
            index: 0,
            request: request_block("method = \"PUT\"\ntarget = \"/fixture-one/key\"\nbody = { utf8 = \"must-not-send\" }\n"),
            clock: None,
            connection: None,
            timeout_ms: Some(2_000),
            transport: Transport::Conn,
            profile: Profile::Aws,
        };

        let error = target.exchange(&plan).expect_err("authored mutation is blocked");
        assert!(error.to_string().contains("read-only"));
        target.finish("s-external-fixture-n007").expect("delete fixture");

        let requests = server.join().expect("fixture server exits");
        let lines: Vec<&str> = requests.iter().map(|request| line(request)).collect();
        assert_eq!(
            lines,
            vec![
                "HEAD /fixture-one HTTP/1.1",
                "PUT /fixture-one HTTP/1.1",
                "DELETE /fixture-one HTTP/1.1"
            ]
        );
    }

    #[test]
    fn owned_buckets_are_deleted_in_reverse_creation_order() {
        let (url, server) = fixture_server(vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        ]);
        let mut target = Conn::external_with_fixtures(std::path::PathBuf::from("."), &url, None).expect("opted-in target");
        let setup =
            request_block("cleanup = \"auto\"\n[[buckets]]\nname = \"fixture-one\"\n[[buckets]]\nname = \"fixture-two\"\n");

        target
            .prepare("s-external-fixture-0003", Some(&setup))
            .expect("create fixtures");
        target.finish("s-external-fixture-0003").expect("delete fixtures");

        let requests = server.join().expect("fixture server exits");
        assert_eq!(line(&requests[4]), "DELETE /fixture-two HTTP/1.1");
        assert_eq!(line(&requests[5]), "DELETE /fixture-one HTTP/1.1");
    }

    #[test]
    fn a_delete_failure_is_returned_instead_of_being_swallowed() {
        let (url, server) = fixture_server(vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        let mut target = Conn::external_with_fixtures(std::path::PathBuf::from("."), &url, None).expect("opted-in target");
        let setup = request_block("cleanup = \"auto\"\n[[buckets]]\nname = \"fixture-one\"\n");
        target
            .prepare("s-external-fixture-n008", Some(&setup))
            .expect("create fixture");

        let error = target
            .finish("s-external-fixture-n008")
            .expect_err("delete failure is surfaced");

        assert!(error.to_string().contains("DELETE"));
        assert!(error.to_string().contains("status 500"));
        let _ = server.join().expect("fixture server exits");
    }

    #[test]
    fn fixture_opt_in_is_valid_only_with_an_external_endpoint() {
        let enabled = crate::cli::Options::parse(&[
            "run".to_owned(),
            "--endpoint".to_owned(),
            "http://127.0.0.1:9000".to_owned(),
            "--allow-external-fixtures".to_owned(),
        ])
        .expect("valid opted-in command")
        .expect("not help");
        let error = crate::cli::Options::parse(&["run".to_owned(), "--allow-external-fixtures".to_owned()])
            .expect_err("fixture opt-in without endpoint is meaningless");

        assert!(enabled.external_fixtures);
        assert!(error.contains("--endpoint"));
    }

    #[test]
    fn parsed_fixture_opt_in_reaches_the_external_target_constructor() {
        let (url, server) = fixture_server(vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        ]);
        let options = crate::cli::Options::parse(&[
            "run".to_owned(),
            "--endpoint".to_owned(),
            url,
            "--allow-external-fixtures".to_owned(),
        ])
        .expect("valid opted-in command")
        .expect("not help");
        let mut target =
            crate::cli::external_target(&options, std::path::PathBuf::from(".")).expect("CLI-selected external target");
        let setup = request_block("cleanup = \"auto\"\n[[buckets]]\nname = \"fixture-cli\"\n");

        target
            .prepare("s-external-fixture-0004", Some(&setup))
            .expect("create fixture");
        target.finish("s-external-fixture-0004").expect("delete fixture");

        let requests = server.join().expect("fixture server exits");
        assert_eq!(line(&requests[1]), "PUT /fixture-cli HTTP/1.1");
        assert_eq!(line(&requests[2]), "DELETE /fixture-cli HTTP/1.1");
    }
}
