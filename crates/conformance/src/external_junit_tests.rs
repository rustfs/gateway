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

//! External CLI-to-JUnit composition tests using an independent XML parser.
//!
//! Responsible for: observed HTTP verdicts and report write failures through the public CLI.
//! NOT responsible for: rendering JUnit or implementing S3 behavior. Upstream: `cli::main`;
//! downstream: a bounded loopback endpoint and Python's standard-library XML parser.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::cli::{self, exit};

struct Corpus(PathBuf);

impl Drop for Corpus {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn corpus() -> Corpus {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "gateway-external-junit-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("cases/junit")).expect("create isolated corpus");
    let repository = crate::corpus::Corpus::discover_root().expect("repository corpus");
    fs::copy(repository.join("case.schema.json"), root.join("case.schema.json")).expect("copy schema");
    fs::write(
        root.join("cases/junit/c-junit-0001.toml"),
        r#"[case]
id = "c-junit-0001"
schema_version = 1
title = "External JUnit composition"
rationale = "An independently parsed report must preserve the verdict observed over HTTP."
polarity = "negative"
operation = "HeadBucket"
tags = ["xml"]
timeout_ms = 10000
quirks = []

[[case.evidence]]
url = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html"
summary = "HeadBucket reports whether the requested bucket can be accessed."
kind = "aws-doc"

[request]
method = "HEAD"
target = "/junit-bucket"

[expect]
kind = "response"
status = 403
"#,
    )
    .expect("write case");
    Corpus(root)
}

fn run(corpus: &Corpus, response_status: u16, report: &std::path::Path) -> ExitCode {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint");
    listener.set_nonblocking(true).expect("bound accept wait");
    let address = listener.local_addr().expect("endpoint address");
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        // Two exchanges: the identity probe `run --endpoint` sends first (an unsigned `HEAD /`),
        // then the one case request, which is the only one `response_status` answers.
        let probe_response =
            "HTTP/1.1 403 Forbidden\r\nServer: RustFS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
        let case_response = format!("HTTP/1.1 {response_status} Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        for (expected_line, response) in [("HEAD / HTTP/1.1\r\n", probe_response), ("", case_response)] {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept external CLI request: {error}"),
                }
            };
            // The listener is non-blocking so the accept loop can watch its own deadline, and on
            // macOS an accepted socket inherits that flag; a non-blocking read answers `WouldBlock`
            // instead of waiting for the request head, and the read timeout below never applies.
            // Linux hands back a blocking socket, which is why this only flaked on one platform.
            stream.set_nonblocking(false).expect("blocking exchange");
            stream.set_read_timeout(Some(Duration::from_secs(10))).expect("read deadline");
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .expect("write deadline");
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut block = [0; 1024];
                let read = stream.read(&mut block).expect("read request head");
                if read == 0 {
                    panic!("external request ended before the head terminator");
                }
                request.extend_from_slice(&block[..read]);
            }
            assert!(request.starts_with(expected_line.as_bytes()), "unexpected request order");
            stream.write_all(response.as_bytes()).expect("write response");
        }
    });
    let result = cli::main(&[
        "run".into(),
        "--root".into(),
        corpus.0.display().to_string(),
        "--endpoint".into(),
        format!("http://{address}"),
        "--profile".into(),
        "aws".into(),
        "--junit".into(),
        report.display().to_string(),
    ]);
    server.join().expect("external endpoint completed");
    result
}

fn assert_junit(path: &std::path::Path, failures: u8) {
    let output = Command::new("python3")
        .arg("-c")
        .arg(
            r#"
import sys
import xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
assert root.tag == 'testsuite', root.tag
assert root.attrib['tests'] == '1', root.attrib
assert root.attrib['failures'] == sys.argv[2], root.attrib
assert root.attrib['skipped'] == '0', root.attrib
cases = root.findall('testcase')
assert len(cases) == 1, len(cases)
assert cases[0].attrib['name'] == 'c-junit-0001', cases[0].attrib
assert len(cases[0].findall('failure')) == int(sys.argv[2])
assert cases[0].find('skipped') is None
assert cases[0].find('error') is None
"#,
        )
        .arg(path)
        .arg(failures.to_string())
        .output()
        .expect("run independent Python XML parser");
    assert!(
        output.status.success(),
        "independent JUnit checks failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn external_junit_records_an_executed_pass() {
    let corpus = corpus();
    let path = corpus.0.join("report.xml");
    assert_eq!(run(&corpus, 403, &path), ExitCode::SUCCESS);
    assert_junit(&path, 0);
}

#[test]
fn external_junit_records_an_observed_failure() {
    let corpus = corpus();
    let path = corpus.0.join("report.xml");
    assert_eq!(run(&corpus, 200, &path), ExitCode::from(exit::REGRESSION));
    assert_junit(&path, 1);
}

#[test]
fn external_junit_write_failure_is_an_environment_error_after_a_pass() {
    let corpus = corpus();
    assert_eq!(run(&corpus, 403, &corpus.0), ExitCode::from(exit::ENVIRONMENT));
}

#[test]
fn external_junit_write_failure_is_an_environment_error_after_a_regression() {
    let corpus = corpus();
    assert_eq!(run(&corpus, 200, &corpus.0), ExitCode::from(exit::ENVIRONMENT));
}
