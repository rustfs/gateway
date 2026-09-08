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

//! Full runner coverage for external empty-bucket fixtures.
//!
//! Responsible for: proving the CLI opt-in reaches fixture controls, an authored read-only
//! exchange, and cleanup in order. NOT responsible for: unit-level ownership and failure cases or
//! production S3 behavior. Upstream: `crate::cli`; downstream: a bounded loopback HTTP endpoint.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::cli::{self, exit};

const CREATE_BODY: &[u8] = b"<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>us-west-2</LocationConstraint></CreateBucketConfiguration>";

struct TestCorpus(PathBuf);

impl TestCorpus {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestCorpus {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_case(root: &Path, id: &str, polarity: &str, status: u16, setup: &str) {
    let case = format!(
        r#"[case]
id = "{id}"
schema_version = 1
title = "External fixture runner control"
rationale = "This isolated corpus proves opted-in empty-bucket state is bounded by one read-only case."
polarity = "{polarity}"
operation = "GetBucketLocation"
tags = ["xml", "region"]
timeout_ms = 2000
quirks = []

[[case.evidence]]
url = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html"
summary = "A non-default location constraint is carried in the create-bucket request body."
kind = "aws-doc"

{setup}[request]
method = "GET"
target = "/fixture-runner?location"

[expect]
kind = "response"
status = {status}
"#
    );
    fs::write(root.join("cases/external-fixture").join(format!("{id}.toml")), case).expect("write case");
}

fn isolated_corpus() -> TestCorpus {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "rustfs-gateway-external-fixture-corpus-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("cases/external-fixture")).expect("create cases directory");
    let repository = crate::corpus::Corpus::discover_root().expect("repository corpus");
    fs::copy(repository.join("case.schema.json"), root.join("case.schema.json")).expect("copy frozen schema");
    write_case(
        &root,
        "c-external-fixture-0001",
        "positive",
        204,
        "[[setup.buckets]]\nname = \"fixture-runner\"\nregion = \"us-west-2\"\n\n",
    );
    write_case(&root, "c-external-fixture-n001", "negative", 400, "");
    write_case(&root, "c-external-fixture-n002", "negative", 403, "");
    TestCorpus(root)
}

fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set fixture request deadline");
    let mut request = Vec::new();
    loop {
        let mut block = [0_u8; 1024];
        let read = stream.read(&mut block).expect("read fixture request");
        assert_ne!(read, 0, "fixture request ended before completion");
        request.extend_from_slice(&block[..read]);
        let Some(head_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
        else {
            continue;
        };
        let head = std::str::from_utf8(&request[..head_end]).expect("fixture request head is UTF-8");
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("numeric content length"))
            })
            .unwrap_or(0);
        if request.len() >= head_end + content_length {
            return request;
        }
    }
}

fn fixture_server() -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture endpoint");
    listener.set_nonblocking(true).expect("bound fixture accept wait");
    let address = listener.local_addr().expect("fixture endpoint address");
    let responses: [&[u8]; 4] = [
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
    ];
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return requests,
                    Err(error) => panic!("accept fixture request: {error}"),
                }
            };
            requests.push(read_request(&mut stream));
            stream.write_all(response).expect("write fixture response");
        }
        requests
    });
    (format!("http://{address}"), server)
}

fn request_line(request: &[u8]) -> &str {
    std::str::from_utf8(request)
        .expect("fixture request is UTF-8")
        .lines()
        .next()
        .expect("fixture request line")
}

#[test]
fn cli_runner_executes_default_auto_fixture_lifecycle_against_external_endpoint() {
    let corpus = isolated_corpus();
    let (url, server) = fixture_server();
    let args = [
        "run".to_owned(),
        "--root".to_owned(),
        corpus.path().display().to_string(),
        "--filter".to_owned(),
        "c-external-fixture-0001".to_owned(),
        "--endpoint".to_owned(),
        url,
        "--allow-external-fixtures".to_owned(),
    ];

    let code = cli::main(&args);
    let requests = server.join().expect("fixture server exits");

    assert_eq!(code, ExitCode::from(exit::SUCCESS));
    assert_eq!(
        requests.iter().map(|request| request_line(request)).collect::<Vec<_>>(),
        [
            "HEAD /fixture-runner HTTP/1.1",
            "PUT /fixture-runner HTTP/1.1",
            "GET /fixture-runner?location HTTP/1.1",
            "DELETE /fixture-runner HTTP/1.1",
        ]
    );
    assert!(requests[1].ends_with(CREATE_BODY));
    let create = std::str::from_utf8(&requests[1]).expect("create request is UTF-8");
    assert!(create.contains("/us-west-2/s3/aws4_request"));
}
