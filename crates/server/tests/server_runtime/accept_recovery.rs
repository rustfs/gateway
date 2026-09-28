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

//! Responsible for: proving the listener survives a failed accept and serves the connection it
//! could not take once the shortage clears, using a real exhausted descriptor table.
//! NOT responsible for: classifying every OS error (the library's unit tests do) or admission.
//! Upstream: the server runtime integration suite. Downstream: `Server`'s accept loop.

use std::fs::File;
use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{RunningServer, echo_server, plaintext_config};

const CHILD_MARKER: &str = "GATEWAY_ACCEPT_RECOVERY_CHILD";
/// `EMFILE` on Linux and on Apple platforms.
const EMFILE: i32 = 24;
const TEST_NAME: &str = "server_runtime::accept_recovery::a_full_descriptor_table_does_not_end_the_listener";

/// Runs this test again in a child whose descriptor limit is small enough to exhaust on purpose.
/// Returns `true` in that child.
fn in_limited_child() -> bool {
    if std::env::var_os(CHILD_MARKER).is_some() {
        return true;
    }
    let output = Command::new("/bin/sh")
        .args(["-c", "ulimit -n 256 && exec \"$0\" \"$@\""])
        .arg(std::env::current_exe().expect("test executable path is available"))
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD_MARKER, "1")
        .output()
        .expect("the limited child starts");
    let report = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "the descriptor-limited child failed:\n{report}");
    assert!(report.contains("1 passed"), "the descriptor-limited child ran no test:\n{report}");
    false
}

#[tokio::test]
async fn a_full_descriptor_table_does_not_end_the_listener() {
    if !in_limited_child() {
        return;
    }
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(plaintext_config());

    // Take every free descriptor, then give exactly one back for the client's socket: the kernel
    // completes and queues the connection, and the listener has no descriptor to accept it into.
    let mut filler = Vec::new();
    loop {
        match File::open("/dev/null") {
            Ok(file) => filler.push(file),
            Err(error) if error.raw_os_error() == Some(EMFILE) => break,
            Err(error) => panic!("unexpected error while filling the descriptor table: {error}"),
        }
    }
    drop(filler.pop());
    let mut client = TcpStream::connect(local_addr)
        .await
        .expect("the kernel queues the connection");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("the queued connection accepts request bytes");

    tokio::time::timeout(Duration::from_secs(5), async {
        while metrics.accept_errors() == 0 && !task.is_finished() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the listener tried to accept the queued connection");
    assert!(!task.is_finished(), "an exhausted descriptor table ended the listener");
    assert!(metrics.accept_errors() >= 1, "the failed accept was not counted");
    assert_eq!(metrics.accepted_connections(), 0, "a connection was accepted without a descriptor");
    // Where the kernel keeps the connection queued (Linux) the listener stays readable; retrying
    // without a pause would count thousands of failures here instead of a handful.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        metrics.accept_errors() <= 10,
        "the listener spun on a full descriptor table: {} failed accepts in 200ms",
        metrics.accept_errors()
    );

    // Whether the kernel keeps the refused connection queued is platform behaviour (Linux keeps
    // it; macOS resets it), so recovery is proven on a new connection.
    drop(filler);
    drop(client);
    let mut next = TcpStream::connect(local_addr)
        .await
        .expect("a new connection reaches the listener");
    next.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("the new request writes");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), next.read_to_end(&mut response))
        .await
        .expect("the listener accepts again once descriptors are free")
        .expect("the response reads");
    assert!(response.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&response));
    assert!(!task.is_finished(), "the listener ended after recovering");
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}
