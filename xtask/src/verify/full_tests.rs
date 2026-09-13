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

//! Responsible for: the full gate's shared setup/runtime deadline and descendant cleanup controls.
//! NOT responsible for: choosing workspace coverage or implementing process supervision.
//! Upstream: full verification orchestration. Downstream: isolated shell fixtures.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{GateCommand, run_setup_then_concurrently};

const CHILD_CASE: &str = "GATEWAY_FULL_GATE_DEADLINE_TEST";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("test clock").as_nanos();
        let root = std::env::temp_dir().join(format!("gateway-full-deadline-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("create fixture directory");
        Self(root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn isolated(name: &str, test: impl FnOnce()) {
    if std::env::var(CHILD_CASE).as_deref() == Ok(name) {
        test();
        return;
    }
    // Short deadlines must not include another unit test's wait for the process-wide signal lock.
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            format!("verify::full_tests::{name}"),
            "--exact".to_owned(),
            "--nocapture".to_owned(),
        ])
        .env(CHILD_CASE, name)
        .output()
        .expect("run the isolated deadline control");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn shell(script: &str, label: &str) -> GateCommand {
    ("sh".to_owned(), vec!["-c".to_owned(), script.to_owned()], label.to_owned())
}

fn assert_descendant_stopped(root: &Path) {
    let pid = fs::read_to_string(root.join("child.pid")).expect("the descendant must have started");
    let stopped = || {
        !Command::new("/bin/kill")
            .args(["-0", pid.trim()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("inspect the actual descendant process")
            .success()
    };
    for _ in 0..200 {
        if stopped() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the full-gate deadline left its descendant running");
}

const DESCENDANT: &str = "(sleep 2; touch completed) & child=$!; printf '%s' \"$child\" > child.pid; wait \"$child\"";

#[test]
fn an_expired_full_gate_never_starts_setup() {
    isolated("an_expired_full_gate_never_starts_setup", || {
        let root = Fixture::new();
        let setup = shell("touch setup", "setup");
        let commands = [shell("touch runtime", "runtime")];
        let batch = run_setup_then_concurrently(&setup, &commands, &root.0, Instant::now());

        assert!(batch.timed_out);
        assert!(!root.0.join("setup").exists());
        assert!(!root.0.join("runtime").exists());
    });
}

#[test]
fn a_full_gate_deadline_terminates_setup_descendants() {
    isolated("a_full_gate_deadline_terminates_setup_descendants", || {
        let root = Fixture::new();
        let setup = shell(DESCENDANT, "setup");
        let commands = [shell("touch runtime", "runtime")];
        let batch = run_setup_then_concurrently(&setup, &commands, &root.0, Instant::now() + Duration::from_millis(500));

        assert!(batch.timed_out);
        assert_eq!(batch.cancelled.iter().map(|step| step.index).collect::<Vec<_>>(), [0]);
        assert_descendant_stopped(&root.0);
        assert!(!root.0.join("completed").exists());
        assert!(!root.0.join("runtime").exists());
    });
}

#[test]
fn a_full_gate_deadline_terminates_runtime_descendants() {
    isolated("a_full_gate_deadline_terminates_runtime_descendants", || {
        let root = Fixture::new();
        let setup = shell("touch setup", "setup");
        let commands = [shell(DESCENDANT, "runtime")];
        let batch = run_setup_then_concurrently(&setup, &commands, &root.0, Instant::now() + Duration::from_millis(500));

        assert!(batch.timed_out);
        assert_eq!(batch.cancelled.iter().map(|step| step.index).collect::<Vec<_>>(), [1]);
        assert!(root.0.join("setup").exists());
        assert_descendant_stopped(&root.0);
        assert!(!root.0.join("completed").exists());
    });
}

#[test]
fn setup_time_is_not_given_back_to_the_runtime_batch() {
    isolated("setup_time_is_not_given_back_to_the_runtime_batch", || {
        let root = Fixture::new();
        let setup = shell("sleep 0.65; touch setup", "setup");
        let commands = [shell("touch runtime; sleep 0.65; touch completed", "runtime")];
        let batch = run_setup_then_concurrently(&setup, &commands, &root.0, Instant::now() + Duration::from_secs(1));

        assert!(batch.timed_out);
        assert_eq!(batch.cancelled.iter().map(|step| step.index).collect::<Vec<_>>(), [1]);
        assert!(root.0.join("setup").exists());
        assert!(root.0.join("runtime").exists());
        assert!(!root.0.join("completed").exists());
    });
}

#[test]
fn setup_failure_prevents_the_runtime_batch() {
    isolated("setup_failure_prevents_the_runtime_batch", || {
        let root = Fixture::new();
        let setup = shell("printf setup-error >&2; exit 7", "setup");
        let commands = [shell("touch runtime", "runtime")];
        let batch = run_setup_then_concurrently(&setup, &commands, &root.0, Instant::now() + Duration::from_secs(5));

        assert!(!batch.timed_out);
        assert_eq!(batch.results.len(), 1);
        let output = batch.results[0].1.as_ref().expect("the setup must have run");
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stderr, b"setup-error");
        assert!(!root.0.join("runtime").exists());
    });
}
