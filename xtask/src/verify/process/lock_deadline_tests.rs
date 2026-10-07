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

//! Responsible for: expiry during an observed supervisor-lock wait, including a paused host.
//! NOT responsible for: unexpired admission or child-process cleanup.
//! Upstream: the verifier's injected clock and signal lock. Downstream: xtask's unit gate.

use super::*;

#[test]
fn deadline_expires_while_waiting_for_supervisor_lock_without_starting_command() {
    assert_expired_lock_wait(Duration::ZERO);
}

/// Negative — a host pause after observing lock contention must not be mistaken for failure to expire the lock wait.
#[test]
fn deadline_expiry_reports_after_a_host_pause() {
    assert_expired_lock_wait(Duration::from_millis(350));
}

fn assert_expired_lock_wait(host_pause: Duration) {
    let root = test_root("lock-deadline");
    let marker = root.join("started");
    let lock = SUPERVISOR_LOCK.lock().expect("test must hold the supervisor lock");
    let (sender, receiver) = mpsc::channel();
    let worker_root = root.clone();
    let worker_marker = marker.clone();
    let worker = thread::spawn(move || {
        let commands = vec![shell(
            vec!["-c".to_owned(), format!("touch '{}'", worker_marker.display())],
            "must not start",
        )];
        let now = Instant::now();
        let deadline = now + Duration::from_secs(3600);
        let reads = std::cell::Cell::new(0);
        // The held lock reaches this clock once before expiry, then again at expiry. Host
        // scheduling may pause either observation without advancing the injected deadline.
        let clock = || {
            let read = reads.get();
            reads.set(read + 1);
            if read == 0 {
                thread::sleep(host_pause);
                now
            } else {
                deadline
            }
        };
        let batch = run_with_clock(&commands, &worker_root, Some(deadline), &clock);
        sender
            .send((batch, reads.get()))
            .expect("test result receiver must remain available");
    });

    // This wall-clock bound detects a hung implementation; it does not decide deadline expiry.
    let result = receiver.recv_timeout(Duration::from_secs(30));
    drop(lock);
    worker.join().expect("deadline worker must finish");
    let (batch, reads) = result.expect("the expired deadline waited for the supervisor lock");

    assert!(reads >= 2, "the test never observed an unexpired lock wait before expiry");

    assert!(batch.timed_out, "lock contention was not reported as a timeout");
    assert!(batch.results.is_empty(), "a command was reported before the supervisor lock was acquired");
    assert!(!marker.exists(), "an expired command started after waiting for the supervisor lock");
    fs::remove_dir_all(root).expect("test directory must be removable");
}
