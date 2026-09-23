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

//! Responsible for: distinguishing terminated zombies from live descendants in timeout tests.
//! NOT responsible for: process-group signaling or production supervision.
//! Upstream: process supervision test observers. Downstream: operating-system process state.

use super::*;

fn state(pid: u32) -> String {
    let output = Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("process state probe must start");
    String::from_utf8(output.stdout)
        .expect("process state must be text")
        .trim()
        .to_owned()
}

fn wait_for_state(pid: u32, expected: char) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if state(pid).starts_with(expected) {
            return;
        }
        if Instant::now() >= deadline {
            panic!("process {pid} never reached state {expected}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_terminated_child_awaiting_reap_is_not_running() {
    let mut child = Command::new("/bin/sh").args(["-c", "exit 0"]).spawn().expect("child starts");
    wait_for_state(child.id(), 'Z');
    let running = alive_after_reap_grace(&child.id().to_string());
    child.wait().expect("zombie is reaped");
    assert!(!running, "a zombie has terminated even while its PID remains visible");
}

#[test]
fn a_sleeping_child_is_still_running() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().expect("child starts");
    let running = alive_after_reap_grace(&child.id().to_string());
    child.kill().expect("live child is killed");
    child.wait().expect("child is reaped");
    assert!(running, "a live sleeping child must not count as terminated");
}

#[test]
fn a_stopped_child_is_still_running() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().expect("child starts");
    Command::new("/bin/kill")
        .args(["-STOP", &child.id().to_string()])
        .status()
        .expect("stop signal is sent");
    wait_for_state(child.id(), 'T');
    let running = alive_after_reap_grace(&child.id().to_string());
    child.kill().expect("stopped child is killed");
    child.wait().expect("child is reaped");
    assert!(running, "a suspended child can resume and must not count as terminated");
}

#[test]
fn descendant_assertion_accepts_a_terminated_unreaped_child() {
    let mut child = Command::new("/bin/sh").args(["-c", "exit 0"]).spawn().expect("child starts");
    wait_for_state(child.id(), 'Z');
    let running = descendant_can_execute(&child.id().to_string());
    child.wait().expect("zombie is reaped");
    assert!(!running, "descendant assertion confused PID visibility with execution");
}

#[test]
fn descendant_assertion_rejects_a_live_sleeping_child() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().expect("child starts");
    let running = descendant_can_execute(&child.id().to_string());
    child.kill().expect("live child is killed");
    child.wait().expect("child is reaped");
    assert!(running, "a live descendant must fail the termination assertion");
}

#[test]
fn descendant_assertion_rejects_a_live_stopped_child() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().expect("child starts");
    Command::new("/bin/kill")
        .args(["-STOP", &child.id().to_string()])
        .status()
        .expect("stop signal is sent");
    wait_for_state(child.id(), 'T');
    let running = descendant_can_execute(&child.id().to_string());
    child.kill().expect("stopped child is killed");
    child.wait().expect("child is reaped");
    assert!(running, "a stopped descendant must fail the termination assertion");
}
