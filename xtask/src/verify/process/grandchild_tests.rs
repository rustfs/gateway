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

//! Responsible for: descendant-cleanup fixture readiness before releasing its deadline.
//! NOT responsible for: production deadline policy or verification command selection.
//! Upstream: process tests and the real supervisor. Downstream: xtask's unit test gate.

use super::*;

fn ready_pid(pid: u32) -> bool {
    observation_tests::state(pid)
        .bytes()
        .next()
        .is_some_and(|state| !matches!(state, b'Z' | b'X'))
}

fn assert_descendant_cleanup(startup: impl FnOnce(&Path) -> String, watchdog_budget: Duration) {
    let root = test_root("crate-grandchild");
    let pid_file = root.join("grandchild.pid");
    let startup = startup(&pid_file);
    let commands = vec![shell(
        vec![
            "-c".to_owned(),
            format!("{startup}sleep 30 & echo $! > '{}'; wait", pid_file.display()),
        ],
        "process tree",
    )];
    let now = Instant::now();
    let deadline = now + Duration::from_secs(3600);
    let watchdog = now + watchdog_budget;
    let ready = std::cell::Cell::new(false);
    // Observe a complete live descendant before expiring its termination clock. The real
    // watchdog bounds missing setup; it is not the deadline being measured.
    let clock = || {
        if !ready.get() {
            let pid = fs::read_to_string(&pid_file).unwrap_or_default();
            ready.set(
                pid.strip_suffix('\n')
                    .is_some_and(|pid| pid.parse::<u32>().is_ok_and(|id| id > 0 && ready_pid(id))),
            );
        }
        if ready.get() || Instant::now() >= watchdog {
            deadline
        } else {
            now
        }
    };
    let batch = run_with_clock(&commands, Path::new("."), Some(deadline), &clock);
    let pid = fs::read_to_string(&pid_file).unwrap_or_default();
    let complete = pid
        .strip_suffix('\n')
        .is_some_and(|pid| pid.parse::<u32>().is_ok_and(|id| id > 0));
    let alive = ready.get() && complete && alive_after_reap_grace(pid.trim());
    if alive {
        terminate_pid(pid.trim());
    }
    fs::remove_dir_all(root).expect("test directory must be removable");
    assert!(ready.get(), "the process tree never published a complete live descendant pid");
    assert!(complete, "an observed ready descendant must retain its complete positive pid");
    assert!(batch.timed_out, "the process-tree deadline was not observed");
    assert!(!alive, "a timed-out command left a grandchild running");
}

#[test]
fn deadline_terminates_grandchildren_in_the_command_group() {
    assert_descendant_cleanup(|_| String::new(), Duration::from_secs(30));
}

#[test]
fn deadline_waits_for_a_delayed_grandchild() {
    assert_descendant_cleanup(|_| "sleep 1.1; ".to_owned(), Duration::from_secs(30));
}

#[test]
fn deadline_waits_past_an_empty_pid_file() {
    assert_descendant_cleanup(|pid| format!(": > '{}'; sleep 1.1; ", pid.display()), Duration::from_secs(30));
}

#[test]
#[should_panic(expected = "the process tree never published a complete live descendant pid")]
fn missing_readiness_at_the_watchdog_is_a_failure() {
    assert_descendant_cleanup(|_| String::new(), Duration::ZERO);
}

#[test]
#[should_panic(expected = "the process tree never published a complete live descendant pid")]
fn partial_pid_at_the_watchdog_is_a_failure() {
    assert_descendant_cleanup(
        |pid| {
            fs::write(pid, std::process::id().to_string()).expect("fixture writes");
            String::new()
        },
        Duration::ZERO,
    );
}

#[test]
#[should_panic(expected = "the process tree never published a complete live descendant pid")]
fn nonnumeric_pid_at_the_watchdog_is_a_failure() {
    assert_descendant_cleanup(
        |pid| {
            fs::write(pid, b"unreadable\n").expect("fixture writes");
            String::new()
        },
        Duration::ZERO,
    );
}

#[test]
#[should_panic(expected = "the process tree never published a complete live descendant pid")]
fn oversized_pid_at_the_watchdog_is_a_failure() {
    assert_descendant_cleanup(
        |pid| {
            fs::write(pid, b"9999999999\n").expect("fixture writes");
            String::new()
        },
        Duration::ZERO,
    );
}

#[test]
#[should_panic(expected = "the process tree never published a complete live descendant pid")]
fn zero_pid_at_the_watchdog_is_a_failure() {
    assert_descendant_cleanup(
        |pid| {
            fs::write(pid, b"0\n").expect("fixture writes");
            String::new()
        },
        Duration::ZERO,
    );
}

#[test]
#[should_panic(expected = "the process tree never published a complete live descendant pid")]
fn terminated_unreaped_pid_at_the_watchdog_is_a_failure() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .spawn()
        .expect("owned child starts");
    observation_tests::wait_for_state(child.id(), 'Z');
    let pid = child.id();
    let outcome = std::panic::catch_unwind(|| {
        assert_descendant_cleanup(
            |file| {
                fs::write(file, format!("{pid}\n")).expect("fixture writes");
                String::new()
            },
            Duration::ZERO,
        );
    });
    child.wait().expect("owned terminated child is reaped");
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
