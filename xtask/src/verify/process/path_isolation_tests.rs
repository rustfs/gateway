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

//! Responsible for: proving process-group termination works with an unusable PATH, measured only
//! after the tree has published a live descendant. NOT responsible for: the supervisor itself or
//! the process-state observer. Upstream: the process test fixtures. Downstream: `run_with_clock`.

use super::*;

/// The pid `echo $! > file` published, once its write has finished: an existing file may still be
/// empty or hold a partial line.
fn complete_pid(published: &str) -> Option<&str> {
    published
        .strip_suffix('\n')
        .filter(|pid| !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()))
}

#[test]
fn path_isolation_helper_process() {
    if std::env::var_os("GATEWAY_PATH_ISOLATION_HELPER").is_none() {
        return;
    }
    let pid_file = PathBuf::from(std::env::var_os("GATEWAY_SIGNAL_PID_FILE").expect("pid file must be provided"));
    let startup = std::env::var("GATEWAY_PATH_ISOLATION_STARTUP").unwrap_or_default();
    let commands = vec![(
        "/bin/sh".to_owned(),
        vec![
            "-c".to_owned(),
            format!("{startup}/bin/sleep 30 & echo $! > '{}'; wait", pid_file.display()),
        ],
        "path-isolated process tree".to_owned(),
    )];
    // The deadline expires on the injected clock only once the tree has published a complete pid
    // of a descendant that can still execute, so group termination is measured against a live
    // tree however slowly the host started it. The wall-clock watchdog only bounds a tree that
    // never becomes ready; the readiness assertion below turns that case into a failure.
    let deadline = Instant::now() + Duration::from_secs(3600);
    let watchdog = Instant::now() + Duration::from_secs(30);
    let ready = std::cell::Cell::new(false);
    let clock = || {
        if !ready.get() {
            let published = fs::read_to_string(&pid_file).unwrap_or_default();
            ready.set(complete_pid(&published).is_some_and(process_alive));
        }
        if ready.get() || Instant::now() >= watchdog {
            deadline
        } else {
            Instant::now()
        }
    };
    let batch = run_with_clock(&commands, Path::new("."), Some(deadline), &clock);
    assert!(ready.get(), "the process tree never published a live descendant pid");
    assert!(batch.timed_out, "the ready process tree was not terminated at its deadline");
}

#[test]
fn group_termination_does_not_depend_on_path_lookup() {
    assert_path_isolated_group_termination(|_| String::new());
}

/// #887: a loaded host can take longer than any fixed deadline to start the shell tree. The
/// deliberate 250ms start must still reach the group kill with a published, live descendant.
#[test]
fn group_termination_after_a_slow_start_does_not_depend_on_path_lookup() {
    assert_path_isolated_group_termination(|_| "/bin/sleep 0.25; ".to_owned());
}

/// An existing but still empty pid file is not readiness: releasing the deadline there would
/// terminate the tree before it has a descendant to prove anything about.
#[test]
fn group_termination_waits_past_an_empty_pid_file() {
    assert_path_isolated_group_termination(|pid_file| format!(": > '{}'; /bin/sleep 0.25; ", pid_file.display()));
}

fn assert_path_isolated_group_termination(startup: impl Fn(&Path) -> String) {
    let root = test_root("path-isolation");
    let pid_file = root.join("grandchild.pid");
    let startup = startup(&pid_file);
    let mut helper = test_executable("verify::process::tests::path_isolation_tests::path_isolation_helper_process")
        .env("GATEWAY_PATH_ISOLATION_HELPER", "1")
        .env("GATEWAY_SIGNAL_PID_FILE", &pid_file)
        .env("GATEWAY_PATH_ISOLATION_STARTUP", startup)
        .env("PATH", "/nonexistent")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("PATH-isolated helper must start");
    let status = helper.wait().expect("PATH-isolated helper must be reaped");
    let pid = fs::read_to_string(&pid_file).unwrap_or_default();
    let alive = !pid.trim().is_empty() && descendant_can_execute(pid.trim());
    if alive {
        terminate_pid(pid.trim());
    }
    fs::remove_dir_all(root).expect("test directory must be removable");

    assert!(status.success(), "the PATH-isolated helper failed: {status:?}");
    assert!(
        complete_pid(&pid).is_some(),
        "the terminated tree never published its descendant pid: {pid:?}"
    );
    assert!(!alive, "PATH isolation bypassed process-group termination");
}
