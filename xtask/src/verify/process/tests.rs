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

//! Responsible for: process-supervisor deadline, cleanup, signal, and failure-attribution
//! regressions. NOT responsible for: selecting verification commands or budgets.
//! Upstream: the verify process supervisor. Downstream: focused xtask tests.

use std::os::unix::process::ExitStatusExt;
use std::process::Child;

use super::*;

fn test_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock must be after the Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("gateway-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).expect("test directory must be creatable");
    root
}

fn shell(args: Vec<String>, step: &str) -> GateCommand {
    ("sh".to_owned(), args, step.to_owned())
}

fn test_supervisor(capture_root: PathBuf) -> Supervisor {
    let signals = SignalControl::new().expect("signal listener must start");
    Supervisor {
        children: Vec::new(),
        capture_root,
        signals,
        cleaned: false,
    }
}

fn all_succeeded(batch: &Batch, expected: usize) -> bool {
    !batch.timed_out
        && !batch.interrupted
        && batch.results.len() == expected
        && batch
            .results
            .iter()
            .all(|(_, result)| result.as_ref().is_ok_and(|output| output.status.success()))
}

fn process_alive(pid: &str) -> bool {
    Command::new("/bin/kill")
        .args(["-0", pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn terminate_pid(pid: &str) {
    let _ = Command::new("/bin/kill")
        .args(["-KILL", pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn wait_for_file(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("{} was not created", path.display());
}

fn wait_or_kill(helper: &mut Child) -> (bool, ExitStatus) {
    for _ in 0..200 {
        if let Some(status) = helper.try_wait().expect("helper wait must succeed") {
            return (false, status);
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = helper.kill();
    let status = helper.wait().expect("killed helper must be reaped");
    (true, status)
}

fn test_executable(test: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable must be available"));
    command.args([test, "--exact", "--nocapture"]);
    command
}

#[test]
fn starts_every_child_before_waiting_for_one() {
    let root = test_root("crate-barrier");
    let first = root.join("first");
    let second = root.join("second");
    let wait_for = |own: &Path, peer: &Path| {
        vec![
            "-c".to_owned(),
            format!(
                "touch '{}'; for _ in $(seq 1 100); do test -f '{}' && exit 0; sleep 0.01; done; exit 1",
                own.display(),
                peer.display()
            ),
        ]
    };
    let commands = vec![
        shell(wait_for(&first, &second), "first"),
        shell(wait_for(&second, &first), "second"),
    ];

    let batch = run(&commands, Path::new("."), Some(Instant::now() + Duration::from_secs(5)));

    fs::remove_dir_all(root).expect("test directory must be removable");
    assert!(all_succeeded(&batch, 2), "crate verification steps ran sequentially");
}

#[test]
fn drains_later_output_without_blocking_an_earlier_child() {
    let root = test_root("crate-output");
    let marker = root.join("writer-finished");
    let commands = vec![
        shell(
            vec![
                "-c".to_owned(),
                format!(
                    "for _ in $(seq 1 200); do test -f '{}' && exit 0; sleep 0.01; done; exit 1",
                    marker.display()
                ),
            ],
            "reader",
        ),
        shell(
            vec![
                "-c".to_owned(),
                format!("dd if=/dev/zero bs=1048576 count=1 2>/dev/null; touch '{}'", marker.display()),
            ],
            "writer",
        ),
    ];

    let batch = run(&commands, Path::new("."), Some(Instant::now() + Duration::from_secs(5)));

    fs::remove_dir_all(root).expect("test directory must be removable");
    assert!(all_succeeded(&batch, 2), "a later child's full pipe blocked an earlier child");
}

#[test]
fn failure_cancels_and_reaps_slow_siblings() {
    let root = test_root("crate-failure");
    let marker = root.join("slow-child-finished");
    let commands = vec![
        shell(vec!["-c".to_owned(), format!("sleep 10; touch '{}'", marker.display())], "slow"),
        shell(vec!["-c".to_owned(), "exit 7".to_owned()], "failure"),
    ];
    let started = Instant::now();

    let batch = run(&commands, Path::new("."), Some(started + Duration::from_secs(5)));
    let elapsed = started.elapsed();

    let slow_child_finished = marker.exists();
    fs::remove_dir_all(root).expect("test directory must be removable");
    assert!(!batch.timed_out, "a child failure was misreported as a timeout");
    assert_eq!(batch.results.len(), 1, "a cancelled sibling was reported as the root failure");
    assert_eq!(batch.results[0].0, "failure");
    assert_eq!(
        batch.results[0]
            .1
            .as_ref()
            .expect("failure output must be captured")
            .status
            .code(),
        Some(7)
    );
    assert!(elapsed < Duration::from_secs(5), "a failed crate step waited for a slow sibling");
    assert!(!slow_child_finished, "a cancelled sibling outlived the crate gate");
}

#[test]
fn an_already_exited_sibling_cannot_hide_the_real_failure() {
    let capture = capture_root().expect("capture directory must be creatable");
    let mut supervisor = test_supervisor(capture);
    supervisor
        .spawn(0, "/bin/sh", &["-c".to_owned(), "true".to_owned()], "success", Path::new("."))
        .expect("successful sibling must start");
    supervisor
        .spawn(1, "/bin/sh", &["-c".to_owned(), "exit 7".to_owned()], "failure", Path::new("."))
        .expect("failing child must start");
    thread::sleep(Duration::from_millis(50));
    let failure = supervisor.children[1]
        .child
        .try_wait()
        .expect("failing child wait must succeed")
        .expect("failing child must have exited");
    supervisor.children[1].completion = Some(Ok(failure));
    supervisor.children[1].reaped = true;

    supervisor.cancel_running();
    let results = supervisor.results();

    assert_eq!(results.len(), 1, "an exited sibling cleanup error hid the real failure");
    assert_eq!(results[0].0, "failure");
    assert_eq!(results[0].1.as_ref().expect("failure output must be captured").status.code(), Some(7));
}

#[test]
fn direct_child_fallback_cannot_hide_a_group_kill_error() {
    let root = test_root("group-kill-error");
    let pid_file = root.join("grandchild.pid");
    let capture = capture_root().expect("capture directory must be creatable");
    let mut supervisor = test_supervisor(capture);
    let args = vec![
        "-c".to_owned(),
        format!("sleep 30 & echo $! > '{}'; wait", pid_file.display()),
    ];
    supervisor
        .spawn(0, "/bin/sh", &args, "permission denied", Path::new("."))
        .expect("process group must start");
    wait_for_file(&pid_file);

    let group_error = io::Error::new(io::ErrorKind::PermissionDenied, "synthetic group kill failure");
    let (reaped, result) = recover_after_group_kill_failure(&mut supervisor.children[0].child, group_error);
    supervisor.children[0].reaped = reaped;
    let pid = fs::read_to_string(&pid_file).expect("grandchild must publish its pid");
    if process_alive(pid.trim()) {
        terminate_pid(pid.trim());
    }
    fs::remove_dir_all(root).expect("test directory must be removable");

    assert!(reaped, "the direct child fallback was not reaped");
    assert_eq!(
        result.expect_err("direct child cleanup cannot prove group cleanup").kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn deadline_is_enforced_while_children_are_running() {
    let commands = vec![shell(vec!["-c".to_owned(), "sleep 2".to_owned()], "slow")];
    let started = Instant::now();

    let batch = run(&commands, Path::new("."), Some(started + Duration::from_millis(100)));

    assert!(batch.timed_out, "an over-budget crate step passed");
    assert!(started.elapsed() < Duration::from_secs(1), "the deadline was checked after completion");
}

#[test]
fn dropping_the_supervisor_kills_and_reaps_a_running_child() {
    let root = test_root("crate-drop");
    let pid_file = root.join("child.pid");
    let capture = capture_root().expect("capture directory must be creatable");
    let mut supervisor = test_supervisor(capture);
    let args = vec!["-c".to_owned(), format!("echo $$ > '{}'; exec sleep 2", pid_file.display())];
    supervisor
        .spawn(0, "sh", &args, "slow", Path::new("."))
        .expect("child must start");
    wait_for_file(&pid_file);
    let pid = fs::read_to_string(&pid_file).expect("child must publish its pid");

    drop(supervisor);

    let alive = process_alive(pid.trim());
    fs::remove_dir_all(root).expect("test directory must be removable");
    assert!(!alive, "a dropped supervisor left its child running");
}

#[test]
fn a_wait_error_is_retained_after_the_child_is_reaped() {
    let capture = capture_root().expect("capture directory must be creatable");
    let mut supervisor = test_supervisor(capture);
    let args = vec!["-c".to_owned(), "sleep 2".to_owned()];
    supervisor
        .spawn(0, "sh", &args, "wait failure", Path::new("."))
        .expect("child must start");
    supervisor.children[0].completion = Some(Err(io::Error::other("synthetic wait failure")));

    supervisor.cancel_running();
    let results = supervisor.results();

    assert_eq!(results.len(), 1, "the root wait error was mistaken for a cancelled sibling");
    let error = results[0]
        .1
        .as_ref()
        .expect_err("the synthetic wait failure must remain visible");
    assert_eq!(error.to_string(), "synthetic wait failure");
}

#[test]
fn deadline_terminates_grandchildren_in_the_command_group() {
    let root = test_root("crate-grandchild");
    let pid_file = root.join("grandchild.pid");
    let commands = vec![shell(
        vec![
            "-c".to_owned(),
            format!("sleep 30 & echo $! > '{}'; wait", pid_file.display()),
        ],
        "process tree",
    )];

    let batch = run(&commands, Path::new("."), Some(Instant::now() + Duration::from_secs(1)));
    let pid = fs::read_to_string(&pid_file).expect("grandchild must publish its pid");
    let alive = process_alive(pid.trim());
    if alive {
        terminate_pid(pid.trim());
    }
    fs::remove_dir_all(root).expect("test directory must be removable");

    assert!(batch.timed_out, "the process-tree deadline was not observed");
    assert!(!alive, "a timed-out command left a grandchild running");
}

#[test]
fn signal_helper_process() {
    if std::env::var_os("GATEWAY_SIGNAL_HELPER").is_none() {
        return;
    }
    let pid_file = PathBuf::from(std::env::var_os("GATEWAY_SIGNAL_PID_FILE").expect("pid file must be provided"));
    let commands = vec![shell(
        vec![
            "-c".to_owned(),
            format!("sleep 30 & echo $! > '{}'; wait", pid_file.display()),
        ],
        "signal process tree",
    )];
    let _ = run(&commands, Path::new("."), Some(Instant::now() + Duration::from_secs(30)));
}

#[test]
fn targeted_sigterm_terminates_the_supervised_process_group() {
    let root = test_root("crate-signal");
    let pid_file = root.join("grandchild.pid");
    let mut helper = test_executable("verify::process::tests::signal_helper_process")
        .env("GATEWAY_SIGNAL_HELPER", "1")
        .env("GATEWAY_SIGNAL_PID_FILE", &pid_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("signal helper must start");
    wait_for_file(&pid_file);
    let pid = fs::read_to_string(&pid_file).expect("grandchild must publish its pid");
    let helper_pid = helper.id();
    let _ = Command::new("/bin/kill").args(["-TERM", &helper_pid.to_string()]).status();
    let _ = wait_or_kill(&mut helper);
    let alive = process_alive(pid.trim());
    if alive {
        terminate_pid(pid.trim());
    }
    fs::remove_dir_all(root).expect("test directory must be removable");

    assert!(!alive, "SIGTERM left a supervised grandchild running");
    let capture_prefix = format!("gateway-verify-{helper_pid}-");
    let capture_left = fs::read_dir(std::env::temp_dir())
        .expect("temporary directory must be readable")
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().starts_with(&capture_prefix));
    assert!(!capture_left, "SIGTERM bypassed supervisor capture cleanup");
}

#[test]
fn stale_signal_helper_process() {
    if std::env::var_os("GATEWAY_STALE_SIGNAL_HELPER").is_none() {
        return;
    }
    PAUSE_SIGNAL_LISTENER.store(true, Ordering::SeqCst);
    SIGNAL_LISTENER_HANDLED.store(false, Ordering::SeqCst);
    let capture = capture_root().expect("capture directory must be creatable");
    let mut supervisor = test_supervisor(capture);
    let args = vec!["-c".to_owned(), "true".to_owned()];
    supervisor
        .spawn(0, "/bin/sh", &args, "completed", Path::new("."))
        .expect("child must start");
    thread::sleep(Duration::from_millis(50));
    let _ = Command::new("/bin/kill")
        .args(["-TERM", &std::process::id().to_string()])
        .status();
    while !SIGNAL_LISTENER_PAUSED.load(Ordering::SeqCst) {
        thread::yield_now();
    }
    let batch = supervisor.wait(Some(Instant::now() + Duration::from_secs(5)));
    assert!(all_succeeded(&batch, 1), "the test must reach the stale signal window");
    let batch = supervisor.finish(batch);
    assert!(all_succeeded(&batch, 1), "finishing the completed batch must succeed");
    PAUSE_SIGNAL_LISTENER.store(false, Ordering::SeqCst);
    while !SIGNAL_LISTENER_HANDLED.load(Ordering::SeqCst) {
        thread::yield_now();
    }
    let commands = vec![shell(vec!["-c".to_owned(), "true".to_owned()], "next batch")];
    let _ = run(&commands, Path::new("."), Some(Instant::now() + Duration::from_secs(5)));
    thread::sleep(Duration::from_secs(30));
}

#[test]
fn signal_observed_before_finish_cannot_be_swallowed_by_the_next_batch() {
    let mut helper = test_executable("verify::process::tests::stale_signal_helper_process")
        .env("GATEWAY_STALE_SIGNAL_HELPER", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("stale-signal helper must start");

    let (survived, status) = wait_or_kill(&mut helper);

    assert!(!survived, "a stale active read allowed the next batch to swallow SIGTERM");
    assert_eq!(status.signal(), Some(SIGTERM), "the stale signal did not preserve SIGTERM semantics");
}

#[test]
fn post_success_signal_helper_process() {
    if std::env::var_os("GATEWAY_POST_SUCCESS_HELPER").is_none() {
        return;
    }
    let ready = PathBuf::from(std::env::var_os("GATEWAY_SIGNAL_READY_FILE").expect("ready file must be provided"));
    let commands = vec![shell(vec!["-c".to_owned(), "true".to_owned()], "success")];
    assert!(all_succeeded(
        &run(&commands, Path::new("."), Some(Instant::now() + Duration::from_secs(5))),
        1
    ));
    File::create(ready).expect("ready file must be creatable");
    thread::sleep(Duration::from_secs(30));
}

#[test]
fn signal_after_success_uses_the_default_termination_action() {
    let root = test_root("post-success-signal");
    let ready = root.join("ready");
    let mut helper = test_executable("verify::process::tests::post_success_signal_helper_process")
        .env("GATEWAY_POST_SUCCESS_HELPER", "1")
        .env("GATEWAY_SIGNAL_READY_FILE", &ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("post-success helper must start");
    wait_for_file(&ready);
    let _ = Command::new("/bin/kill").args(["-TERM", &helper.id().to_string()]).status();
    let (survived, status) = wait_or_kill(&mut helper);
    fs::remove_dir_all(root).expect("test directory must be removable");

    assert!(!survived, "a successful supervisor drop left SIGTERM ignored");
    assert_eq!(status.signal(), Some(SIGTERM), "SIGTERM did not retain its default action");
}

#[test]
fn completion_race_helper_process() {
    if std::env::var_os("GATEWAY_COMPLETION_RACE_HELPER").is_none() {
        return;
    }
    let capture = capture_root().expect("capture directory must be creatable");
    let mut supervisor = test_supervisor(capture);
    let args = vec!["-c".to_owned(), "true".to_owned()];
    supervisor
        .spawn(0, "/bin/sh", &args, "completed", Path::new("."))
        .expect("child must start");
    thread::sleep(Duration::from_millis(50));
    let _ = Command::new("/bin/kill")
        .args(["-TERM", &std::process::id().to_string()])
        .status();
    thread::sleep(Duration::from_millis(50));
    let batch = supervisor.wait(Some(Instant::now() + Duration::from_secs(5)));
    assert!(batch.interrupted, "a signal racing completion was reported as success");
}

#[test]
fn signal_racing_last_completion_cannot_return_success() {
    let mut helper = test_executable("verify::process::tests::completion_race_helper_process")
        .env("GATEWAY_COMPLETION_RACE_HELPER", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("completion-race helper must start");

    let (survived, status) = wait_or_kill(&mut helper);

    assert!(!survived, "a signal racing the last completion returned success");
    assert_eq!(status.signal(), Some(SIGTERM), "the completion race did not preserve SIGTERM semantics");
}

#[test]
fn path_isolation_helper_process() {
    if std::env::var_os("GATEWAY_PATH_ISOLATION_HELPER").is_none() {
        return;
    }
    let pid_file = PathBuf::from(std::env::var_os("GATEWAY_SIGNAL_PID_FILE").expect("pid file must be provided"));
    let commands = vec![(
        "/bin/sh".to_owned(),
        vec![
            "-c".to_owned(),
            format!("/bin/sleep 30 & echo $! > '{}'; wait", pid_file.display()),
        ],
        "path-isolated process tree".to_owned(),
    )];
    let _ = run(&commands, Path::new("."), Some(Instant::now() + Duration::from_millis(100)));
}

#[test]
fn group_termination_does_not_depend_on_path_lookup() {
    let root = test_root("path-isolation");
    let pid_file = root.join("grandchild.pid");
    let mut helper = test_executable("verify::process::tests::path_isolation_helper_process")
        .env("GATEWAY_PATH_ISOLATION_HELPER", "1")
        .env("GATEWAY_SIGNAL_PID_FILE", &pid_file)
        .env("PATH", "/nonexistent")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("PATH-isolated helper must start");
    wait_for_file(&pid_file);
    let _ = helper.wait();
    let pid = fs::read_to_string(&pid_file).expect("grandchild must publish its pid");
    let alive = process_alive(pid.trim());
    if alive {
        terminate_pid(pid.trim());
    }
    fs::remove_dir_all(root).expect("test directory must be removable");

    assert!(!alive, "PATH isolation bypassed process-group termination");
}
