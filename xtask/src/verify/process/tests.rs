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
use std::sync::mpsc;

use super::*;

#[path = "observation_tests.rs"]
mod observation_tests;
#[path = "path_isolation_tests.rs"]
mod path_isolation_tests;

/// A directory no other test in this process shares. The clock alone is not unique: macOS reports
/// microseconds, so parallel cases with one label started in the same microsecond once shared a
/// root and deleted each other's fixtures.
fn test_root(label: &str) -> PathBuf {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock must be after the Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("gateway-{label}-{}-{nonce}-{sequence}", std::process::id()));
    fs::create_dir(&root).expect("test directory must be creatable and not already exist");
    root
}

fn shell(args: Vec<String>, step: &str) -> GateCommand {
    ("sh".to_owned(), args, step.to_owned())
}

fn test_supervisor(capture_root: PathBuf) -> Supervisor<'static> {
    let signals = SignalControl::new(None, &Instant::now)
        .expect("signal listener must start")
        .expect("a supervisor without a deadline must acquire the lock");
    Supervisor {
        children: Vec::new(),
        capture_root,
        signals,
        cleaned: false,
        clock: &Instant::now,
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

/// Whether `pid` can still execute after the process-group kill.
///
/// A SIGKILLed grandchild whose parent died with it is reparented to init and stays visible to
/// `kill -0` as a zombie until init reaps it. Observe termination independently of that reap:
/// zombies cannot execute, but sleeping and stopped descendants can and must remain failures.
fn alive_after_reap_grace(pid: &str) -> bool {
    for _ in 0..200 {
        if !process_alive(pid) {
            return false;
        }
        let output = Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", pid])
            .output()
            .expect("process state probe must start");
        let state = String::from_utf8(output.stdout).expect("process state must be text");
        if output.status.success() && state.trim_start().starts_with('Z') {
            return false;
        }
        if !output.status.success() && process_alive(pid) {
            panic!("process state probe failed for a visible descendant");
        }
        thread::sleep(Duration::from_millis(10));
    }
    true
}

// The PATH-isolation and signal assertions must measure the same descendant state.
fn descendant_can_execute(pid: &str) -> bool {
    alive_after_reap_grace(pid)
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

/// A killed command leaves no result behind, so unless the deadline reports which command it was
/// holding, the diagnostic upstream has nothing left to name but the deadline itself.
#[test]
fn a_deadline_kill_names_the_step_it_was_still_holding() {
    let root = test_root("deadline-kill");
    let marker = root.join("running");
    let mut supervisor = test_supervisor(capture_root().expect("capture directory must be creatable"));
    let args = vec!["-c".to_owned(), format!("touch '{}'; exec sleep 30", marker.display())];
    supervisor
        .spawn(0, "sh", &args, "slow", Path::new("."))
        .expect("child must start");
    wait_for_file(&marker);

    let batch = supervisor.wait(Some(Instant::now() + Duration::from_millis(50)));

    drop(supervisor);
    fs::remove_dir_all(root).expect("test directory must be removable");
    assert!(batch.timed_out, "a running child was not killed at its deadline");
    assert_eq!(batch.cancelled.len(), 1, "the killed step was not reported");
    assert_eq!(batch.cancelled[0].index, 0);
    assert_eq!(
        batch.cancelled[0].compiled_crates, 0,
        "a step that compiled nothing must not be credited with a build"
    );
}

/// The other direction of the same signal: a step that had been compiling when the deadline arrived
/// reports what it compiled, which is how a cold build inside the budget becomes legible instead of
/// being read as the crate's own cost.
#[test]
fn a_step_killed_after_compiling_reports_the_crates_it_compiled() {
    let root = test_root("deadline-build");
    let marker = root.join("compiled");
    let mut supervisor = test_supervisor(capture_root().expect("capture directory must be creatable"));
    let args = vec![
        "-c".to_owned(),
        format!(
            "( printf '   Compiling proc-macro2 v1.0.95\\n   Compiling syn v2.0.0\\n' >&2 ); touch '{}'; exec sleep 30",
            marker.display()
        ),
    ];
    supervisor
        .spawn(0, "sh", &args, "cold", Path::new("."))
        .expect("child must start");
    wait_for_file(&marker);

    let batch = supervisor.wait(Some(Instant::now() + Duration::from_millis(50)));

    drop(supervisor);
    fs::remove_dir_all(root).expect("test directory must be removable");
    assert!(batch.timed_out, "a running child was not killed at its deadline");
    assert_eq!(batch.cancelled.len(), 1, "the killed step was not reported");
    assert_eq!(batch.cancelled[0].compiled_crates, 2);
}

/// A batch that finishes inside its deadline has no killed step, and reporting one anyway would
/// hang a build note on a run nothing interrupted.
/// A verification child must see the shell's environment, not the package variables `cargo`
/// gave this process: a nested Cargo inheriting them reruns `ring`'s build script and rebuilds
/// everything above it (rustfs/gateway#897). `cargo test` sets them here exactly as `cargo run`
/// sets them for xtask, and a user's Cargo configuration still has to reach the child.
#[test]
fn a_verification_child_sees_no_package_variable_but_keeps_cargo_configuration() {
    assert!(
        std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
        "cargo test must set the variable under test"
    );
    let script = "printf 'manifest=%s\\n' \"${CARGO_MANIFEST_DIR-unset}\"; printf 'name=%s\\n' \"${CARGO_PKG_NAME-unset}\"; printf 'cargo=%s\\n' \"${CARGO-unset}\"";
    let commands = vec![shell(vec!["-c".to_owned(), script.to_owned()], "environment")];

    let batch = run(&commands, Path::new("."), None);

    assert!(all_succeeded(&batch, 1));
    let output = batch.results[0].1.as_ref().expect("child output must be captured");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("manifest=unset\n"), "{stdout}");
    assert!(stdout.contains("name=unset\n"), "{stdout}");
    assert!(!stdout.contains("cargo=unset"), "the cargo binary must stay visible: {stdout}");
}

#[test]
fn a_batch_that_finishes_reports_no_killed_step() {
    let mut supervisor = test_supervisor(capture_root().expect("capture directory must be creatable"));
    let args = vec!["-c".to_owned(), "printf '   Compiling proc-macro2 v1.0.95\\n' >&2".to_owned()];
    supervisor
        .spawn(0, "sh", &args, "quick", Path::new("."))
        .expect("child must start");

    let batch = supervisor.wait(Some(Instant::now() + Duration::from_secs(30)));

    assert!(!batch.timed_out, "a completed batch was reported as a timeout");
    assert!(batch.cancelled.is_empty(), "a completed batch reported a killed step");
}

#[test]
fn deadline_expires_while_waiting_for_supervisor_lock_without_starting_command() {
    let root = test_root("lock-deadline");
    let marker = root.join("started");
    let lock = SUPERVISOR_LOCK.lock().expect("test must hold the supervisor lock");
    let (sender, receiver) = mpsc::channel();
    let (ready_sender, ready_receiver) = mpsc::channel();
    let worker_root = root.clone();
    let worker_marker = marker.clone();
    let worker = thread::spawn(move || {
        let commands = vec![shell(
            vec!["-c".to_owned(), format!("touch '{}'", worker_marker.display())],
            "must not start",
        )];
        ready_sender.send(()).expect("test readiness receiver must remain available");
        let batch = run(&commands, &worker_root, Some(Instant::now() + Duration::from_millis(50)));
        sender.send(batch).expect("test result receiver must remain available");
    });

    ready_receiver.recv().expect("deadline worker must become ready");
    let result = receiver.recv_timeout(Duration::from_millis(250));
    drop(lock);
    let batch = result.expect("the expired deadline waited for the supervisor lock");
    worker.join().expect("deadline worker must finish");

    assert!(batch.timed_out, "lock contention was not reported as a timeout");
    assert!(batch.results.is_empty(), "a command was reported before the supervisor lock was acquired");
    assert!(!marker.exists(), "an expired command started after waiting for the supervisor lock");
    fs::remove_dir_all(root).expect("test directory must be removable");
}

/// The lock wait reads the injected clock as well: a deadline that clock has already passed ends
/// the wait at once, although the real clock is still an hour short of it. The receive bound only
/// keeps an implementation that waits on the real clock from hanging the suite.
#[test]
fn an_injected_clock_past_the_deadline_ends_the_lock_wait() {
    let root = test_root("lock-injected-clock");
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
        let deadline = Instant::now() + Duration::from_secs(3600);
        let batch = run_with_clock(&commands, &worker_root, Some(deadline), &move || deadline);
        sender.send(batch).expect("test result receiver must remain available");
    });

    let result = receiver.recv_timeout(Duration::from_secs(30));
    drop(lock);
    worker.join().expect("deadline worker must finish");
    let batch = result.expect("the lock wait ignored the injected clock");

    assert!(batch.timed_out, "an injected expiry during the lock wait was not reported");
    assert!(batch.results.is_empty(), "a command was reported before the supervisor lock was acquired");
    assert!(!marker.exists(), "a command started after its injected deadline expired");
    fs::remove_dir_all(root).expect("test directory must be removable");
}

#[test]
fn supervisor_lock_released_before_deadline_allows_command_to_start() {
    let root = test_root("lock-release");
    let marker = root.join("started");
    let lock = SUPERVISOR_LOCK.lock().expect("test must hold the supervisor lock");
    let (ready_sender, ready_receiver) = mpsc::channel();
    let worker_root = root.clone();
    let worker_marker = marker.clone();
    let worker = thread::spawn(move || {
        let commands = vec![shell(
            vec!["-c".to_owned(), format!("touch '{}'", worker_marker.display())],
            "must start",
        )];
        ready_sender.send(()).expect("test readiness receiver must remain available");
        run(&commands, &worker_root, Some(Instant::now() + Duration::from_secs(1)))
    });
    ready_receiver.recv().expect("deadline worker must become ready");
    thread::sleep(Duration::from_millis(50));
    drop(lock);

    let batch = worker.join().expect("deadline worker must finish");

    assert!(all_succeeded(&batch, 1), "lock contention caused an early timeout");
    assert!(marker.exists(), "a command released before its deadline did not start");
    fs::remove_dir_all(root).expect("test directory must be removable");
}

#[test]
fn already_expired_deadline_never_starts_command() {
    let root = test_root("expired-before-spawn");
    let marker = root.join("started");
    let commands = vec![shell(
        vec!["-c".to_owned(), format!("touch '{}'", marker.display())],
        "must not start",
    )];

    let batch = run(&commands, &root, Some(Instant::now()));

    assert!(batch.timed_out, "an expired deadline was not reported");
    assert!(batch.results.is_empty(), "an expired command produced a result");
    assert!(!marker.exists(), "an already expired command started");
    fs::remove_dir_all(root).expect("test directory must be removable");
}

#[test]
fn deadline_expiring_after_lock_acquisition_stops_command_startup() {
    let root = test_root("expired-before-spawn");
    let marker = root.join("started");
    let capture = capture_root().expect("capture directory must be creatable");
    let mut supervisor = test_supervisor(capture);
    let deadline = Instant::now() + Duration::from_millis(25);
    thread::sleep(Duration::from_millis(50));
    let started = supervisor
        .spawn_before_deadline(
            0,
            "sh",
            &["-c".to_owned(), format!("touch '{}'", marker.display())],
            "must not start",
            &root,
            Some(deadline),
        )
        .expect("deadline check must not fail");

    assert!(!started, "startup did not recheck the deadline after acquiring the lock");
    assert!(!marker.exists(), "a command started after its deadline expired");
    drop(supervisor);
    fs::remove_dir_all(root).expect("test directory must be removable");
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
    let alive = alive_after_reap_grace(pid.trim());
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
    let alive = descendant_can_execute(pid.trim());
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
