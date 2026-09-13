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

//! Supervised child execution for bounded verification.
//!
//! Responsible for: draining command output without pipe backpressure, enforcing live deadlines,
//! and reaping every spawned child. NOT responsible for: choosing verification commands or budgets.
//! Upstream: crate and full-gate verification. Downstream: operating-system child processes.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};
#[cfg(unix)]
use std::sync::{Mutex, MutexGuard, OnceLock, TryLockError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use command_group::{CommandGroup, GroupChild};
#[cfg(unix)]
use signal_hook::consts::{SIGINT, SIGTERM};
#[cfg(unix)]
use signal_hook::iterator::Signals;
#[cfg(unix)]
use signal_hook::low_level;

use super::{GateCommand, GateResult};

pub(super) struct Batch {
    pub(super) results: Vec<GateResult>,
    pub(super) timed_out: bool,
    pub(super) interrupted: bool,
    /// The commands the deadline killed while they were still running. Empty unless `timed_out`.
    pub(super) cancelled: Vec<CancelledStep>,
}

/// A command the deadline killed, and what its output showed it had done first.
///
/// A killed command has no cost to report, so this carries the two facts that were actually
/// observed: which command it was, and how many crates cargo said it compiled before the kill.
pub(super) struct CancelledStep {
    /// Index into the command slice the batch was given.
    pub(super) index: usize,
    /// Lines of the form `Compiling <crate>` counted in the command's captured stderr.
    pub(super) compiled_crates: usize,
}

struct SupervisedChild {
    index: usize,
    step: String,
    child: GroupChild,
    stdout: PathBuf,
    stderr: PathBuf,
    completion: Option<io::Result<ExitStatus>>,
    reaped: bool,
    cancelled: bool,
}

struct Supervisor<'clock> {
    children: Vec<SupervisedChild>,
    capture_root: PathBuf,
    signals: SignalControl,
    cleaned: bool,
    clock: &'clock dyn Fn() -> Instant,
}

#[cfg(unix)]
struct SignalControl {
    _guard: MutexGuard<'static, ()>,
    finished: bool,
}

#[cfg(not(unix))]
struct SignalControl;

#[cfg(unix)]
const SIGNAL_INACTIVE: i32 = 0;
#[cfg(unix)]
const SIGNAL_ACTIVE: i32 = -1;
#[cfg(unix)]
static SIGNAL_STATE: AtomicI32 = AtomicI32::new(SIGNAL_INACTIVE);
#[cfg(unix)]
static SIGNAL_LISTENER: OnceLock<Result<(), String>> = OnceLock::new();
#[cfg(unix)]
static SUPERVISOR_LOCK: Mutex<()> = Mutex::new(());
#[cfg(all(test, unix))]
static PAUSE_SIGNAL_LISTENER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(all(test, unix))]
static SIGNAL_LISTENER_PAUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(all(test, unix))]
static SIGNAL_LISTENER_HANDLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(super) fn run(commands: &[GateCommand], current_dir: &Path, deadline: Option<Instant>) -> Batch {
    run_with_clock(commands, current_dir, deadline, &Instant::now)
}

/// [`run`] against an injected clock.
///
/// Every deadline comparison the supervisor makes — waiting for the signal lock, starting a
/// command, and polling running children — reads this clock, so a test can make a deadline expire
/// at a point its child has proven it reached instead of at a wall-clock instant a loaded host
/// may miss. Production passes `Instant::now`.
pub(super) fn run_with_clock(
    commands: &[GateCommand],
    current_dir: &Path,
    deadline: Option<Instant>,
    clock: &dyn Fn() -> Instant,
) -> Batch {
    if commands.is_empty() {
        return Batch {
            results: Vec::new(),
            timed_out: false,
            interrupted: false,
            cancelled: Vec::new(),
        };
    }
    run_supervised(commands, current_dir, deadline, clock)
}

fn run_supervised(commands: &[GateCommand], current_dir: &Path, deadline: Option<Instant>, clock: &dyn Fn() -> Instant) -> Batch {
    let capture_root = match capture_root() {
        Ok(path) => path,
        Err(error) => return failed_to_start(&commands[0].2, error),
    };
    let signals = match SignalControl::new(deadline, clock) {
        Ok(Some(signals)) => signals,
        Ok(None) => {
            let _ = fs::remove_dir_all(capture_root);
            return Batch {
                results: Vec::new(),
                timed_out: true,
                interrupted: false,
                cancelled: Vec::new(),
            };
        }
        Err(error) => {
            let _ = fs::remove_dir_all(capture_root);
            return failed_to_start(&commands[0].2, error);
        }
    };
    let mut supervisor = Supervisor {
        children: Vec::with_capacity(commands.len()),
        capture_root,
        signals,
        cleaned: false,
        clock,
    };
    for (index, (program, args, step)) in commands.iter().enumerate() {
        match supervisor.spawn_before_deadline(index, program, args, step, current_dir, deadline) {
            Ok(true) => {}
            Ok(false) => {
                return supervisor.finish(Batch {
                    results: Vec::new(),
                    timed_out: true,
                    interrupted: false,
                    cancelled: Vec::new(),
                });
            }
            Err(error) => return failed_to_start(step, error),
        }
    }
    let batch = supervisor.wait(deadline);
    supervisor.finish(batch)
}

fn failed_to_start(step: &str, error: io::Error) -> Batch {
    Batch {
        results: vec![(step.to_owned(), Err(error))],
        timed_out: false,
        interrupted: false,
        cancelled: Vec::new(),
    }
}

fn capture_root() -> io::Result<PathBuf> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    for attempt in 0..100 {
        let path = std::env::temp_dir().join(format!("gateway-verify-{}-{nonce}-{attempt}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique verification capture directory",
    ))
}

impl Supervisor<'_> {
    fn spawn_before_deadline(
        &mut self,
        index: usize,
        program: &str,
        args: &[String],
        step: &str,
        current_dir: &Path,
        deadline: Option<Instant>,
    ) -> io::Result<bool> {
        if deadline.is_some_and(|deadline| (self.clock)() >= deadline) {
            return Ok(false);
        }
        self.spawn(index, program, args, step, current_dir)?;
        Ok(true)
    }

    fn spawn(&mut self, index: usize, program: &str, args: &[String], step: &str, current_dir: &Path) -> io::Result<()> {
        let stdout = self.capture_root.join(format!("{index}.stdout"));
        let stderr = self.capture_root.join(format!("{index}.stderr"));
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(current_dir)
            .stdout(Stdio::from(File::create(&stdout)?))
            .stderr(Stdio::from(File::create(&stderr)?));
        let child = command.group_spawn()?;
        self.children.push(SupervisedChild {
            index,
            step: step.to_owned(),
            child,
            stdout,
            stderr,
            completion: None,
            reaped: false,
            cancelled: false,
        });
        Ok(())
    }

    fn wait(&mut self, deadline: Option<Instant>) -> Batch {
        loop {
            let mut failed = false;
            let mut complete = true;
            for child in &mut self.children {
                if child.completion.is_some() {
                    continue;
                }
                match child.child.try_wait() {
                    Ok(Some(status)) => {
                        child.reaped = true;
                        failed |= !status.success();
                        child.completion = Some(Ok(status));
                    }
                    Ok(None) => complete = false,
                    Err(error) => {
                        failed = true;
                        child.completion = Some(Err(error));
                    }
                }
            }
            if self.signals.interrupted() {
                self.cancel_running();
                return Batch {
                    results: self.results(),
                    timed_out: false,
                    interrupted: true,
                    cancelled: Vec::new(),
                };
            }
            if failed {
                self.cancel_running();
                return Batch {
                    results: self.results(),
                    timed_out: false,
                    interrupted: false,
                    cancelled: Vec::new(),
                };
            }
            if complete {
                return Batch {
                    results: self.results(),
                    timed_out: false,
                    interrupted: false,
                    cancelled: Vec::new(),
                };
            }
            if deadline.is_some_and(|deadline| (self.clock)() >= deadline) {
                self.cancel_running();
                return Batch {
                    cancelled: self.cancelled_steps(),
                    results: self.results(),
                    timed_out: true,
                    interrupted: false,
                };
            }
            let delay = deadline
                .map(|deadline| {
                    deadline
                        .saturating_duration_since((self.clock)())
                        .min(Duration::from_millis(10))
                })
                .unwrap_or(Duration::from_millis(10));
            if !delay.is_zero() {
                thread::sleep(delay);
            }
        }
    }

    fn cancel_running(&mut self) {
        for child in &mut self.children {
            if child.reaped {
                continue;
            }
            let was_running = child.completion.is_none();
            let (reaped, termination) = terminate_process_tree(&mut child.child);
            child.reaped = reaped;
            match termination {
                Ok(()) => {
                    child.cancelled = was_running;
                }
                Err(error) => {
                    if child.completion.is_none() {
                        child.completion = Some(Err(error));
                    }
                    child.cancelled = false;
                }
            }
        }
    }

    fn results(&mut self) -> Vec<GateResult> {
        let mut results = self
            .children
            .iter_mut()
            .filter(|child| !child.cancelled)
            .map(|child| {
                let result = match child.completion.take() {
                    Some(Ok(status)) => read_output(status, &child.stdout, &child.stderr),
                    Some(Err(error)) => Err(error),
                    None => Err(io::Error::other("supervised child has no completion status")),
                };
                (child.index, child.step.clone(), result)
            })
            .collect::<Vec<_>>();
        results.sort_by_key(|(index, _, _)| *index);
        results.into_iter().map(|(_, step, result)| (step, result)).collect()
    }

    /// The steps that were still running when the deadline arrived, with what they had compiled.
    ///
    /// Call after `cancel_running`, which is what marks a child cancelled and reaps it: the
    /// captured output is only complete once the process group is gone.
    fn cancelled_steps(&self) -> Vec<CancelledStep> {
        self.children
            .iter()
            .filter(|child| child.cancelled)
            .map(|child| CancelledStep {
                index: child.index,
                compiled_crates: compiled_crates(&child.stderr),
            })
            .collect()
    }

    fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        self.cancel_running();
        let _ = fs::remove_dir_all(&self.capture_root);
        self.cleaned = true;
    }

    fn finish(mut self, batch: Batch) -> Batch {
        self.cleanup();
        let signal = self.signals.finish();
        drop(self);
        if let Some(signal) = signal {
            #[cfg(unix)]
            let _ = low_level::emulate_default_handler(signal);
        }
        batch
    }
}

#[cfg(unix)]
impl SignalControl {
    fn new(deadline: Option<Instant>, clock: &dyn Fn() -> Instant) -> io::Result<Option<Self>> {
        ensure_signal_listener()?;
        let guard = match deadline {
            None => SUPERVISOR_LOCK
                .lock()
                .map_err(|_| io::Error::other("signal supervisor lock is poisoned"))?,
            Some(deadline) => loop {
                match SUPERVISOR_LOCK.try_lock() {
                    Ok(guard) => break guard,
                    Err(TryLockError::Poisoned(_)) => {
                        return Err(io::Error::other("signal supervisor lock is poisoned"));
                    }
                    Err(TryLockError::WouldBlock) => {
                        let remaining = deadline.saturating_duration_since(clock());
                        if remaining.is_zero() {
                            return Ok(None);
                        }
                        thread::sleep(remaining.min(Duration::from_millis(10)));
                    }
                }
            },
        };
        SIGNAL_STATE.store(SIGNAL_ACTIVE, Ordering::SeqCst);
        Ok(Some(Self {
            _guard: guard,
            finished: false,
        }))
    }

    fn interrupted(&self) -> bool {
        SIGNAL_STATE.load(Ordering::SeqCst) > SIGNAL_INACTIVE
    }

    fn finish(&mut self) -> Option<i32> {
        if self.finished {
            return None;
        }
        self.finished = true;
        let signal = SIGNAL_STATE.swap(SIGNAL_INACTIVE, Ordering::SeqCst);
        (signal > SIGNAL_INACTIVE).then_some(signal)
    }
}

#[cfg(not(unix))]
impl SignalControl {
    fn new(deadline: Option<Instant>, clock: &dyn Fn() -> Instant) -> io::Result<Option<Self>> {
        if deadline.is_some_and(|deadline| clock() >= deadline) {
            return Ok(None);
        }
        Ok(Some(Self))
    }

    fn interrupted(&self) -> bool {
        false
    }

    fn finish(&mut self) -> Option<i32> {
        None
    }
}

#[cfg(unix)]
impl Drop for SignalControl {
    fn drop(&mut self) {
        if let Some(signal) = self.finish() {
            let _ = low_level::emulate_default_handler(signal);
        }
    }
}

impl Drop for Supervisor<'_> {
    fn drop(&mut self) {
        self.cleanup();
        if let Some(signal) = self.signals.finish() {
            #[cfg(unix)]
            let _ = low_level::emulate_default_handler(signal);
        }
    }
}

/// Counts the `Compiling <crate>` lines cargo wrote to a step's captured stderr before the kill.
///
/// This is an observation of what the child printed, not an estimate: a killed step that compiled
/// nothing reports nothing. Unreadable capture files count as zero, which understates a build and
/// never invents one.
fn compiled_crates(capture: &Path) -> usize {
    fs::read_to_string(capture)
        .map(|captured| {
            captured
                .lines()
                .filter(|line| line.trim_start().starts_with("Compiling "))
                .count()
        })
        .unwrap_or(0)
}

fn read_output(status: ExitStatus, stdout: &Path, stderr: &Path) -> io::Result<Output> {
    Ok(Output {
        status,
        stdout: fs::read(stdout)?,
        stderr: fs::read(stderr)?,
    })
}

#[cfg(unix)]
fn ensure_signal_listener() -> io::Result<()> {
    let result = SIGNAL_LISTENER.get_or_init(|| {
        let mut signals = Signals::new([SIGINT, SIGTERM]).map_err(|error| error.to_string())?;
        thread::Builder::new()
            .name("gateway-verify-signals".to_owned())
            .spawn(move || {
                for signal in signals.forever() {
                    #[cfg(all(test, unix))]
                    if PAUSE_SIGNAL_LISTENER.load(Ordering::SeqCst) {
                        SIGNAL_LISTENER_PAUSED.store(true, Ordering::SeqCst);
                        while PAUSE_SIGNAL_LISTENER.load(Ordering::SeqCst) {
                            thread::yield_now();
                        }
                        SIGNAL_LISTENER_PAUSED.store(false, Ordering::SeqCst);
                    }
                    match SIGNAL_STATE.compare_exchange(SIGNAL_ACTIVE, signal, Ordering::SeqCst, Ordering::SeqCst) {
                        Ok(_) => {}
                        Err(SIGNAL_INACTIVE) => {
                            let _ = low_level::emulate_default_handler(signal);
                        }
                        Err(_) => {}
                    }
                    #[cfg(all(test, unix))]
                    SIGNAL_LISTENER_HANDLED.store(true, Ordering::SeqCst);
                }
            })
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    result.as_ref().map(|_| ()).map_err(|error| io::Error::other(error.clone()))
}

fn terminate_process_tree(child: &mut GroupChild) -> (bool, io::Result<()>) {
    match child.kill() {
        Ok(()) => {
            let waited = child.wait();
            (waited.is_ok(), waited.map(|_| ()))
        }
        Err(group_error) => recover_after_group_kill_failure(child, group_error),
    }
}

fn recover_after_group_kill_failure(child: &mut GroupChild, group_error: io::Error) -> (bool, io::Result<()>) {
    if child.try_wait().is_ok_and(|status| status.is_some()) {
        return (true, Ok(()));
    }
    let _ = child.inner().kill();
    let waited = child.inner().wait();
    let reaped = waited.is_ok();
    (reaped, Err(group_error))
}

#[cfg(all(test, unix))]
mod tests;
