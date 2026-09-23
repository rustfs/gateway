#!/usr/bin/env python3
"""Measure one cold bootstrap under a matched two-CPU, job-local profile configuration."""
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def emit(event, **fields):
    print(json.dumps(dict(event=event, **fields), sort_keys=True), flush=True)


def command_output(*args):
    return subprocess.check_output(args, text=True).strip()


def stop_process_group(process):
    # Only this arm's private session is signalled; descendants may ignore TERM.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('baseline', 'no-debug'):
        raise ValueError('expected baseline or no-debug')
    mode = sys.argv[1]
    debug = [os.environ.get('CARGO_PROFILE_DEV_DEBUG'), os.environ.get('CARGO_PROFILE_TEST_DEBUG')]
    if debug != (['0', '0'] if mode == 'no-debug' else [None, None]):
        raise ValueError('job profile overrides do not match the experiment arm')
    if os.environ.get('CARGO_INCREMENTAL') != '0':
        raise ValueError('both arms require CARGO_INCREMENTAL=0')
    forbidden = {'CARGO_BUILD_BUILD_DIR', 'CARGO_BUILD_TARGET_DIR', 'CARGO_TARGET_DIR',
                 'CARGO_BUILD_TARGET', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
                 'RUSTC', 'CARGO_BUILD_RUSTC', 'RUSTFLAGS'}
    conflicts = sorted(name for name in os.environ if name in forbidden
                       or name.endswith('_RUSTFLAGS') or name.startswith(('SCCACHE_', 'CCACHE_'))
                       or (name.startswith('CARGO_PROFILE_') and name not in
                           {'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG'}))
    if conflicts:
        raise ValueError('inherited build overrides prevent a matched cold run: ' + ', '.join(conflicts))
    image = [os.environ.get('ImageOS'), os.environ.get('ImageVersion')]
    if not all(image):
        raise ValueError('runner image identity is missing')
    source = command_output('git', 'rev-parse', 'HEAD')
    if source != os.environ.get('GITHUB_SHA'):
        raise ValueError('checkout does not match the workflow source SHA')
    available = sorted(os.sched_getaffinity(0))
    if len(available) < 2:
        raise ValueError('experiment requires at least two available CPUs')
    selected = available[:2]
    os.sched_setaffinity(0, selected)
    affinity = sorted(os.sched_getaffinity(0))
    if affinity != selected:
        raise ValueError('two-CPU affinity was not applied')
    # Resolve the installed toolchain before replacing Cargo's home; no downloads or cache reuse.
    active_toolchain = command_output('rustup', 'show', 'active-toolchain').split()
    if not active_toolchain:
        raise ValueError('installed active toolchain is missing')
    toolchain = active_toolchain[0]
    cargo = Path(command_output('rustup', 'which', 'cargo'))
    if not cargo.is_file():
        raise ValueError('installed Cargo executable is missing')
    os.environ.setdefault('RUSTUP_HOME', str(Path.home() / '.rustup'))
    os.environ['RUSTUP_TOOLCHAIN'] = toolchain
    os.environ['PATH'] = str(cargo.parent) + os.pathsep + os.environ['PATH']
    target = Path(tempfile.mkdtemp(prefix='bootstrap-profile-', dir=os.environ['RUNNER_TEMP']))
    cargo_home = Path(tempfile.mkdtemp(prefix='bootstrap-cargo-', dir=os.environ['RUNNER_TEMP']))
    target_empty = not any(target.iterdir())
    cargo_home_empty = not any(cargo_home.iterdir())
    if not target_empty or not cargo_home_empty or target == cargo_home:
        raise ValueError('cold target and Cargo cache must be distinct empty directories')
    os.environ['CARGO_TARGET_DIR'] = str(target)
    os.environ['CARGO_HOME'] = str(cargo_home)
    cpu_model = next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                      if ':' in line and line.split(':', 1)[0].strip() == 'model name'), '')
    if not cpu_model:
        raise ValueError('CPU model identity is missing')
    emit('identity', arm=mode, source_sha=source, runner_image=image, cpu_model=cpu_model,
         available_cpus=available, affinity=affinity, target=str(target), target_empty=target_empty,
         cargo_home=str(cargo_home), cargo_home_empty=cargo_home_empty, installed_toolchain=toolchain,
         rustc=command_output('rustc', '-vV'), cargo=command_output('cargo', '--version'),
         profile_debug=debug, incremental=os.environ['CARGO_INCREMENTAL'])
    started = time.monotonic()
    emit('started', command=['cargo', 'xtask', 'bootstrap'], elapsed_seconds=0.0)
    signals = {signal.SIGTERM, signal.SIGINT}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    # This Unix wrapper is single-threaded: restore the inherited mask before child exec,
    # while the parent keeps interruption blocked until it owns the child and its handlers.
    def restore_child_mask():
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    try:
        process = subprocess.Popen(['cargo', 'xtask', 'bootstrap'], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True,
                                   preexec_fn=restore_child_mask)
    except BaseException:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise

    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)

    handlers = {signum: signal.signal(signum, interrupted) for signum in signals}
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        for line in process.stdout:
            emit('output', elapsed_seconds=time.monotonic() - started, line=line.rstrip('\n'))
        status = process.wait()
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        stop_process_group(process)
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    exit_code = status if status >= 0 else 128 - status
    emit('finished', elapsed_seconds=time.monotonic() - started, exit_code=exit_code)
    return exit_code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f'bootstrap experiment: {error}', file=sys.stderr)
        sys.exit(2)
