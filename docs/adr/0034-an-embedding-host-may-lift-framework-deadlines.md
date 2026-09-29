# ADR-0034: An embedding host may lift the framework's handler, continuation and body deadlines

- Status: Accepted
- Date: 2026-09-30
- Trigger: axiom A3, because whether the framework may cancel a handler, drop a committed continuation or refuse a body for time is an ordering contract ADR-0011 fixed as always bounded; a host now decides it per deadline.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0011 and leaves its text unchanged. ADR-0011 gives every operation a closed
deadline class and maps each class to a validated, non-zero duration, so a handler that runs too
long is always signalled, given a cleanup grace, and then abandoned. The committed-continuation
bound (`try_with_commit_progress`) and the request-body deadlines (first byte, between reads, and
the throughput floor) follow the same rule: zero is refused, and every one of them always arms a
timer.

RustFS embeds the gateway in its own listener, and the gateway replaces the legacy stack for the
operations it serves. Legacy RustFS bounds none of these: its external S3 middleware stack has no
timeout layer (`rustfs/src/server/http.rs:2044-2072` on rustfs/rustfs `1e7065101d`; only the
console gets one, `rustfs/src/admin/console.rs:625`), it answers `CompleteMultipartUpload` once
the completion has run (`rustfs/src/app/multipart_usecase.rs:889-903`), and its one body idle
bound, `RUSTFS_HTTP_REQUEST_BODY_READ_TIMEOUT`, is applied inside RustFS's own `PutObject` and
`UploadPart` handlers (`rustfs/src/app/object/put.rs:127-160`), which keep applying it behind the
gateway. Under the shipped deadlines a server-side copy is cancelled after about 31 s, a
committed continuation is dropped mid-write after 60 s, and a body that pauses for 30 s is refused,
where legacy RustFS finishes all three (rustfs/backlog#1677 ruling R15). A very long duration
behaves the same in practice, but it still arms a timer and still describes a bound the host does
not have; the host asked for exactly legacy's behaviour, not a larger number.

## Decision

A host may lift each of these deadlines explicitly: `HandlerDeadlineConfig::without_deadline(class)`
for either class, `HandlerDeadlineConfig::without_commit_progress_deadline()`,
`RequestBodyDeadlineConfig::without_idle_deadlines()` and
`RequestBodyDeadlineConfig::without_throughput_floor()`. A lifted deadline has the length
`NO_DEADLINE` (`Duration::MAX`), so every accessor keeps answering a `Duration` and every
existing contract that reads one is unchanged; the framework arms no timer for it. A lifted handler
class is never signalled for time; a lifted continuation bound wraps the continuation in nothing; a
lifted body deadline or floor never refuses a body for time or rate.

Zero is still refused everywhere and is never an alias for "lifted". The shipped defaults stay
bounded. Nothing else changes: the operation classes stay closed, a request the transport abandons
is still cancelled with its cleanup grace, and the byte ceilings still bound a body's size.

## Evidence

- `crates/gateway/tests/host_deadlines.rs` runs the same staged write — `CopyObject`,
  `UploadPartCopy`, `DeleteObjects`, `CompleteMultipartUpload`, `PutObject` — under a bounded
  deadline, where it is cancelled mid-write and rolled back with nothing left staged or committed,
  and under the lifted settings, where it finishes whole; the same for a committed continuation and
  for a body that pauses before each half.
- `lifted_deadlines_arm_no_timer` in the same file counts heap blocks: a warm signed `PutObject`
  allocates eight fewer blocks per request under the lifted settings — the four timers the shipped
  deadlines arm, two blocks each — measured at 7.9–8.2 per request over six runs on macOS.
- `wire_read::lifted_deadline_tests` observes that a lifted idle deadline leaves the awaited
  frame with no timer on every poll, and `request_deadline::lifted_deadline_tests` that a lifted
  continuation bound returns the backend's future itself.
- `compat/sut` (the RustFS-profile assembly) lifts all of them (`rustfs_service_config`).

## Rejected alternatives

| Alternative | Why not |
| --- | --- |
| Keep "a very long duration" as the host's spelling | It arms a timer and names a bound the host does not have; RustFS asked for exactly legacy's behaviour, and a reader of the settings cannot tell a deliberate absence from a large number |
| `Option<Duration>` on every accessor | Every existing deadline accessor, guard and test reads a `Duration`; changing all of them buys no behaviour the lifted length lacks |
| A third operation class, `Unbounded` | ADR-0011 keeps the operation classes closed and describing the operation; whether a host bounds a class is deployment policy, not a property of the operation |
| Zero as "lifted" | The existing contract refuses zero precisely so that a mistyped zero is never read as "no limit" |

## Consequences

- An embedding host that lifts a deadline owns the bound: a stuck backend call or a stalled body
  holds its task and buffers until the connection drops, exactly as in legacy RustFS. The RustFS
  profile records that as a Legacy-compat item (rustfs/backlog#2684).
- A generic deployment is unaffected unless it calls one of the four methods.
