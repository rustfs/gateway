# ADR-0013: Freeze committed response heads before detached work

- Status: Accepted
- Date: 2026-08-23
- Trigger: crate boundary
- Supersedes / Superseded by: none

## Context

`CompleteMultipartUpload`, `CopyObject`, and `UploadPartCopy` may report an error
document after a success status has been sent. Their operation specifications are
the only three with `allows_error_after_200 = true`. The response headers are part
of the committed answer, so values such as server-side encryption and version
identifiers must be known before the deferred work starts producing its terminal
document. The AWS `CompleteMultipartUpload` API description records this response
shape, and `rustfs/backlog#1701` fixes it as a protocol requirement rather than an
implementation option.

The current boundary cannot express that contract. `Resp::commit` accepts only a
future and records only a status. Both static dispatch paths await that future and
then run the ordinary output encoder, so the facade has no complete head to return
while the work is pending. `KEEPALIVE_BYTE` and its five-second interval exist, but
no response body writes the byte. Moving the future into the body without detaching
it would make backend progress depend on client reads and would cancel the work when
the body is dropped.

The final encoder also needs `MetaView<'_>`, which borrows the accepted request. A
deferred task must be `'static`; it cannot retain that view. The owned request can
cross the task boundary and the view can be rebuilt inside the task without adding
a reverse dependency or cloning request metadata.

References:

- <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html>
- <https://github.com/rustfs/backlog/issues/1701>

## Decision

Represent a committed response as a typed, frozen `HeadPart` plus detached
`CommitWork`. Expose `Resp::commit` only for operations carrying the
codegen-owned deferred-operation marker. The authoritative set is
`CompleteMultipartUpload`, `CopyObject`, and `UploadPartCopy`. Accept only typed
`HeaderName` and `HeaderValue` entries in `HeadPart`, validate their names
against the operation's generated response bindings, and finalize the status,
operation headers, framework headers, filters, and HTTP invariants before
spawning deferred work. The gateway facade moves the owned accepted request
into a Tokio task, rebuilds `MetaView` there, drives and contains the work
independently of the response body, encodes only the terminal document, and
sends that result through a one-shot channel. The response body sends the XML
prologue with the frozen head, emits no keep-alive byte before five seconds have
elapsed, emits one ASCII space every five seconds while the result remains
pending, and never polls the backend work itself. Dropping the response body
drops only its receiver and timers; the detached work continues unless an
explicit abort handle is used. The terminal encoder rejects any operation-header
set that differs from the frozen set and renders that mismatch as the late error
document under the already-committed status. `rustfs-gateway-core` remains
runtime-independent, `rustfs-gateway` owns the Tokio task and timer, and
`rustfs-gateway-server` remains a protocol-neutral consumer with no dependency
back into the facade.

## Evidence

Measured on `origin/main@ca2a9e5` with **rustc 1.97.1
(8bab26f4f 2026-07-14)** and **cargo 1.97.1
(c980f4866 2026-06-30)** on `darwin/arm64`.

| Fact | Command | Result |
|---|---|---|
| The protocol authority selects exactly three operations | `rg -l 'allows_error_after_200 = true' spec/operations/*.toml \| wc -l` | `3` |
| The three names are stable and reviewable | `rg -n 'allows_error_after_200 = true' spec/operations/*.toml` | `CompleteMultipartUpload`, `CopyObject`, `UploadPartCopy` |
| The public commit constructor carries no head | `rg -n 'pub fn commit\\(' crates/core/src/handler.rs` | one constructor whose only argument is `CommitWork<O>` |
| Static dispatch waits for the continuation before returning its committed outcome | `rg -n 'contain_committed_work\\(work\\)\\.await' crates/core/src/static_dispatch.rs crates/gateway/src/operation_mode.rs` | one wait in each dispatch path |
| The keep-alive byte has no driver | `rg -n 'KEEPALIVE_BYTE' crates/gateway/src --glob '*.rs'` | references are confined to `commit.rs`; the only executable use is its unit assertion |
| The facade already owns the required runtime primitives | `rg -n '^tokio =|^futures-timer' crates/gateway/Cargo.toml` | both are production dependencies |
| The request view is borrowed | `rg -n 'pub struct MetaView' crates/core/src/codec/view.rs` | `MetaView<'a>` stores references into the accepted request |

`[inferred]` Because the final encoder takes `&MetaView<'_>` and the spawned task
must be `'static`, the task must own the accepted request and rebuild the view; a
borrow or a cloned view cannot satisfy both signatures.

## Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| Keep awaiting the continuation before constructing `Response<Body>` | It cannot put a head or a keep-alive byte on the wire while work is pending; this is the measured current behavior. |
| Poll `CommitWork` from the response body's `poll_frame` | A slow reader then slows backend progress, and dropping the body cancels the operation at an arbitrary await point. |
| Build the head from the terminal output | It repeats the existing defect: headers do not exist until the deferred result exists, so nothing complete can be committed early. |
| Let a backend write raw header bytes | It bypasses `HeaderValue` validation and the generated operation binding set, reopening the response-splitting and silent-header-loss paths. |
| Store or clone `MetaView` into the detached task | The view is a borrow, not owned metadata. Cloning individual fields creates a second request parser and can drift from the codec's view. |
| Use `tokio::time::interval` directly | Its first tick is immediately ready, so a fast completion gains an unnecessary whitespace frame and the documented five-second start threshold is false. |
| Add a `rustfs-gateway-server -> rustfs-gateway` dependency for spawning | The server crate is protocol-neutral and already runs arbitrary tower services. The facade already has Tokio and timer dependencies, so reversing this boundary buys no capability. |

## Consequences

- The implementation changes a public handler constructor and therefore follows
  ADR-0004's versioning rules. Existing settled and event-stream responses keep
  their current shape; only committed-response callers migrate.
- Registration fails when an operation outside the three codegen-authoritative
  names exposes a committed response. A name check written by hand in the facade
  is not an acceptable substitute.
- A committed response with an invalid, unbound, or incomplete `HeadPart` fails
  before the work is spawned. After the head is returned, no path may mutate its
  status or operation headers.
- The response body owns only the prologue, keep-alive timer, and result receiver.
  The task owns the continuation and the accepted request. This ownership split is
  enforced by real-socket tests where the client stops reading and where it sends
  RST, plus a body-drop contract test that observes backend completion.
- The timing contract is byte-based, not wall-clock performance gating: paused
  time proves no early tick and exact five-second ticks deterministically; CI does
  not compare elapsed wall time.
- `scripts/check_role_verdicts.sh`, the generated operation-contract checks, and
  the committed-response conformance ledger remain the blocking guardrails. The
  implementation must add mutations for an extra allowed operation, a missing
  frozen header, an immediate first tick, body-drop cancellation, and polling work
  from the body.
