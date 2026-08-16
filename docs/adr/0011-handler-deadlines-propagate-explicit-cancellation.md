# ADR-0011: Handler deadlines propagate explicit cancellation

- Status: Accepted
- Date: 2026-08-16
- Trigger: RustFS Gateway axiom A3 (ordering contracts are fixed by types)
- Supersedes / Superseded by: none

## Context

The request pipeline owns five idle deadlines before and around handler execution: the server owns
header-read, write-progress, and keep-alive; the body gate owns first-byte and between-read idle.
The sixth layer, handler execution, has no owner. The current gateway awaits the erased operation
future directly. A connection-lifetime limit is an additional safety valve, not an operation
deadline, and dropping a handler future does not tell the handler why work stopped or prove that a
storage transaction rolled back.

Operation durations are not interchangeable. A normal read needs a short bound while a complete
multipart operation may legitimately run much longer. The deadline therefore belongs to the
operation contract, while the runtime policy maps that contract to a duration. Cancellation must
cross the core-facade boundary because the handler is the only layer that can roll back its own
side effects.

## Decision

Give every `Operation` an explicit closed deadline class; no implicit or unlimited class is
permitted. The request configuration maps each class to a validated, non-zero duration. Start that
duration immediately before invoking the typed handler, after routing, body admission, decoding,
and authorization have completed.

Pass one framework-created `HandlerContext` beside `Req<O>` when invoking `Handler<O>`. The context
owns a cloneable cancellation token that exposes cancellation as an awaitable signal and records
`HandlerCancellation::Deadline` as the cause. Keeping execution state outside `Req<O>` preserves
ADR-0010's boxed input and exact request-layout contract. When the deadline wins, the gateway first
signals the token, then continues polling the handler for a bounded cleanup grace. A cooperative
handler observes the signal, rolls back, and returns; its result is discarded. After the deadline
wins, no handler response may be encoded or committed.

Expiry without a handler acknowledgement is containment, not successful rollback. After the
cleanup grace the gateway closes the response path, records an unacknowledged cancellation, and may
drop the remaining future. Tests and reports must distinguish acknowledged rollback from this
fallback. The implementation remains runtime-independent and must not require Tokio in the public
core or facade contract.

## Evidence

Measured on `rustc 1.97.1 (8bab26f4f 2026-07-14)` at gateway main
`a6c6ad930b3b33709a751b681962c4be59e54dc3`.

- `scripts/check_timeout_layer_ownership.sh` reported
  `OK: 3/6 timeout layers owned by rustfs-gateway-server; connection lifetime is an extra safety valve`.
  The three remaining owners are not server responsibilities.
- `rg -n 'deadline_class|handler deadline|handler_deadline|CancelToken|CancellationToken|cancel\('
  crates/gateway/src crates/core/src crates/server/src` found only the server module statement that
  handler deadlines are out of scope. No request-scoped cancellation token or operation deadline
  class exists.
- `crates/gateway/src/service.rs` awaits `catch_boxed_future(|| execution).await` before matching the
  handler result. There is no deadline race or cancellation acknowledgement on that path.
- `cargo test -p rustfs-gateway-core --test integration dto_cold_split -- --nocapture` passed both
  existing request-layout tests in 11.00 seconds wall time. Cancellation state must therefore stay
  outside `Req<O>` unless a later ADR deliberately supersedes that exact layout.
- [inferred] A future that is only dropped cannot produce an observable rollback acknowledgement;
  an explicit signal and a separately observed rollback marker are required to distinguish cleanup
  from abandonment.

## Rejected alternatives

- Use connection lifetime as the handler deadline: it starts at the wrong boundary and would turn a
  valid long-running operation into a connection-age failure.
- Apply one duration to every operation: it either kills complete-multipart work or leaves ordinary
  reads with an unnecessarily large denial-of-service window.
- Drop the handler future at expiry: it provides no cancellation cause, no cleanup grace, and no
  evidence that the handler rolled back.
- Commit a result returned after expiry: scheduling would decide whether a timed-out side effect is
  externally visible. The deadline verdict must be terminal for the response path.
- Use `tokio::time::timeout` or spawn a detached cleanup task: the facade is runtime-independent and
  cannot require downstream users to run Tokio.
- Store the cancellation token inside `Req<O>`: that silently breaks ADR-0010's exact request-layout
  contract. A separate handler context carries execution state without making request data larger.

## Consequences

- Adding `HandlerContext` to `Handler::call` and the deadline class to `Operation` changes public
  core contracts. The implementation PR advances the affected versions and documents a `BREAKING`
  migration for handler implementations and custom operations.
- Generated standard operations must declare a deadline class explicitly. Code generation and a
  census guard reject missing, duplicate, or unlimited declarations.
- `scripts/check_timeout_layer_ownership.sh` must name all six owners and must gain mutations for a
  missing handler owner and for counting connection lifetime as one of the six.
- `c-lim-0063` must observe the token inside a real handler, complete a rollback marker before the
  cleanup grace, and prove that no post-deadline response or side effect is committed. Mutations must
  cover skipping the signal, dropping without grace, accepting a late result, and changing the
  operation deadline class.
- The form, load, and final limits-ledger slices remain separate work.
