# Observability

What the gateway tells an operator, and in what shape: the `tracing` events it emits, and how an
embedding host turns them into its own logs. RustFS is the host this shape is chosen for; any host
that installs a `tracing` subscriber reads the same events.

[docs/middleware.md](middleware.md) covers the read-only `Observer` and when to use it instead of a
filter; [docs/security-model.md](security-model.md) covers what a refusal may and may not say to the
caller, which bounds what an event may say to an operator.

## No stdout, no stderr

The runtime crates never write a line of their own to stdout or stderr. A line the host cannot
route, filter, raise, lower or silence is a line that ends up in the wrong place: in RustFS's case,
outside its logging pipeline, its JSON output and its log exporter. Every diagnostic is a `tracing`
event instead, and the host's subscriber decides where it goes. Without a subscriber nothing is
written, which is what a library owes a process it did not start.

`clippy::print_stdout`, `clippy::print_stderr` and `clippy::dbg_macro` are denied outside tests in
`rustfs-gateway`, `rustfs-gateway-core`, `rustfs-gateway-server`, `rustfs-gateway-stream` and the
add-ons `dialect-rustfs-admin`, `dialect-minio` and `fs` (`#![cfg_attr(not(test), deny(...))]` in each
`lib.rs`), so a print cannot come back unnoticed there. The protocol crates `http`, `sig`, `types`
and `xml` write nothing either, but do not declare the lint yet. Only `rustfs-gateway` and
`rustfs-gateway-server` emit events at all. CI's clippy run builds default features, so the
`dangerous-*` code paths are linted only by `cargo clippy -p rustfs-gateway --all-features
--all-targets`.

## Shape

Every event of the `rustfs-gateway` crate has:

- the target `rustfs_gateway`, so `RUST_LOG=rustfs_gateway=debug` (or the host's equivalent) raises
  or lowers this crate alone;
- `event`, `component` and `subsystem` as its first fields, in that order — RustFS's own field order
  (rustfs/rustfs `.agents/skills/rustfs-logging-governance/SKILL.md`), so a RustFS filter or alert
  written for its own events selects these unchanged;
- `component = "gateway"` on every event;
- a `result` or `reason` next, when the event has one, then context, then the message: a short
  sentence, or, on a posture event, the start-up line itself. `tracing` records the message ahead of
  the named fields whatever the call site's order; RustFS's own formatters print it first too.

The level follows RustFS's policy: `error` for a failure that affects behaviour or security,
`warn` for a degraded or operator-actionable state, `info` for a low-frequency lifecycle or mode
change, `debug` and `trace` for diagnostics.

## Events

| `event` | Level | `subsystem` | Fields after the first three | When |
| --- | --- | --- | --- | --- |
| `gateway_security_posture` | `info` | `posture` | message: the `SECURITY_POSTURE` line | once per assembly (`ServiceBuilder::build`) |
| `gateway_dialect_posture` | `info` | `posture` | message: the `DIALECT_POSTURE` line (ADR-0024) | once per assembly |
| `gateway_naming_posture` | `info` | `posture` | message: the `NAMING_POSTURE` line | once per assembly |
| `gateway_presigned_expiry_posture` | `info` | `posture` | message: the `PRESIGNED_EXPIRY_POSTURE` line | once per assembly, only when a non-default presigned-lifetime rule is on |
| `gateway_dangerous_assembly` | `warn` | `assembly` | `reason`: `custom_wall_clock`, `allow_all_authorizer`, `allow_all_authorizer_constructed` or `replaced_aws_signature_verifier`; message: the sentence the start-up log always carried | once per assembly, or per construction of the allow-all authorizer |
| `gateway_report_panicked` | `error` | `report` | `result = "contained"`, `callback`: `request observer` or `authorization audit sink`; message | each time a deployment's report callback panics; the answer went out unchanged |

The posture lines keep their exact text — each module's unit tests pin its line, and
`scripts/check_sig_case_coverage.sh` pins the `SECURITY_POSTURE` format and the event that carries
it — and so do the dangerous-assembly sentences, less the `WARN:` prefix the level now carries; only
the way they reach a log changed.

`rustfs-gateway-server`, the listener a deployment without one of its own can use, emits four
unstructured events under its module targets (`rustfs_gateway_server::…`): a TLS reload refused
(`error`), and a TLS handshake that timed out or failed and an HTTP connection closed with an error
(`debug`). RustFS serves the gateway from its own listener and never emits them.

## What no event carries

A header value, a query string, a body byte, an access key, a secret, a session token, a signature,
a string to sign or a canonical request, or a customer key. Fields are identifiers the gateway
minted or validated, names from its own vocabulary, and counts. A report callback's panic payload
is deployment text and is in no event; the process's panic hook still sees the panic, as it sees
every panic, and what it does with the payload is the host's to decide (Rust's default hook prints
it on stderr).

Three guards hold this: `scripts/check_secret_hygiene.sh` refuses a formatting or logging macro under
`crates/gateway/src/` that names key material anywhere in its invocation, fields on lines of their
own included; `crates/gateway/tests/tracing_events.rs` captures every event the facade emits while
it assembles, answers a signed request (`200`) and refuses the same request with a forged signature
(`403`), and scans each field for the access key, the secret, any piece of an `Authorization` value
and any 64-digit hexadecimal run (a signature, the caller's or the computed one), with a poison
control emitted from inside the request path that proves the scan sees such a field when one exists;
and the lints above keep every diagnostic on this one path.

## A host's subscriber

RustFS installs its own subscriber and receives these events with the rest of its logs, at the levels
its filter lets through. Its default level is `error` (`RUSTFS_OBS_LOGGER_LEVEL`, rustfs/rustfs
`crates/config/src/constants/app.rs:29`), which leaves out the posture events and a dangerous
assembly's `warn` exactly as it leaves out RustFS's own `warn` for a disabled security control
(`tls_verification_disabled`, `rustfs/src/admin/router.rs:794`). A deployment that wants them adds a
directive for this crate's target, for example `RUSTFS_OBS_LOGGER_LEVEL=error,rustfs_gateway=info`
or the same in `RUST_LOG`, which RustFS prefers when it is set (`crates/obs/src/telemetry/filter.rs`,
`build_env_filter`).

A launcher with no subscriber of its own installs any it likes; `compat/sut` prints every event at
`info` or above as one line on stderr (`compat/sut/src/logging.rs`), which keeps the start-up report
in every suite run's log.
