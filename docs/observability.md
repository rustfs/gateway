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
| `gateway_form_claim_posture` | `info` | `posture` | message: the `FORM_CLAIM_POSTURE` line (ADR-0041) | once per assembly, only when a dialect installed a form claim |
| `gateway_presigned_expiry_posture` | `info` | `posture` | message: the `PRESIGNED_EXPIRY_POSTURE` line | once per assembly, only when a non-default presigned-lifetime rule is on |
| `gateway_profile_posture` | `info` | `posture` | message: the `PROFILE_POSTURE` line (rustfs/backlog#2751): every legacy RustFS reading the assembly applies, by the builder method that turns it on, `switches=[]` for none | once per assembly, last of the posture lines |
| `gateway_dangerous_assembly` | `warn` | `assembly` | `reason`: `custom_wall_clock`, `allow_all_authorizer`, `allow_all_authorizer_constructed` or `replaced_aws_signature_verifier`; message: the sentence the start-up log always carried | once per assembly, or per construction of the allow-all authorizer |
| `gateway_report_panicked` | `error` | `report` | `result = "contained"`, `callback`: `request observer` or `authorization audit sink`, `suppressed`; message | when a deployment's report callback panics, at most once per five seconds per callback, `suppressed` counting the panics since the last; the answer went out unchanged |
| `gateway_request_refused` | `warn` | `authentication` | `result = "refused"`, `request_id`, `operation` (`unknown` before routing), `status`, `code`; message | the signature, the credential, the signed-payload declaration, a POST policy or the security floor refused the request, the authenticator could not answer, or no verifier serves the request's custom scheme |
| `gateway_request_refused` | `warn` | `authorization` | `result = "refused"`, `decision` (`deny` or `indeterminate`), `authorization_stage` (`route` or `input`), `request_id`, `operation`, `action`; message | an authorization decision refused the request; `indeterminate` means the policy source could not answer |
| `gateway_request_refused` | `debug` | `governor` | as `authentication` (`code = "SlowDown"`) | a limiter refused the request before any expensive work, or its body outran its quota |
| `gateway_request_refused` | `debug` | `wire` | as `authentication` | the request head could not be accepted or routed, including an `OPTIONS` without `Origin` and a malformed CORS preflight |
| `gateway_request_refused` | `debug` | `decode` | as `authentication` | the query, headers, POST form or body could not be read into the operation's input, or the body failed its integrity check; a POST form its policy refuses (`403`) is `authentication`, and an `aws-chunked` chunk or trailer whose signature fails is too |
| `gateway_extension_panicked` | `error` | `extension` | `result = "contained"`, `extension` (`handler` or `authorizer`), `request_id`, `operation`, `suppressed`; message | a deployment's handler (or what runs inside its dispatch: its operation layers, the policy source's snapshot, the CORS source) or authorizer panicked, and the request was answered `500`; at most once per five seconds per extension, `suppressed` counting the panics since the last |

The posture lines keep their exact text — each module's unit tests pin its line, and
`scripts/check_sig_case_coverage.sh` pins the `SECURITY_POSTURE` format and the event that carries
it — and so do the dangerous-assembly sentences, less the `WARN:` prefix the level now carries; only
the way they reach a log changed. The same lines, in the order they were logged, are what
`S3Service::startup_posture` returns, so a host without a subscriber at assembly time can print
them through its own logger; `tests/tracing_events.rs` holds the two to each other, and
`docs/rustfs-profile.md` pins the RustFS profile's to a golden.

`rustfs-gateway-server`, the listener a deployment without one of its own can use, emits four
unstructured events under its module targets (`rustfs_gateway_server::…`): a TLS reload refused
(`error`), and a TLS handshake that timed out or failed and an HTTP connection closed with an error
(`debug`). RustFS serves the gateway from its own listener and never emits them.

### Refusals

One event per request the gateway itself refused, with the identifier the caller was answered with,
so a log line joins the observer's `RequestEvent`, the authorization audit sink's events and the
caller's `x-amz-request-id` — as long as nothing after the gateway rewrites that header: a host
that answers with an identifier of its own hands it to the gateway (rustfs/gateway#1150), so that
the gateway answers, and reports, with the same one. What is not reported:

- a refusal the deployment answered — its handler (a missing key, a failed precondition, including
  one over a body it never read) or one of its filters — which is the deployment's answer, not a
  refusal of the gateway's; and an allowed request;
- the authorization decision that only decides whether a missing object reads as missing or as
  denied (the `s3:ListBucket` visibility check `GetObject` asks): it is audited, and refuses nothing
  on its own;
- a CORS preflight the bucket's CORS configuration does not allow: that is the configuration's
  answer (a preflight without `Origin`, or malformed, is a `wire` refusal);
- a response the gateway could not complete for a reason of its own (an answer that breaks a
  response invariant, an internal inconsistency): answered `500`, and the host's completion log
  records it.

The levels follow RustFS's for the same classes. It logs a credential it cannot find, an unsigned
`x-amz-*` header and an unsupported algorithm at `warn`, an authorization denial at `warn`, its own
rate-limit refusals at `debug`, and a request its S3 stack cannot read not above `debug`. This crate
logs every authentication refusal at `warn` — a signature mismatch and an unreadable credential
included, one class — bounded by the limiter's admission of unauthenticated work; a limiter's own
refusals at `debug`, since shedding load must not cost a log line per request shed; and a panic at
`error`, at most once per five seconds per extension or callback with the count it stands for, as
RustFS bounds its own per-request `5xx` line (`LogThrottle`, `crates/utils/src/logging.rs:21-58`,
`rustfs/src/server/layer.rs:74`). The failure class of an authentication refusal is the code the
caller was answered with, and nothing finer: which rule refused a credential — expired, disabled,
bound to another token — is what the uniform `403` withholds, and a log line is not the place to
write it down.

`decision = "indeterminate"` is what the pipeline decides when the policy source could not answer,
what an authorizer may answer itself, and what an `x-amz-expected-bucket-owner` check that cannot be
settled comes to (no bucket to check, or an owner lookup that failed). A caller can produce the
last, so an alert on `indeterminate` reads the audit sink's event, joined by `request_id`, before
paging anyone.

These are the gateway's own events, under its own names. RustFS keeps emitting its own events from
its own code — the denial its authorizer decides, the credential its IAM lookup refuses, the
completion line of every request — so a RustFS dashboard counting those keeps counting the same
requests, and this crate's events add the stage the gateway refused at:

| RustFS event (rustfs/rustfs `3268c42e00`) | Level | The gateway's event for the same request |
| --- | --- | --- |
| `request_rate_limited` (`rustfs/src/server/rate_limit.rs:566`), RustFS's own API rate limit | `debug` | none from RustFS's limiter; `gateway_request_refused`, `governor`, `debug`, for the gateway's |
| `secret_key_lookup_failed` (`rustfs/src/auth.rs:238-265`), the credential store refused or could not answer | `warn` | `gateway_request_refused`, `authentication`, `code = "InvalidAccessKeyId"` (or `500 InternalError` when the store could not answer) |
| `sigv4_unsigned_amz_header` (`rustfs/src/auth.rs:1116`), an `x-amz-*` header outside the signature | `warn` | `gateway_request_refused`, `authentication`, the code the floor answered with |
| `s3_authorization_denied` (`rustfs/src/storage/access.rs:1147`), a policy denial | `warn` | `gateway_request_refused`, `authorization`, `decision = "deny"`; RustFS's own probe denials are `debug` (`:1134`), as the visibility check is not reported here |
| `http_request_completed` (`rustfs/src/server/layer.rs:481-539`), every request's status and duration | `info`, `error` for a 5xx | none: the gateway reports a request's completion to the `Observer` (`RequestEvent`), which RustFS's layer does not need |

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
it assembles, answers a signed request (`200`), refuses the same request with a forged signature
(`403`) and refuses a signed read at authorization (`403`), requires both refusal events, and scans
each field for the access key, the secret, the bucket and key the read named, any piece of an
`Authorization` value and any 64-digit hexadecimal run (a signature, the caller's or the computed
one), with a poison control emitted from inside the request path that proves the scan sees such a
field when one exists;
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
