# Capacity planning

The gateway installs a pre-authentication rate limiter even when a deployment configures nothing.
It bounds requests before credential lookup, CORS storage access, or body reads. Byte limits,
connection back-pressure, and authenticated quotas are separate controls.

## Shipped limits

`GovernorRates::default()` defines five token buckets and one memory bound:

| Layer | Key | Burst | Per second |
| --- | --- | ---: | ---: |
| Aggregate | process | 4096 | 2048 |
| Per client | IPv4 `/32` or IPv6 `/64` | 256 | 128 |
| Credential lookup | class | 128 | 64 |
| CORS preflight | class | 128 | 64 |
| Unauthenticated | class | 256 | 128 |
| Tracked clients | bounded address table | 4096 entries | — |

A pre-authentication request must pass the aggregate meter, its class meter, and its client meter.
If a later layer refuses, earlier charges are returned. Every request is classified before
authentication, so the limiter never sees an identity; per-identity quotas belong in the
`Authorizer`, which runs after the identity is known. A layer configured with `Rate::none()` is
named in `SecurityPosture` as a closed pre-authentication layer.

The meters count unverified work only. Once a request's signature verifies, the service reports it
through `Governor::verified` and the framework returns its charge to all three meters, so what
stays counted is a request still waiting for its verdict, a request whose authentication failed,
and a request that presented no credentials. A verified client is therefore never capped by these
rates, while the work a caller without a secret can force is bounded exactly as before. A
deployment governor installed with `governor(custom)` hears the same report; the trait's default
does nothing, so whatever a deployment governor counted stays counted unless it overrides the hook.

The client key comes only from a `ClientAddr` request extension inserted by the listener or a
trusted-proxy adapter. The gateway never reads `X-Forwarded-For`. Requests without a trusted peer
address share one unknown-client meter. The address is canonicalised before it is keyed: a
dual-stack listener reports an IPv4 client as an IPv4-mapped IPv6 address, and that client is
metered as its IPv4 `/32`, not as one member of the `/64` every mapped address shares.

The address table is split across 32 locks. At capacity, the least-recently-used entry in the
selected shard is replaced and its token debt is transferred to the new key. Address rotation
therefore cannot turn eviction into a fresh burst.

## Tuning

Tune the mandatory limiter with `framework_governor_rates`:

```rust
use rustfs_gateway::{GovernorRates, Rate, ServiceBuilder};

let service = ServiceBuilder::new()
    // ...operations, authenticator, authorizer...
    .framework_governor_rates(GovernorRates {
        aggregate: Rate::new(16_384, 8_192),
        ..GovernorRates::default()
    })
    .build();
```

| Change | Effect | Risk |
| --- | --- | --- |
| Raise `aggregate` | More total pre-authentication work | The process may exhaust CPU or workers before limiting |
| Raise `per_ip` | More traffic from one trusted peer key | A single source can consume more of the aggregate budget |
| Raise `credential_lookup` | More signed-looking requests reach authentication | More credential-provider work can be forced without valid credentials |
| Raise `cors_preflight` | More browser preflights reach CORS lookup | More unauthenticated storage reads can be forced |
| Raise `unauthenticated` | More anonymous routed work | More requests can reach the body boundary |
| Raise `tracked_clients` | More exact client meters | More memory can be occupied by peer keys |
| Set a layer to `Rate::none()` | Close that layer | Every request in its path receives `503 SlowDown` |
| Set a layer to `Rate::unlimited()` | Lift that layer: it admits without counting and keeps no state | Nothing bounds the work that layer bounded; the posture names it |

A class meter shared by every peer can be drained by one peer that sends failing requests faster
than the class refills. Keep a bounded class's refill above `per_ip`'s, so that one peer key alone
cannot empty it for everyone else.

`governor(custom)` adds a deployment governor after the mandatory one. Both must admit. Even
`governor(Unlimited)` leaves the framework limits in force, so an extension cannot silently remove
the security floor.

## Embedded in RustFS

RustFS embeds the gateway service in its own listener. Legacy RustFS applies no pre-authentication
limit: its optional per-client limit (`RUSTFS_API_RATE_LIMIT_*`, off by default) is a host layer in
front of both stacks. The RustFS profile therefore lifts every framework layer, so that none refuses
a request legacy RustFS answers, and takes any bound from RustFS configuration instead:

```rust
use rustfs_gateway::{GovernorRates, Rate};

let rates = GovernorRates {
    aggregate: Rate::unlimited(),
    per_ip: Rate::unlimited(),
    credential_lookup: Rate::unlimited(),
    cors_preflight: Rate::unlimited(),
    unauthenticated: Rate::unlimited(),
    tracked_clients: GovernorRates::default().tracked_clients,
};
// builder.framework_governor_rates(rates)
```

`Rate::unlimited()` is not a large rate. The widest finite rate, `Rate::new(u32::MAX, u32::MAX)`,
is still a limit — frozen at one instant it admits about four million requests and refuses the next
— and it still keeps a token count and an address entry per peer. An unlimited layer admits without
counting, keeps no state, and is named in `SecurityPosture` (`per-IP bucket: unlimited`,
`unlimited pre-authentication layers: ...`), so the absence of a limit is a stated configuration
rather than a number that looks like one. Only the assembly's own `framework_governor_rates` can
lift a layer; a deployment governor is still ANDed after the framework one. `compat/sut`, the
RustFS-profile assembly, lifts all five.

The host inserts `ClientAddr` on every request from the address it already trusts for its own
per-client limit: the trusted-proxy layer's client address when there is one, otherwise the
accepted socket's peer. An operator who opts into a bound — for instance on failed signatures —
sets `credential_lookup` and `per_ip` from RustFS configuration to finite rates, keeping the class
refill above the per-client refill as described under Tuning. Because a verified request returns
its charge, such a bound limits forged and failing requests without capping valid signed traffic.

## Refusal and performance contracts

Every refusal is the same fixed response: HTTP `503`, S3 code `SlowDown`, no `Retry-After`, and no
request-derived content. A caller cannot learn which meter is full or its refill rate.

The built-in `DefaultGovernor::try_acquire_sync` path allocates nothing. Aggregate and class meters
use atomic compare-and-swap; only one client shard is locked. The protected object-safe `Governor`
trait still returns `BoxFuture`, so dispatch through that existing extension boundary allocates the
future box. Removing that boundary allocation would require a breaking trait change.

## Connection memory

`rustfs_gateway_server::conn_memory_budget(n)` is `n x 408 KiB`. The per-connection figure is
Hyper's HTTP/1 read-buffer ceiling, `8 KiB + 4 KiB x 100`, which is what one connection can hold
open at the parser alone; ten thousand connections is therefore a four-gibibyte planning number,
not a four-gibibyte allocation.

The budget is measured, not asserted. Two cases in `crates/server/tests/server_load.rs` read the
process resident set through `ps` in an isolated child:

| Case | Load | Observed growth | Budget |
| --- | --- | ---: | ---: |
| `c-lim-0006` / `a-srv-0008` | 1,000 open connections, one in ten mid-request | ~19 MiB | 408 MiB |
| `c-lim-0061` / `a-srv-0026` | 1,000 readers parked on a stalled response | ~39 MiB | 408 MiB |

Both cases then run three further identical waves and require their average cost to stay below a
fraction of the first. That is deliberately a *reuse* measurement and not a return-to-baseline one:
a freed allocation is not a shrinking resident set, since the allocator may keep the pages — and
on macOS it does. "Resident memory came back down" is a claim that harness cannot make honestly,
while "later waves keep getting cheaper" is one it can, and it is the claim an unbounded-growth
defect actually fails. A retained, incompressible ballast first proves that the host's RSS
instrument can see accumulation; otherwise the reuse result is reported as unmeasurable instead
of passing.

What the slow-reader case additionally observes is that the parked wave is not paid for by the
traffic beside it: a healthy connection's p99 is sampled with the wave parked and without it, and
the loaded reading must stay inside eight times the unloaded one. Measured on a four-worker
runtime, that is single-digit milliseconds against a low-single-digit-millisecond baseline. On a
single-worker runtime the same load pushes p99 past 200 ms, which is the reason the case pins its
runtime flavour rather than inheriting the default.

## Response write strategy

`ServerConfig::write_strategy = WriteStrategy::Disabled` passes `writev(false)` to Hyper's HTTP/1
builder. Hyper calls that internal mode `WriteStrategy::Flatten`: response head and body fragments
are copied into one contiguous connection buffer before the socket write. This can help an I/O
adapter that handles vectored writes poorly, but it adds user-space copies and can grow the buffered
working set up to `h1_max_buf_size`; it must not be used to claim a zero-copy file response.

`WriteStrategy::Enabled` forces Hyper's queued vectored-write mode, while `Auto` lets Hyper inspect
the concrete I/O transport. These settings apply only to the Hyper assembly. The plaintext
self-held HTTP/1 driver negotiates a `FileRegion` separately and reports completed kernel-transfer
calls and bytes; TLS, HTTP/2, verification obligations and unsupported platforms stay on a named,
byte-counted user-space fallback.

A handler answers with a file region through `ByteStream::from_file_region`. On the self-held
driver it leaves through `sendfile`. On every other path — the Hyper driver, TLS, HTTP/2, an
in-process `call_bytes` caller — `S3Service` copies it on the blocking pool in 64 KiB reads and
records one `adapt_copies_total` of the region's length plus one `zero_copy_refusals` with the
reason (`tls-in-path`, `http2-in-path`, `transport-lacks-sendfile`, or
`verification-obligation-present`). The copy is streamed, so its resident cost is one read buffer,
not the object.

Dedicated 1 GiB RSS and syscall measurements belong to rustfs/backlog#1766, as recorded by
ADR-0014. They are not wall-clock gates on shared runners.

## What this does not do

- It does not share limits across processes. A fleet of `n` gateways has `n` independent budgets.
- It does not meter body bytes. `rustfs_gateway_http::Limits` owns byte ceilings.
- It does not queue. Refusal is immediate rather than allowing callers to choose queued memory.
- It does not trust forwarding headers. A proxy must validate its trust boundary before inserting
  `ClientAddr`.
- It does not replace post-authentication quotas. Use an `Authorizer` or deployment governor for
  tenant, identity, or key-specific policy.

Refill uses a monotonic clock, so wall-clock adjustment cannot refill a rate bucket. Wall time is
captured separately for signature expiry. A custom wall clock can only be installed with
`clock_with_skew_ack` and its explicit replay-risk acknowledgement, whatever its reading at
assembly: a source that is correct at `build()` and then freezes would keep every captured
signature valid. `SecurityPosture` and the start-up log name a custom wall clock.

## Measured transfer costs

Recorded by `.github/workflows/perf-evidence.yml` on the org `sm-standard-4` runner (Intel Xeon
6973P-C, 32 vCPU, 64 GiB, Linux 6.8 x86_64), runs 36391443781 and 36393972731. The runner is shared,
so the elapsed-time columns are records, not gates; the byte, syscall and memory columns are
asserted by the workflow on every run.

| Case | Bytes through `sendfile` | Bytes through `write`-family syscalls | Resident peak growth | Throughput |
| --- | ---: | ---: | ---: | ---: |
| 1 GiB GET, self-held driver | 1,073,741,824 | 7,042 / 7,178 (heads only) | 3.0 MiB | 730 MiB/s |
| 1 GiB GET, self-held driver forced to copy | 0 | 1,073,873,359 | 2.8 MiB | 133 MiB/s |
| 1 GiB PUT, self-held driver | — | — | 3.7 MiB (19 KB allocated in total) | 245 MiB/s |
| 1 GiB PUT, Hyper driver | — | — | 4.0 MiB (866 KB allocated in total) | 403 MiB/s |

A healthy client beside 102 slow clients that keep progressing (a third trickling a head, a third a
body, a third reading one byte a second) kept its p99 at 0.977x and 1.020x of an idle control
listener probed in lock-step (median of five rounds of 2,000 probes each).

The per-request allocation ceilings are 148 blocks for a warm signed `GetObject` and 195 for a
`PutObject` (`crates/gateway/tests/steady_state_allocations.rs`); rustfs/gateway#1012 tracks
reducing them.

