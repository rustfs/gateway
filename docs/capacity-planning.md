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
If a later layer refuses, earlier charges are returned. An authenticated request does not consume
these meters; authenticated identity quotas belong after authentication.

The client key comes only from a `ClientAddr` request extension inserted by the listener or a
trusted-proxy adapter. The gateway never reads `X-Forwarded-For`. Requests without a trusted peer
address share one unknown-client meter.

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

`governor(custom)` adds a deployment governor after the mandatory one. Both must admit. Even
`governor(Unlimited)` leaves the framework limits in force, so an extension cannot silently remove
the security floor.

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

## What this does not do

- It does not share limits across processes. A fleet of `n` gateways has `n` independent budgets.
- It does not meter body bytes. `rustfs_gateway_http::Limits` owns byte ceilings.
- It does not queue. Refusal is immediate rather than allowing callers to choose queued memory.
- It does not trust forwarding headers. A proxy must validate its trust boundary before inserting
  `ClientAddr`.
- It does not replace post-authentication quotas. Use an `Authorizer` or deployment governor for
  tenant, identity, or key-specific policy.

Refill uses a monotonic clock, so wall-clock adjustment cannot refill a rate bucket. Wall time is
captured separately for signature expiry. A custom wall clock more than 60 seconds from the system
clock is rejected at assembly unless the deployment supplies the explicit replay-risk
acknowledgement; the service posture reports which choice was made.
