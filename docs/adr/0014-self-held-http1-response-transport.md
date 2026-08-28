# ADR-0014: Self-held HTTP/1.1 response transport

- Status: Accepted
- Date: 2026-08-28
- Trigger: crate boundary
- Supersedes / Superseded by: none

## Context

`rustfs-gateway-stream` already represents response bodies as typed `Payload` values and owns
`PayloadCaps`, `TransportCaps`, `FileRegion`, `ZeroCopyQuery`, `NoZeroCopy`, and `StreamMetrics`.
That vocabulary can prove whether a body is eligible for a kernel-side transfer and can attribute a
refusal, but no production transport consumes it. The generic server currently gives every accepted
connection to Hyper, and the facade's dependency on `rustfs-gateway-server` is test-only. Hyper is
the correct default for TLS, HTTP/2, and embedding, but its response-body contract cannot hand a file
descriptor and socket to one kernel transfer operation.

A transport cannot inspect one response, recover a socket that Hyper already owns, and then return
that connection to Hyper without duplicating or corrupting the HTTP/1.1 keep-alive state machine.
The ownership choice therefore happens when a connection is assembled, not after its first file
response is produced. An optional self-held plaintext HTTP/1.1 assembly must drive every response on
that connection: eligible `Payload::File` bodies use a real platform implementation; every other
body uses an observed read/write fallback. TLS and HTTP/2 remain on Hyper.

The self-held assembly changes a crate dependency direction and spans a generic runtime boundary.
It must reuse the existing listener, admission, shutdown, request acceptance, `S3Service`, response
invariants, and stream capability authorities. It must not turn the conformance runner's test-side
`conn` client into evidence for a production response writer. See
<https://github.com/rustfs/backlog/issues/1740>.

## Decision

Keep `rustfs-gateway-stream` as the sole owner of payload and transport capability vocabulary; do
not duplicate those types in core, server, or facade. Keep Hyper as the default production driver
and as the only TLS and HTTP/2 driver. Add an explicit accepted-connection driver seam to
`rustfs-gateway-server` without adding an internal gateway dependency, and add a normal
`rustfs-gateway -> rustfs-gateway-server` dependency so the facade can provide a production
self-held plaintext HTTP/1.1 driver beside the existing Hyper driver. Select a driver once per
listener, never once per response; every accepted connection inherits its listener's driver. A
self-held listener rejects TLS, HTTP/2, and h2c configuration at assembly, and an HTTP/2 client
preface sent to it is refused rather than handed to another driver. A mixed-protocol deployment uses
a separate Hyper listener. The self-held HTTP/1 parser validates only parser-level syntax and
framing, preserves the accepted method, target, version, and duplicate headers losslessly, and
constructs the request carrier without interpreting S3 policy. One shared transport-facing service
seam then invokes `S3Service`; its existing pipeline performs the single authoritative
`WireRequest::accept` pass, finalizes the same `Response<Body>`, announces the connection verdict,
and exposes whether the socket must really close. Neither driver may bypass or duplicate that seam.
Self-held code is limited to HTTP/1.1 syntax/framing, socket progress, and response-payload transfer.
It advertises only capabilities backed by a real implementation on that
build and connection and uses `Payload::try_into_file_region_for` before a kernel transfer. Existing
`StreamMetrics` remain the authority for payload adaptation and zero-copy refusal. A facade-owned
`ResponseTransportMetrics` records exactly one connection-path selection, exactly one named fallback
per response that leaves the preferred transfer path, copied payload bytes from completed read/write
operations, and bytes returned by successful kernel-transfer syscalls; intended lengths are never
counted. The self-held driver handles non-file responses and unsupported platforms with that
observed read/write path on the same connection. It never advertises unrealized `SPLICE` or
`URING_ZC` bits, and it does not add an RDMA bit. Both production drivers run the same conformance
cases, including the same request-smuggling, connection-verdict, and response-invariant controls,
and transport comparison fails on any semantic result difference.

## Evidence

Measured on `origin/main@4adf155` with **rustc 1.97.1
(8bab26f4f 2026-07-14)** and **cargo 1.97.1
(c980f4866 2026-06-30)** on `Darwin/arm64`.

| Fact | Command | Result |
|---|---|---|
| The zero-copy vocabulary has one crate owner | `rg -n 'pub struct TransportCaps\|pub enum NoZeroCopy\|pub struct FileRegion\|try_into_file_region_for' crates/stream/src --glob '*.rs'` | Definitions and negotiation are confined to `rustfs-gateway-stream` |
| The production server has no internal gateway dependency | `cargo tree -p rustfs-gateway-server -e normal --depth 1` | No `rustfs-gateway-*` child appears |
| The facade uses the server only for tests | `rg -n -B6 -A3 'rustfs-gateway-server' crates/gateway/Cargo.toml` | The dependency is under `[dev-dependencies]` |
| Hyper owns the only production connection driver | `rg -n 'serve_connection\(' crates/server/src --glob '*.rs'` | One call, in `crates/server/src/conn.rs` |
| No response-transport abstraction or production sendfile writer exists | `rg -n 'ResponseTransport\|sendfile' crates/gateway/src crates/server/src --glob '*.rs'` | No match |
| `conn` is currently conformance-side vocabulary | `rg -n 'Transport::Conn' crates/conformance/src --glob '*.rs'` | Matches only the test runner and its tests |

`[inferred]` Hyper's connection driver owns the socket across keep-alive responses; because the
current server exposes no accepted-connection driver seam, a facade response cannot borrow that
socket for one kernel transfer and then restore Hyper's parser state.

`[inferred]` A driver selected at accepted-connection time must handle non-file responses itself.
Falling back within that driver preserves connection ownership, while selecting by response payload
would require observing a result only after a different driver had already acquired the socket.

## Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| Recover the socket with `hyper::upgrade` for each file response | Upgrade permanently changes ownership and disrupts Hyper's keep-alive state; it cannot return the connection parser to its prior state. |
| Select Hyper or self-held transport after inspecting each response | The response exists only after a driver has parsed and dispatched the request, so this creates an impossible or duplicated socket state machine. |
| Silently hand TLS, HTTP/2, or h2c from a self-held listener to Hyper | Driver selection would stop being an assembly contract, and operators could not tell which path actually ran. Separate explicit listeners keep ownership and observation truthful. |
| Treat vectored Hyper writes as zero-copy | `writev` still transfers body bytes through user-space buffers and cannot truthfully satisfy a file-region kernel-transfer observation. |
| Add `as_any` and downcast payloads inside a transport | A failed downcast silently changes behavior and can bypass the typed verification obligation that `ZeroCopyQuery` checks first. |
| Put `TransportCaps` and `ResponseTransport` in core | Capability types already have one authority in stream, and a socket writer is runtime/transport policy rather than protocol-kernel policy. |
| Put the gateway-specific driver in server | It would add a reverse internal dependency or teach the generic listener about S3 payload and response semantics. |
| Duplicate request parsing, signing, or response invariants in the self-held path | Two protocol authorities would let the same request or response receive different security decisions depending on the configured driver. |
| Advertise `SPLICE`, `URING_ZC`, or RDMA for future use | A capability without a reachable implementation makes negotiation and metrics report intention as observation. |
| Keep only Hyper and reserve a future extension point | A single unexercised abstraction does not deliver the core plaintext large-object transfer capability or prove the boundary. |

## Consequences

- The facade gains a normal dependency on the generic server; the server remains free of internal
  gateway dependencies. `scripts/check_layer_dependencies.sh` enforces that direction.
- Deployments choose the default Hyper listener or the optional plaintext HTTP/1.1 self-held
  listener. TLS, HTTP/2, or h2c on the self-held listener is an assembly error; mixed-protocol
  deployments use separate explicit listeners.
- The self-held path must implement all HTTP/1.1 response shapes, keep-alive sequencing, partial
  writes, cancellation, and shutdown behavior even when no response is a file. This is the accepted
  maintenance cost of owning the socket.
- The implementation must add deterministic guards that bind every advertised `TransportCaps` bit
  to an implementation and test, and reject duplicated request-acceptance, signing, XML, or response
  policy inside the self-held modules.
- The shared transport-facing service seam must be the only path from either driver into
  `S3Service`. Real-socket controls prove both verdict directions: announcing close closes the
  connection, while announcing keep-alive leaves it reusable.
- `ResponseTransportMetrics` has a closed fallback-reason enum and separate counters for selected
  connections, fallback responses, copied payload bytes, kernel-transfer calls, and
  kernel-transferred bytes. Tests fail if one fallback increments zero or multiple times, or if an
  injected short syscall records the requested length instead of returned progress.
- Production tests must prove both directions: an eligible file region causes actual kernel-transfer
  progress with zero copied payload bytes, while TLS, HTTP/2, verification obligations, unsupported
  platforms, transformed bodies, and non-file payloads fall back with a named observation.
- Real-socket controls must cover short writes, client reset, graceful shutdown, keep-alive reuse,
  HEAD/bodyless statuses, conflicting framing, trailers, and an injected transport semantic
  difference. Every new assertion must be mutation-tested.
- The conformance matrix must compare both production drivers case by case. A test-side socket client
  or a capability bit alone is never accepted as evidence that the self-held production path ran.
- Dedicated 1 GiB throughput, RSS, and timing measurements remain in
  `rustfs/backlog#1766`; this decision requires truthful syscall and byte counters but does not add a
  noisy shared-runner timing gate.
