# rustfs-gateway-server crate map

Ring-1 generic HTTP runtime. Start at `src/lib.rs`; read only the row needed for the current failure.

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | Public modules and re-exports | A caller cannot name a server type |
| `src/config.rs` | Serializable tuning, defaults and validation | A knob is missing or accepts an unsafe value |
| `src/listener.rs` | socket2 bind, tuning and read-back | Bind family or socket option is wrong |
| `src/tls.rs` | Atomic TLS config, advertised ALPN protocols and fail-closed reload | New handshakes see the wrong certificate or protocol |
| `src/io.rs` | Write-progress and connection-idle timers, and the lingering read on close | A slow reader is killed or never released, or a peer sees `ECONNRESET` where a close was due |
| `src/io_deadline_tests.rs` | Every configured `ProgressIo` timer rearmed at `Duration::MAX` | A configured timeout panics a connection instead of meaning never |
| `src/io_sendfile_tests.rs` | Real-socket controls for sendfile writable-readiness handoff | Sendfile retries spin, stall, or lose a writable transition |
| `src/conn.rs` | Admission and connection lifecycle | Accept limits or shutdown sequencing fails |
| `src/accept_error.rs` | Classifies a failed accept as connection-local, a resource shortage to wait out, or a broken listener | The listener exits on a transient accept error, or keeps running on a broken socket |
| `src/driver.rs` | Accepted-connection ownership, driver selection and the default Hyper driver | Adding a connection driver or changing who owns a socket |
| `src/connection_service.rs` | Transport-independent request capacity, context, panic and shutdown lifecycle | A driver can bypass generic request contracts |
| `src/request_capacity.rs` | Global request permits, accept-loop capacity notification and request cancellation | H1/H2 exceed the shared request ceiling, listener acceptance fails to pause or peer loss does not reach service cleanup |
| `src/sendfile.rs` | Safe Linux/Apple file-to-socket syscall signature normalization | A self-held driver reports wrong sendfile progress or platform errors |
| `src/sendfile_task.rs` | Bounded blocking handoff for file-transfer syscalls | A cold file stalls Tokio workers or blocking file work grows without a ceiling |
| `src/shutdown.rs` | Trigger, report and metrics | Drain or abort counts are wrong |
| `src/write_receipt.rs` | Counts a response drained only after the transport confirms its bytes were written (flush, half-close or clean connection end) | Shutdown reports drained for a response the peer never received |
| `src/dispatch.rs` | Generic path-prefix selection | A route reaches the fallback unexpectedly |
| `src/layers.rs` | General tower layer attachment points | Wiring panic, request ID, trace or compression |
| `tests/acceptance.rs` | Deterministic config, dispatch and TLS reload cases | A source-only contract regresses |
| `tests/server_load/isolation.rs` | Real load-child and drain-fixture lease exclusion controls | Saturating load overlaps the healthy shutdown fixture |
| `tests/server_runtime.rs` | Live h1 admission and shutdown cases | Socket lifecycle behaviour regresses |
| `tests/server_runtime/drain_fixture.rs` | Healthy 8 MiB shutdown drain, in flight when shutdown begins, with lease checkpoints | Changing the full-body drain or its resource-isolation controls |
| `tests/server_runtime/shutdown_drain.rs` | A final frame blocked on the socket is aborted at the grace; the same frame written after shutdown began is drained | Drained/aborted accounting diverges from what reached the socket |
| `tests/server_runtime/connection_driver.rs` | Live custom-driver ownership, managed-service and shutdown controls | `serve_with` releases admission or bypasses request lifecycle |
| `tests/server_runtime/frozen_clock.rs` | Frozen fixture-clock polling with an independent watchdog | Slow-header setup races deadlines under host load |
| `tests/server_runtime/global_admission.rs` | a-srv-0014 global-limit refusal and permit reuse, with a scheduling-stall control on a frozen fixture clock | The global connection limit accepts early, or a host stall expires the permit holder |
| `tests/server_runtime/unbounded_timeouts.rs` | HTTP/1.1 and HTTP/2 served with every timeout at `Duration::MAX` | A configured timeout panics the listener or Hyper |
| `tests/server_runtime/accept_recovery.rs` | Real exhausted descriptor table: the listener survives, backs off and serves again | A failed accept ends the listener or spins |
| `tests/tls_h2.rs` | Live TLS and h2 cases | Reload, TLS admission or h2 flow control regresses |
| `tests/tls_h2/alpn.rs` | ALPN negotiation and the protocol it selects | A TLS client cannot negotiate h2, or a negotiated protocol is not enforced |
| `tests/lingering_close.rs` | How a refused connection ends, on a real socket: closed, open or reset | A client reads `ECONNRESET` instead of the refusal, or a close costs a connection slot |
