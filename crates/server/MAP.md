# rustfs-gateway-server crate map

Ring-1 generic HTTP runtime. Start at `src/lib.rs`; read only the row needed for the current failure.

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | Public modules and re-exports | A caller cannot name a server type |
| `src/config.rs` | Serializable tuning, defaults and validation | A knob is missing or accepts an unsafe value |
| `src/listener.rs` | socket2 bind, tuning and read-back | Bind family or socket option is wrong |
| `src/tls.rs` | Atomic TLS config and fail-closed reload | New handshakes see the wrong certificate |
| `src/io.rs` | Write-progress and connection-idle timers, and the lingering read on close | A slow reader is killed or never released, or a peer sees `ECONNRESET` where a close was due |
| `src/conn.rs` | Admission and connection lifecycle | Accept limits or shutdown sequencing fails |
| `src/driver.rs` | Accepted-connection ownership, driver selection and the default Hyper driver | Adding a connection driver or changing who owns a socket |
| `src/connection_service.rs` | Transport-independent request capacity, context, panic and shutdown lifecycle | A driver can bypass generic request contracts |
| `src/request_capacity.rs` | Global request permits, accept-loop capacity notification and request cancellation | H1/H2 exceed the shared request ceiling, listener acceptance fails to pause or peer loss does not reach service cleanup |
| `src/shutdown.rs` | Trigger, report and metrics | Drain or abort counts are wrong |
| `src/dispatch.rs` | Generic path-prefix selection | A route reaches the fallback unexpectedly |
| `src/layers.rs` | General tower layer attachment points | Wiring panic, request ID, trace or compression |
| `tests/acceptance.rs` | Deterministic config, dispatch and TLS reload cases | A source-only contract regresses |
| `tests/server_runtime.rs` | Live h1 admission and shutdown cases | Socket lifecycle behaviour regresses |
| `tests/server_runtime/connection_driver.rs` | Live custom-driver ownership, managed-service and shutdown controls | `serve_with` releases admission or bypasses request lifecycle |
| `tests/tls_h2.rs` | Live TLS and h2 cases | Reload, TLS admission or h2 flow control regresses |
| `tests/lingering_close.rs` | How a refused connection ends, on a real socket: closed, open or reset | A client reads `ECONNRESET` instead of the refusal, or a close costs a connection slot |
