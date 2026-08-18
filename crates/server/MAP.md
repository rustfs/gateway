# rustfs-gateway-server crate map

Ring-1 generic HTTP runtime. Start at `src/lib.rs`; read only the row needed for the current failure.

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | Public modules and re-exports | A caller cannot name a server type |
| `src/config.rs` | Serializable tuning, defaults and validation | A knob is missing or accepts an unsafe value |
| `src/listener.rs` | socket2 bind, tuning and read-back | Bind family or socket option is wrong |
| `src/tls.rs` | Atomic TLS config and fail-closed reload | New handshakes see the wrong certificate |
| `src/io.rs` | Write-progress and connection-idle timers | A slow reader is killed or never released |
| `src/conn.rs` | Admission, Hyper driving and connection lifecycle | Accept, h1/h2 or shutdown sequencing fails |
| `src/request_capacity.rs` | Global request permits and accept-loop capacity notification | H1/H2 exceed the shared request ceiling or listener acceptance fails to pause |
| `src/shutdown.rs` | Trigger, report and metrics | Drain or abort counts are wrong |
| `src/dispatch.rs` | Generic path-prefix selection | A route reaches the fallback unexpectedly |
| `src/layers.rs` | General tower layer attachment points | Wiring panic, request ID, trace or compression |
| `tests/acceptance.rs` | Deterministic config, dispatch and TLS reload cases | A source-only contract regresses |
| `tests/server_runtime.rs` | Live h1 admission and shutdown cases | Socket lifecycle behaviour regresses |
| `tests/tls_h2.rs` | Live TLS and h2 cases | Reload, TLS admission or h2 flow control regresses |
