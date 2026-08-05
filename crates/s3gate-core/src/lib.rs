//! Operations, routing, the typed pipeline, and the extension points.
//!
//! Responsible for: `Operation`/`OperationSpec`, the ordered route table, the type-state
//! pipeline, and every extension trait (`Authorizer`, `HostResolver`, `Governor`, ...).
//! NOT responsible for: HTTP transport assembly (that is the `s3gate` facade).
//! Upstream: `s3gate-sig`. Downstream: `s3gate`.
#![forbid(unsafe_code)]
