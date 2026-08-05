//! A protocol-exact, security-first S3 server framework for Rust.
//!
//! Responsible for: the public facade — `ServiceBuilder`, the hyper/tower adapters, re-exports.
//! NOT responsible for: storage semantics or IAM policy evaluation; those belong to the user.
//! Upstream: `s3gate-core`. Downstream: application code.
#![forbid(unsafe_code)]
