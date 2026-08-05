//! Payload and body primitives.
//!
//! Responsible for: `Body`, `ByteStream`, `Payload`, trailer delivery typing.
//! NOT responsible for: anything S3-specific. This crate exists so that
//! `GetObjectOutput.body: StreamingBlob` does not create a `s3gate-types` <-> `s3gate-http` cycle.
//! Upstream: `bytes`/`http`. Downstream: `s3gate-types`, `s3gate-http`.
#![forbid(unsafe_code)]
