//! S3 scalar types, operation inputs/outputs, and their generated codecs.
//!
//! Responsible for: `ETag`, `Checksum`, `Timestamp`, names, `Range`, error codes, and the
//! generated per-operation DTOs plus their XML/header codec impls.
//! NOT responsible for: wire framing, signing, routing.
//! Upstream: `s3gate-xml`, `s3gate-stream`. Downstream: `s3gate-http` and everything above.
#![forbid(unsafe_code)]
