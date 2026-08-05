//! Signature verification state machine (SigV2/SigV4, presigned, POST policy).
//!
//! Responsible for: `PayloadMode`/`AuthScheme`, canonical request construction, the
//! constant-time verification proof that makes "never compared" unrepresentable.
//! NOT responsible for: authorization (that is `s3gate-core`), credential storage.
//! Upstream: `s3gate-http`. Downstream: `s3gate-core`.
#![forbid(unsafe_code)]
