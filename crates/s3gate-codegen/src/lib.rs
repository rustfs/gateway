//! Code generator turning the s3gate IR into Rust sources.
//!
//! Responsible for: emitting `generated/**`, `spec/operations/*.toml`, `OPERATIONS.md`.
//! NOT responsible for: parsing Smithy (that is `s3gate-model`), runtime behaviour.
//! Upstream: `s3gate-model`. Downstream: the checked-in generated sources.
#![forbid(unsafe_code)]
