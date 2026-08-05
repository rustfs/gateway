//! Smithy model parsing and the frozen s3gate IR.
//!
//! Responsible for: loading the pinned AWS Smithy model, applying overlays, producing the IR.
//! NOT responsible for: emitting Rust code (that is `s3gate-codegen`), any runtime behaviour.
//! Upstream: the pinned `model/` directory. Downstream: `s3gate-codegen`.
//!
//! Build-time only — never appears in a runtime dependency tree.
#![forbid(unsafe_code)]
