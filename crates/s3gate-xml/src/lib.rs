//! XML serialization/deserialization machinery.
//!
//! Responsible for: the `XmlSerialize`/`XmlDeserialize` traits and the reader/writer machinery.
//! NOT responsible for: any S3 semantics — it holds no S3 types. Generated impls live in
//! `s3gate-types` (traits here + types there satisfies the orphan rule, same shape as serde).
//! Upstream: `quick-xml`. Downstream: `s3gate-types`.
#![forbid(unsafe_code)]
