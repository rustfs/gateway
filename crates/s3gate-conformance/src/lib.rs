//! Data-driven S3 conformance suite.
//!
//! Responsible for: the case schema, the runner, and baseline-aware reporting. Runnable against
//! any S3 implementation, not just this one — hence its independent version number.
//! NOT responsible for: being a unit-test harness for the framework internals.
#![forbid(unsafe_code)]
