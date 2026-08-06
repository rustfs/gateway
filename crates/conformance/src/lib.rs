// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Data-driven S3 conformance suite.
//!
//! Responsible for: the case schema, the runner, and baseline-aware reporting. Runnable against
//! any S3 implementation, not just this one — hence its independent version number.
//! NOT responsible for: being a unit-test harness for the framework internals.
//!
//! # How a case becomes a verdict
//!
//! ```text
//!   corpus   find conformance/, read cases/**/*.toml, validate against the frozen schema
//!   lint     the conventions the schema cannot express: naming, goldens, capture wiring
//!   runner   select, interpolate ${capture.*}, drive the exchanges, collect diagnostics
//!   expect   judge one [expect] block against one Observation
//!   report   group by capability domain, compare against a baseline, decide the exit code
//! ```
//!
//! Four properties hold this together, and everything else exists to serve them.
//!
//! 1. **The frozen schema is the contract, and it is read rather than mirrored.**
//!    `case.schema.json` is evaluated at run time against the parsed TOML. A Rust mirror of a
//!    frozen document is a second copy, and a second copy drifts. An unknown schema keyword is a
//!    load error, for the same reason `additionalProperties: false` is in the schema at all.
//! 2. **Every case reaches a stated conclusion.** Passed, failed, or skipped *with a reason*.
//!    "Did not run" and "ran and was red" are different facts, and a report that cannot tell them
//!    apart is how a suite stops asserting anything without anyone noticing.
//! 3. **An environment failure is not a case failure.** A corpus that will not load, or a target
//!    that cannot be reached, exits 3 and never 1 — otherwise the first bad run writes itself
//!    into the baseline and the tolerance meant for existing failures starts hiding new ones.
//! 4. **No dependency but the facade.** This crate is a product other S3 implementations run
//!    against themselves, so it carries no third-party dependency at all: the TOML reader, the
//!    JSON reader, the schema evaluator and the pattern matcher are here, small and testable,
//!    rather than inherited by every consumer.
//!
//! # Running it
//!
//! ```bash
//! cargo run -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- validate
//! cargo run -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- run --filter 'etag/'
//! ```
//!
//! Point it at another corpus with `--root`, or with `RUSTFS_GATEWAY_CONFORMANCE_ROOT`.
#![forbid(unsafe_code)]

pub mod cli;
pub mod corpus;
pub mod diagnostic;
pub mod expect;
pub mod interpolate;
pub mod json;
pub mod lint;
pub mod observation;
pub mod pattern;
pub mod report;
pub mod runner;
pub mod schema;
pub mod sha256;
pub mod sut;
pub mod toml;
pub mod value;
pub mod xml;
