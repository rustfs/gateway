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

//! The one error type this crate returns.
//!
//! Responsible for: naming every way loading a model, an overlay, or lowering to IR can fail.
//! NOT responsible for: recovery. Codegen is a batch tool; the only response to any of these is to
//! stop with a message a human can act on.
//! Upstream: every module in this crate. Downstream: `s3gate-codegen` and `xtask`.

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while turning the pinned model plus overlays into IR.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file could not be read or written.
    #[error("io error on {path}: {source}")]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A JSON document did not parse.
    #[error("json: {0}")]
    Json(String),
    /// A TOML overlay did not parse.
    #[error("{path}:{line}: {message}")]
    Toml {
        /// Overlay path.
        path: String,
        /// One-based line number.
        line: usize,
        /// What went wrong.
        message: String,
    },
    /// The Smithy AST was structurally not what the loader requires.
    #[error("model: {0}")]
    Model(String),
    /// The overlay is internally inconsistent, or disagrees with the model.
    #[error("overlay: {0}")]
    Overlay(String),
    /// Lowering produced something the frozen IR shape does not permit.
    #[error("ir({operation}): {message}")]
    Ir {
        /// The operation being lowered.
        operation: String,
        /// What the IR rule was.
        message: String,
    },
}

impl Error {
    /// Wraps an I/O failure with the path that caused it.
    pub fn io(path: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    /// Builds an IR violation for one operation.
    pub fn ir(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Error::Ir {
            operation: operation.into(),
            message: message.into(),
        }
    }
}
