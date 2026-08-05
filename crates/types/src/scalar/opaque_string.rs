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

//! A value that is stored and returned byte for byte, and never interpreted.
//!
//! Responsible for: carrying strings whose only contract is "give back exactly what was put in".
//! `Expires` is the motivating case, and the IR marks it `OpaqueString` for that reason.
//! NOT responsible for: parsing, validating, normalising, or reformatting anything. The absence of
//! those methods is the feature — see below.
//! Upstream: none. Downstream: any dto field the IR types as `OpaqueString`.
//!
//! # Why there is no date parsing here, and why there must never be
//!
//! `Expires` is declared as a timestamp in the S3 model, but stored objects carry values that are
//! not dates: the header is user-supplied metadata, and clients have been writing arbitrary
//! strings into it for as long as the API has existed. AWS eventually added a second, string-typed
//! member to its own SDKs to stop losing those values. An implementation that parses the header
//! and re-renders it either fails on values that were accepted at write time, or silently rewrites
//! them into a different spelling — and a caller comparing what it stored with what it read back
//! sees a mismatch it cannot explain.
//!
//! So this type has `as_str`, and that is deliberately all. Adding a `parse_as_date`, a
//! `to_timestamp`, or a `Deref<Target = Timestamp>` convenience would reintroduce exactly the
//! defect the IR is spelling out. If a caller genuinely needs a date, it parses the `&str` itself,
//! at its own risk, and the risk is visible at the call site.

use std::borrow::Cow;
use std::fmt;

/// A string echoed back unchanged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct OpaqueString(Cow<'static, str>);

impl OpaqueString {
    /// Wraps a value. Nothing is validated, because there is nothing to validate against.
    #[must_use]
    pub fn new(value: impl Into<Cow<'static, str>>) -> Self {
        Self(value.into())
    }

    /// The stored bytes, unchanged.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unwraps into an owned `String`.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0.into_owned()
    }
}

impl From<String> for OpaqueString {
    fn from(value: String) -> Self {
        Self(Cow::Owned(value))
    }
}

impl From<&'static str> for OpaqueString {
    fn from(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }
}

impl AsRef<str> for OpaqueString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Writes the value verbatim. Unlike [`super::ETag`] and [`super::Timestamp`], an opaque string
/// has exactly one rendering — that is its whole definition — so `Display` cannot be misused here.
impl fmt::Display for OpaqueString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
