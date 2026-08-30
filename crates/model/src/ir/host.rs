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

//! [`HostClass`] and [`ArnForm`]: the two [`super::Predicate`] operands with a closed IR-side
//! vocabulary of their own.
//!
//! Responsible for: the exact set of spellings `spec/ir.schema.json`'s `host_class` and `arn_form`
//! definitions pin, and parsing/rendering them.
//! NOT responsible for: which operation's route uses either one (that is [`mod@crate::lower`]) or
//! matching a live request against them (that is `rustfs-gateway-core::route`, which carries its
//! own copy of this same closed set — see the module docs on `crates/core/src/route/generated.rs`
//! for why the two copies do not merge).
//! Upstream: [`mod@crate::lower`]. Downstream: `rustfs-gateway-codegen`.

/// Which endpoint family a request arrived on.
///
/// Mirrors `rustfs-gateway-core::route::HostClass` and `spec/ir.schema.json`'s `host_class`
/// definition one for one — this is the IR's copy of the same closed set, not a competing
/// definition of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostClass {
    /// The ordinary REST endpoint, path-style or virtual-hosted.
    Standard,
    /// `<route>.s3-object-lambda.<region>.amazonaws.com`.
    ObjectLambda,
    /// The zonal endpoint of a directory bucket.
    S3Express,
    /// The static-website endpoint, a different protocol on the same shapes.
    Website,
    /// An Outposts endpoint.
    Outposts,
    /// The transfer-acceleration endpoint.
    Accelerate,
    /// The dual-stack endpoint.
    Dualstack,
}

impl HostClass {
    /// Every variant, in IR-spelling order.
    pub const ALL: [Self; 7] = [
        Self::Standard,
        Self::ObjectLambda,
        Self::S3Express,
        Self::Website,
        Self::Outposts,
        Self::Accelerate,
        Self::Dualstack,
    ];

    /// The spelling used in the IR.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::ObjectLambda => "ObjectLambda",
            Self::S3Express => "S3Express",
            Self::Website => "Website",
            Self::Outposts => "Outposts",
            Self::Accelerate => "Accelerate",
            Self::Dualstack => "Dualstack",
        }
    }

    /// Parses the IR spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.as_str() == text)
    }
}

/// The ARN shape occupying the bucket position of the path.
///
/// Mirrors `rustfs-gateway-core::route::ArnForm` and `spec/ir.schema.json`'s `arn_form`
/// definition one for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArnForm {
    /// `arn:aws:s3:<region>:<account>:accesspoint/<name>`.
    AccessPoint,
    /// `arn:aws:s3-outposts:...`.
    Outposts,
    /// A multi-region access point alias.
    Mrap,
}

impl ArnForm {
    /// Every variant, in IR-spelling order.
    pub const ALL: [Self; 3] = [Self::AccessPoint, Self::Outposts, Self::Mrap];

    /// The spelling used in the IR.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessPoint => "AccessPoint",
            Self::Outposts => "Outposts",
            Self::Mrap => "MRAP",
        }
    }

    /// Parses the IR spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|form| form.as_str() == text)
    }
}

#[cfg(test)]
mod tests {
    use super::{ArnForm, HostClass};

    #[test]
    fn every_host_class_round_trips_through_its_ir_spelling() {
        for class in HostClass::ALL {
            assert_eq!(HostClass::parse(class.as_str()), Some(class));
        }
    }

    #[test]
    fn every_arn_form_round_trips_through_its_ir_spelling() {
        for form in ArnForm::ALL {
            assert_eq!(ArnForm::parse(form.as_str()), Some(form));
        }
    }

    #[test]
    fn n_an_unknown_spelling_parses_to_neither() {
        assert_eq!(HostClass::parse("Nope"), None);
        assert_eq!(ArnForm::parse("Nope"), None);
    }
}
