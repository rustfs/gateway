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

//! The ADR-0004 P10 placeholder contract, and the guard that keeps a placeholder off the wire.
//!
//! Responsible for: the one question every scalar in the vocabulary has to be able to answer —
//! "are you the wire-invalid value your `Default` produces?" — and the error a decoder returns
//! when a required member is still holding one.
//! NOT responsible for: validating a value against its wire rules (that is each scalar's own
//! constructor), or deciding which members are required (that is the IR).
//! Upstream: `super::scalar`. Downstream: the generated dto's `check_required`, and the codecs
//! that call it at the end of decoding.
//!
//! # Why the placeholders exist at all
//!
//! ADR-0004 P1 requires every generated Input and Output to `#[derive(Default)]`, because
//! `..Default::default()` is what keeps thousands of construction sites compiling when AWS adds a
//! member. P1 also requires a **required** member to use a bare type rather than `Option<T>`, so
//! that the type tells the truth about the wire contract and a handler does not unwrap a value
//! that can never be absent. Those two rules together force every scalar that can sit in a
//! required position to have a `Default`.
//!
//! P10 fixes what that `Default` may be: a value that is **invalid on the wire**, never a
//! plausible one. `BucketName::default()` is the empty name, which `validate_bucket_name` rejects;
//! `Timestamp::default()` is an instant no wire format can render. A placeholder is therefore
//! detectable, and this module is where the detection lives.
//!
//! # Why the guard returns an error rather than asserting
//!
//! [`reject_placeholder`] returns `Err` in every build instead of `debug_assert!`-ing. A
//! `debug_assert!` is compiled out of the release binary — the only build that ever faces a
//! hostile request — so it would guard exactly the configuration that does not need guarding. And
//! the failure mode is security-relevant rather than cosmetic: an empty `BucketName` or
//! `ObjectKey` reaching a handler is a value that authorization and storage would both accept and
//! neither would recognise. Failing closed costs one comparison per required member on the decode
//! path and turns a latent defect into a 400.

use std::fmt;

/// Whether a value is the wire-invalid placeholder its `Default` produces.
///
/// Implemented for every type that can appear as a **required**, non-container member of a
/// generated dto. Types whose `Default` is a legitimate wire value — `String`, `i64`, `bool`,
/// [`super::OpaqueString`] — implement this as a constant `false`, because for them "empty" and
/// "zero" are things a client may genuinely send and rejecting them would be a bug of its own.
pub trait WirePlaceholder {
    /// Whether `self` is the placeholder value [`Default`] produces.
    ///
    /// A `true` answer means the value cannot have come off the wire: no encoding of this type
    /// produces it, so its presence means a required member was never filled in.
    fn is_wire_placeholder(&self) -> bool;
}

/// A required member reached the end of decoding still holding its placeholder default.
///
/// Never a client error in the ordinary sense: a request that omits a required member is rejected
/// earlier, by the binding that failed to find it. This is the decoder's own invariant, reported
/// rather than asserted so that a release build fails closed — see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderDefault {
    /// The generated type that carries the member, e.g. `PutObjectInput`.
    type_name: &'static str,
    /// The member's model name, e.g. `Bucket`.
    member: &'static str,
}

impl PlaceholderDefault {
    /// The generated type that carries the member.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        self.type_name
    }

    /// The member's model name.
    #[must_use]
    pub const fn member(&self) -> &'static str {
        self.member
    }
}

impl fmt::Display for PlaceholderDefault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{} is required but still holds its placeholder default, \
             which is not a value the wire can carry (ADR-0004 P10)",
            self.type_name, self.member
        )
    }
}

impl std::error::Error for PlaceholderDefault {}

/// Fails when a required member is still holding its placeholder default.
///
/// The generated `check_required` calls this once per required, non-container member. It is the
/// decode-path exit check ADR-0004 P10 asks for.
///
/// # Errors
///
/// Returns [`PlaceholderDefault`] naming the type and the model member.
pub fn reject_placeholder<T: WirePlaceholder + ?Sized>(
    type_name: &'static str,
    member: &'static str,
    value: &T,
) -> Result<(), PlaceholderDefault> {
    if value.is_wire_placeholder() {
        return Err(PlaceholderDefault { type_name, member });
    }
    Ok(())
}

/// Declares the types whose `Default` is a legitimate wire value and therefore never a placeholder.
macro_rules! never_a_placeholder {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl WirePlaceholder for $ty {
                fn is_wire_placeholder(&self) -> bool {
                    false
                }
            }
        )+
    };
}

// `String::default()` is the empty string and `i64::default()` is zero. Both are values a client
// may legitimately send — `Prefix` is required in a `ListObjectsV2` response and is routinely
// empty, and `Content-Length: 0` is a valid `PutObject`. There is no bit pattern of these types
// that means "not filled in", so the guard has nothing to check and says so explicitly rather than
// leaving the impl missing, which would silently drop a member out of `check_required`.
never_a_placeholder!(String, bool, i32, i64, bytes::Bytes);

/// The spelling every generated string enumeration's placeholder `Default` holds.
///
/// ADR-0004 P10 asks for a value that is **invalid on the wire**. The empty string was used until
/// rustfs/gateway#1078, and it is not: a client sends it as `<Status></Status>`, legacy RustFS hands
/// it to its handlers (an empty `Payer` is stored and read back), and the decoder produced it — so the
/// exit check mistook the client's empty value for a member nobody filled and answered this side's
/// `500`. A NUL is what no decoder can produce for a required member: the XML readers refuse it as a
/// character XML 1.0 cannot represent, a header value cannot carry one, and no required enumeration
/// is bound to a query parameter or a form field. `as_str` still spells the placeholder as the empty
/// string, so what a defaulted member renders as is unchanged.
pub(crate) const STRING_ENUMERATION_PLACEHOLDER: &str = "\u{0}";
